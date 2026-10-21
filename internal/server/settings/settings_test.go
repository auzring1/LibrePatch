package settings

import (
	"os"
	"strings"
	"testing"
)

func TestRegistryIsComplete(t *testing.T) {
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	for _, s := range Sections {
		if !strings.HasPrefix(s.Perm, "settings:") {
			t.Errorf("%s: odd permission %q", s.ID, s.Perm)
		}
	}
}

func section(t *testing.T, id string) Section {
	t.Helper()
	s, ok := ByID(id)
	if !ok {
		t.Fatalf("no section %s", id)
	}
	return s
}

func TestNormalizeRefusesBadValues(t *testing.T) {
	sec := section(t, "security")
	cases := map[string]map[string]any{
		"unknown key":        {"nope": 1},
		"int range low":      {"session_idle_minutes": 1},
		"int range high":     {"session_absolute_hours": 500},
		"password too short": {"password_min_length": 8},
		"fraction":           {"lockout_threshold": 5.5},
		"wrong type":         {"lockout_minutes": "ten"},
		"bad cidr":           {"ip_allowlist": []any{"not-an-ip"}},
		"control chars":      {"login_banner": "hello\x00"},
		"banner too long":    {"login_banner": strings.Repeat("x", 2001)},
		"bool as string":     {"login_banner_enabled": "yes"},
	}
	for name, in := range cases {
		if _, errs := sec.Normalize(in); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	out, errs := sec.Normalize(map[string]any{"session_idle_minutes": float64(20), "ip_allowlist": []any{"10.1.2.3", "192.168.1.77/24"}})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if V(out).Int("session_idle_minutes") != 20 || V(out).Int("lockout_threshold") != 10 {
		t.Fatalf("defaults and values: %v", out)
	}
	if got := V(out).Strings("ip_allowlist"); len(got) != 2 || got[1] != "192.168.1.0/24" {
		t.Fatalf("networks are canonicalised: %v", got)
	}
}

func TestSecurityCrossChecks(t *testing.T) {
	sec := section(t, "security")
	vals, errs := sec.Normalize(map[string]any{"ip_allowlist": []any{"10.0.0.0/8"}})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if e := sec.Cross(vals, nil, Actor{IP: "203.0.113.9"}); e["ip_allowlist"] == "" {
		t.Fatal("an allow-list that excludes the caller must be refused")
	}
	if e := sec.Cross(vals, nil, Actor{IP: "10.4.5.6"}); len(e) != 0 {
		t.Fatalf("caller inside: %v", e)
	}
	vals, _ = sec.Normalize(map[string]any{"login_banner_enabled": true})
	if e := sec.Cross(vals, nil, Actor{}); e["login_banner"] == "" {
		t.Fatal("a shown notice needs text")
	}
}

func TestNotificationRules(t *testing.T) {
	sec := section(t, "notifications")
	d := sec.Defaults()
	vals, errs := sec.Normalize(d)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if e := sec.Cross(vals, nil, Actor{}); len(e) != 0 {
		t.Fatalf("defaults must be valid: %v", e)
	}
	// Turn the first rule on without recipients.
	rules := vals["rules"].([]any)
	rules[0].(map[string]any)["enabled"] = true
	vals, errs = sec.Normalize(vals)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if e := sec.Cross(vals, nil, Actor{}); e["rules[0].recipients"] == "" {
		t.Fatalf("an e-mail rule needs recipients: %v", e)
	}
	// The set of rules is closed.
	short := map[string]any{"rules": rules[:3]}
	if _, errs := sec.Normalize(short); errs["rules"] == "" {
		t.Fatal("rules cannot be removed")
	}
	// E-mail needs a server and a sender, and a password only with a user name.
	vals, _ = sec.Normalize(map[string]any{"email_enabled": true})
	e := sec.Cross(vals, nil, Actor{})
	if e["smtp_host"] == "" || e["from_address"] == "" {
		t.Fatalf("e-mail settings: %v", e)
	}
	vals, _ = sec.Normalize(map[string]any{"email_enabled": true, "smtp_host": "smtp.example.org", "from_address": "a@example.org", "smtp_username": "u"})
	if e := sec.Cross(vals, map[string]bool{}, Actor{}); e["smtp_password"] == "" {
		t.Fatalf("a user name without a password: %v", e)
	}
	if e := sec.Cross(vals, map[string]bool{"smtp_password": true}, Actor{}); len(e) != 0 {
		t.Fatalf("complete: %v", e)
	}
}

func TestSecretsAreNeverPartOfTheDocument(t *testing.T) {
	sec := section(t, "integrations")
	in := map[string]any{"webhooks": []any{
		map[string]any{"name": "SIEM", "url": "https://hooks.example.org/x", "secret": "s3cret", "events": []any{"failed_install"}},
		map[string]any{"id": "keep-me", "name": "Other", "url": "http://10.0.0.5/x", "clear_secret": true, "events": []any{"update_held"}},
	}}
	clean, secrets, clears, err := prepare(sec, in)
	if err != nil {
		t.Fatal(err)
	}
	items := clean["webhooks"].([]any)
	first := items[0].(map[string]any)
	id, _ := first["id"].(string)
	if id == "" {
		t.Fatal("an item without an id gets one")
	}
	if _, has := first["secret"]; has {
		t.Fatal("the secret must be taken out of the item")
	}
	if p := secrets["webhooks."+id+".secret"]; p == nil || *p != "s3cret" {
		t.Fatalf("secret collected: %v", secrets)
	}
	if p := secrets["webhooks.keep-me.secret"]; p == nil || *p != "" || !clears["webhooks.keep-me.secret"] {
		t.Fatalf("clear collected: %v", secrets)
	}
	vals, errs := sec.Normalize(clean)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if strings.Contains(toJSON(vals), "s3cret") {
		t.Fatal("secret leaked into values")
	}
	if live := livePaths(sec, vals); !live["webhooks."+id+".secret"] || live["webhooks.gone.secret"] {
		t.Fatalf("live paths: %v", live)
	}
}

func TestListValidation(t *testing.T) {
	sec := section(t, "integrations")
	bad := []map[string]any{
		{"name": "x", "url": "ftp://x", "events": []any{"failed_install"}},
		{"name": "x", "url": "https://user:pw@x.example", "events": []any{"failed_install"}},
		{"name": "x", "url": "https://x.example", "events": []any{}},
		{"name": "x", "url": "https://x.example", "events": []any{"bogus"}},
		{"name": "", "url": "https://x.example", "events": []any{"failed_install"}},
	}
	for i, w := range bad {
		if _, errs := sec.Normalize(map[string]any{"webhooks": []any{w}}); len(errs) == 0 {
			t.Errorf("case %d accepted", i)
		}
	}
	dev := section(t, "devices")
	if _, errs := dev.Normalize(map[string]any{"custom_fields": []any{map[string]any{"key": "Asset Tag", "label": "x", "type": "text"}}}); len(errs) == 0 {
		t.Error("a key with spaces and capitals must be refused")
	}
	two := []any{map[string]any{"key": "owner", "label": "Owner", "type": "text"}, map[string]any{"key": "owner", "label": "Other", "type": "text"}}
	if _, errs := dev.Normalize(map[string]any{"custom_fields": two}); len(errs) == 0 {
		t.Error("repeated keys must be refused")
	}
	vals, _ := dev.Normalize(map[string]any{"custom_fields": []any{map[string]any{"key": "tier", "label": "Tier", "type": "select"}}})
	if e := dev.Cross(vals, nil, Actor{}); e["custom_fields[0].options"] == "" {
		t.Errorf("a choice field needs choices: %v", e)
	}
	if _, errs := dev.Normalize(map[string]any{"naming_pattern": "([unclosed"}); errs["naming_pattern"] == "" {
		t.Error("a bad regular expression must be refused")
	}
}

func TestTimeZonesAndTimes(t *testing.T) {
	sec := section(t, "appearance")
	if _, errs := sec.Normalize(map[string]any{"time_zone": "Mars/Base"}); errs["time_zone"] == "" {
		t.Error("unknown zone")
	}
	if _, errs := sec.Normalize(map[string]any{"time_zone": "Europe/Berlin"}); len(errs) != 0 {
		t.Error(errs)
	}
	up := section(t, "updates")
	if _, errs := up.Normalize(map[string]any{"active_start": "25:00"}); errs["active_start"] == "" {
		t.Error("bad time")
	}
}

func TestDiffShowsOnlyChanges(t *testing.T) {
	sec := section(t, "security")
	a := sec.Defaults()
	b := deepCopy(a)
	b["lockout_threshold"] = 8
	b["ip_allowlist"] = []any{"10.0.0.0/8"}
	d := Diff(sec, a, b)
	if len(d) != 2 {
		t.Fatalf("diff: %v", d)
	}
	if d["lockout_threshold"].(map[string]any)["after"] != 8 {
		t.Fatalf("after: %v", d)
	}
}

func TestAllowlist(t *testing.T) {
	list := []string{"10.0.0.0/8", "192.0.2.5"}
	for ip, want := range map[string]bool{"10.9.9.9": true, "192.0.2.5": true, "192.0.2.6": false, "2001:db8::1": false, "garbage": false} {
		if InAllowlist(list, ip) != want {
			t.Errorf("%s: want %v", ip, want)
		}
	}
	if !InAllowlist(nil, "1.2.3.4") {
		t.Error("an empty list allows everyone")
	}
}

func TestEventReferenceCoversEveryEvent(t *testing.T) {
	have := map[string]bool{}
	for _, d := range EventReference() {
		have[d.Event] = true
		if d.When == "" || d.Payload["event"] != d.Event {
			t.Errorf("%s: incomplete", d.Event)
		}
	}
	for _, e := range Events {
		if !have[e.Value] {
			t.Errorf("event %s has no reference entry", e.Value)
		}
	}
}

func toJSON(v any) string { b, _ := jsonMarshal(v); return string(b) }

func TestSettingsDocIsUpToDate(t *testing.T) {
	b, err := os.ReadFile("../../../docs/SETTINGS.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != Markdown() {
		t.Fatal("docs/SETTINGS.md is out of date: run  go run ./internal/server/settings/gen > docs/SETTINGS.md")
	}
}

// An installation that saved its notification settings while the "license usage" event existed must still load them:
// the retired rule and the retired webhook choice are dropped instead of making every later save fail.
func TestStoredSettingsWithARetiredEventStillLoad(t *testing.T) {
	sec := section(t, "notifications")
	rule := func(ev string) map[string]any {
		return map[string]any{"event": ev, "enabled": false, "email": true, "webhook": true, "recipients": []any{}, "threshold": 0, "quiet_hours": true}
	}
	stored := map[string]any{"rules": []any{rule("failed_install"), rule("update_held"), rule("device_offline"), rule("license_limit"), rule("agent_out_of_date")}}
	norm, errs := sec.Normalize(dropUnknown(sec.Fields, stored))
	if len(errs) != 0 {
		t.Fatalf("a stored document with the retired rule must still validate: %v", errs)
	}
	if n := len(norm["rules"].([]any)); n != len(Events) {
		t.Fatalf("the retired rule must be dropped, got %d rules for %d events", n, len(Events))
	}

	hooks := section(t, "integrations")
	var hookField Field
	for _, f := range hooks.Fields {
		if f.Kind == List {
			for _, sub := range f.Fields {
				if sub.Key == "events" {
					hookField = f
				}
			}
		}
	}
	if hookField.Key == "" {
		t.Skip("no webhook list with an events field in this section")
	}
	kept := dropUnknown(hooks.Fields, map[string]any{hookField.Key: []any{map[string]any{"events": []any{"license_limit", "failed_install"}}}})
	ev := kept[hookField.Key].([]any)[0].(map[string]any)["events"].([]any)
	if len(ev) != 1 || ev[0] != "failed_install" {
		t.Fatalf("the retired choice must be dropped, the others kept: %v", ev)
	}
}

// An installation that saved its notification rules before an event was added (the four rules of the first version)
// must keep loading and saving them: the new events appear, switched off, and the saved rules keep their values.
func TestStoredRulesGainNewlyAddedEvents(t *testing.T) {
	sec := section(t, "notifications")
	old := []any{}
	for _, ev := range []string{"failed_install", "update_held", "device_offline", "agent_out_of_date"} {
		old = append(old, map[string]any{"event": ev, "enabled": ev == "device_offline", "email": true, "webhook": false,
			"recipients": []any{"ops@example.org"}, "threshold": 48, "quiet_hours": true})
	}
	norm, errs := sec.Normalize(dropUnknown(sec.Fields, map[string]any{"rules": old}))
	if len(errs) != 0 {
		t.Fatalf("a stored document from before the new events must still validate: %v", errs)
	}
	rules := norm["rules"].([]any)
	if len(rules) != len(Events) {
		t.Fatalf("got %d rules for %d events", len(rules), len(Events))
	}
	byEvent := map[string]map[string]any{}
	for _, r := range rules {
		m := r.(map[string]any)
		byEvent[m["event"].(string)] = m
	}
	if r := byEvent["device_offline"]; r["enabled"] != true || r["threshold"] != float64(48) && r["threshold"] != 48 {
		t.Fatalf("the saved rule lost its values: %v", r)
	}
	if r, ok := byEvent["low_disk"]; !ok || r["enabled"] != false {
		t.Fatalf("a new event must appear switched off: %v", r)
	}
}
