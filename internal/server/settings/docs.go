package settings

import (
	"fmt"
	"strings"
)

func def(f Field) string {
	switch v := f.Default.(type) {
	case nil:
		return "none"
	case string:
		if v == "" {
			return "empty"
		}
		return "`" + v + "`"
	case []any:
		if len(v) == 0 {
			return "empty"
		}
		if f.Kind == List {
			return fmt.Sprintf("%d built-in item(s)", len(v))
		}
		parts := make([]string, len(v))
		for i, e := range v {
			parts[i] = fmt.Sprint(e)
		}
		return "`" + strings.Join(parts, ", ") + "`"
	}
	return fmt.Sprintf("`%v`", f.Default)
}

func limits(f Field) string {
	switch f.Kind {
	case Int:
		u := ""
		if f.Unit != "" {
			u = " " + f.Unit
		}
		return fmt.Sprintf("%d to %d%s", f.Min, f.Max, u)
	case Enum, Multi:
		o := make([]string, len(f.Options))
		for i, x := range f.Options {
			o[i] = x.Value
		}
		return strings.Join(o, ", ")
	case Text, String, Secret, URL, Regex:
		if f.Max > 0 {
			return fmt.Sprintf("up to %d characters", f.Max)
		}
	case Emails, CIDRs, Tags, List:
		if f.Max > 0 {
			return fmt.Sprintf("up to %d entries", f.Max)
		}
	}
	return ""
}

var effect = map[string]string{Live: "in effect", Prefill: "starting value", Planned: "stored only"}

func cell(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ") }

func table(w *strings.Builder, fs []Field, indent string) {
	fmt.Fprintf(w, "%s| Setting | Type | Default | Limits | Effect | What it does |\n%s|---|---|---|---|---|---|\n", indent, indent)
	for _, f := range fs {
		fmt.Fprintf(w, "%s| **%s** (`%s`) | %s | %s | %s | %s | %s |\n", indent, cell(f.Label), f.Key, f.Kind, cell(def(f)), cell(limits(f)), effect[f.Effect], cell(f.Help))
	}
}

// Markdown renders the settings reference (docs/SETTINGS.md) from the registry.
func Markdown() string {
	var w strings.Builder
	w.WriteString(`# Settings reference

*This file is generated from the settings registry (internal/server/settings/registry.go) by
go run ./internal/server/settings/gen. Edit the registry, not this file. A test fails when it is out of date.*

## How settings work

* **Where.** Console: Settings (left navigation, search box at the top). Every section is a form with a help text under
  each field, a "Reset to default" link, an "unsaved changes" bar, and a prompt before you leave with unsaved edits.
* **Validation.** The server checks every value against its declaration (type, range, choices, length, shape) and refuses
  the whole save with a message per field; the console's checks are a convenience only. Unknown keys are refused.
* **Audit.** Every save writes ` + "`update`" + ` to the audit log with the section, the new revision and, per changed
  setting, the value before and after. Secrets are never written to the log (only "(set)" or "(cleared)"). Test sends,
  exports, imports and support-bundle downloads are audited too.
* **Concurrency.** A section has a revision. Saving with an older revision answers 409 so two administrators cannot
  silently overwrite each other.
* **Storage and versions.** One JSON document per section (` + "`settings_sections`" + `), with a schema version
  (currently ` + fmt.Sprint(SchemaVersion) + `). A document from a newer server is refused, not guessed at. Reads are cached for up to 30 seconds and
  are invalidated on save; callers always get a copy.
* **Secrets** (mail password, webhook secrets) are sealed with the server's master key, kept apart from the values, never
  returned by the API, never exported, never in the support bundle. In a form, leave a secret empty to keep it.
* **Export and import.** Settings > Export settings downloads a JSON file of every section's values (no secrets, no
  branding images). Import checks the file first (dry run) and applies it only if every section is valid; it needs
  the same permissions as editing the sections. Branding (names, colors, texts, images) has its own page and is not part of the file.
* **Who may change what.** Each section has its own permission. Administrators hold all of them; the operator role holds
  notifications, device defaults and scheduled reports; read-only people hold none. Export, import and About need the
  administrator permission ` + "`settings:write`" + `. API tokens cannot hold settings permissions (except the older ` + "`settings:write`" + `).
  Site-scoped roles never grant 
* **Effect.** "in effect": the server or console acts on it now. "starting value": used when someone creates a ring or a
  rule; existing ones are not changed. "stored only": saved and validated, nothing uses it yet (nothing at the moment).

`)
	for _, s := range Sections {
		fmt.Fprintf(&w, "## %s\n\nPermission: `%s`. %s\n\n", s.Label, s.Perm, s.Description)
		table(&w, s.Fields, "")
		for _, f := range s.Fields {
			if f.Kind != List {
				continue
			}
			fmt.Fprintf(&w, "\n**Each item of “%s”:**\n\n", f.Label)
			table(&w, f.Fields, "")
		}
		w.WriteString("\n")
	}
	w.WriteString(`## Pages that are not schema-driven

* **General** (per-user installs policy), permission ` + "`settings:write`" + ` to change, ` + "`catalog:read`" + ` to see: the default for how deployments treat copies of an app that users installed for themselves.
* **Branding**, permission ` + "`branding:write`" + `: organization and product name, colors, sign-in texts, support contact, report footer, images. Theme choices live under Appearance.
* **About**, permission ` + "`settings:write`" + `: version, build, database and license state, and the support bundle (a zip with configuration, settings, counts and the latest audit and notification entries; never secrets, keys, tokens, certificates or device data).

## Not done yet (honest list)

* The audit log is never pruned: it is append-only and hash-chained, and verification starts at the first entry. Retention for it needs a checkpoint design.
* Scheduled report PDFs use a monospaced table layout (the header carries the report logo, names and brand color).
* Custom device fields are text, choice and date; numbers and multi-select are not supported, and group filters treat all of them as text.
* "Language" sets number and date formatting only; the console's text is English.
* Maintenance windows and restart policy defaults pre-fill new update rings; there is no organization-wide window that overrides rings.
`)
	return w.String()
}
