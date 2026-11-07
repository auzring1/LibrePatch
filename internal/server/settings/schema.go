// Package settings is the organization's typed, versioned configuration (decision D95). Every setting is declared once,
// in the registry (registry.go): its label, help text, default, type and limits. The server validates every write
// against that declaration (the console's form is only a convenience), stores one document per section with a revision
// for optimistic concurrency, seals secrets, audits each change with before and after, and caches reads safely.
package settings

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SchemaVersion is the version of the settings documents. Add a migration step in migrate.go when a field changes
// meaning; a document written by a newer server is refused rather than guessed at.
const SchemaVersion = 1

// Kind is a field's type.
type Kind string

// Field kinds.
const (
	Bool     Kind = "bool"
	Int      Kind = "int"
	String   Kind = "string"
	Text     Kind = "text"     // multi-line string
	Enum     Kind = "enum"     // one of Options
	Multi    Kind = "multi"    // a list of Options
	Time     Kind = "time"     // HH:MM
	Timezone Kind = "timezone" // an IANA name, or "" for "the viewer's own"
	Emails   Kind = "emails"   // a list of e-mail addresses
	CIDRs    Kind = "cidrs"    // a list of IP addresses or networks
	URL      Kind = "url"      // an https (or, for internal webhooks, http) URL
	Secret   Kind = "secret"   // write-only; sealed at rest; never returned or exported
	List     Kind = "list"     // a list of objects described by Fields
	Regex    Kind = "regex"    // a regular expression (checked by compiling it)
	Tags     Kind = "tags"     // a list of free-text values (the choices of a custom field)
)

// Option is one choice of an Enum or Multi field.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Effect says honestly what a setting does today, so the console can tell people.
const (
	Live    = "live"    // the server or console acts on it now
	Prefill = "prefill" // used as the starting value when someone creates something
	Planned = "planned" // stored and validated, nothing consumes it yet
)

// Field declares one setting.
type Field struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Help    string `json:"help"`
	Kind    Kind   `json:"kind"`
	Default any    `json:"default"`
	// Min and Max bound an Int, the length of a String/Text/Secret, and the number of items of a list.
	Min     int      `json:"min,omitempty"`
	Max     int      `json:"max,omitempty"`
	Options []Option `json:"options,omitempty"`
	// Fields describes the items of a List.
	Fields []Field `json:"fields,omitempty"`
	// Fixed: the items of a List are a closed set (one per value of the Enum field named by ItemKey); people can edit
	// them but not add or remove them.
	Fixed   bool   `json:"fixed,omitempty"`
	ItemKey string `json:"item_key,omitempty"`
	// Required: a String/Text/URL/Enum must not be empty.
	Required    bool   `json:"required,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Unit        string `json:"unit,omitempty"`
	// ShowIf hides the field in the console unless the named Bool field of the same object is true.
	ShowIf string `json:"show_if,omitempty"`
	Effect string `json:"effect"`
	// Validate is an extra check run after the type checks; it sees the section's other values.
	Validate func(v any, all map[string]any) error `json:"-"`
}

// Section groups fields under one permission.
type Section struct {
	ID          string  `json:"id"`
	Label       string  `json:"label"`
	Description string  `json:"description"`
	Perm        string  `json:"perm"`
	Fields      []Field `json:"fields"`
	// Cross checks rules that involve several fields or the caller (for example that the IP allow-list still lets the
	// person who saves it in). secrets says which secret paths are saved after this change.
	Cross func(vals map[string]any, secrets map[string]bool, a Actor) FieldErrors `json:"-"`
}

// FieldErrors maps a field path ("smtp_host", "webhooks[2].url") to a message.
type FieldErrors map[string]string

func (e FieldErrors) Error() string {
	keys := make([]string, 0, len(e))
	for k := range e {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+e[k])
	}
	return "settings: " + strings.Join(parts, "; ")
}

var (
	timeRe  = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	slugRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,29}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	optsSet = func(opts []Option) map[string]bool {
		m := make(map[string]bool, len(opts))
		for _, o := range opts {
			m[o.Value] = true
		}
		return m
	}
)

func hasControl(s string, allowNewline bool) bool {
	for _, r := range s {
		if unicode.IsControl(r) && !(allowNewline && (r == '\n' || r == '\r' || r == '\t')) {
			return true
		}
	}
	return false
}

// Normalize checks values against the section's declaration and returns the cleaned document: unknown keys are
// refused, missing keys take their defaults, numbers and lists are coerced to canonical types. Secret fields are not
// part of the result (see SplitSecrets).
func (s Section) Normalize(in map[string]any) (map[string]any, FieldErrors) {
	errs := FieldErrors{}
	out := normalizeObject(s.Fields, in, "", errs, true)
	if len(errs) == 0 {
		for _, f := range s.Fields {
			if f.Validate != nil && f.Kind != Secret {
				if err := f.Validate(out[f.Key], out); err != nil {
					errs[f.Key] = err.Error()
				}
			}
		}
	}
	return out, errs
}

// Defaults returns the section's default document (secrets omitted).
func (s Section) Defaults() map[string]any {
	out := map[string]any{}
	for _, f := range s.Fields {
		if f.Kind == Secret {
			continue
		}
		out[f.Key] = cloneValue(f.Default)
	}
	return out
}

func cloneValue(v any) any {
	switch x := v.(type) {
	case []any:
		c := make([]any, len(x))
		for i := range x {
			c[i] = cloneValue(x[i])
		}
		return c
	case []string:
		c := make([]any, len(x))
		for i := range x {
			c[i] = x[i]
		}
		return c
	case map[string]any:
		c := make(map[string]any, len(x))
		for k, e := range x {
			c[k] = cloneValue(e)
		}
		return c
	}
	return v
}

func normalizeObject(fields []Field, in map[string]any, path string, errs FieldErrors, top bool) map[string]any {
	out := map[string]any{}
	known := map[string]Field{}
	for _, f := range fields {
		known[f.Key] = f
	}
	for k := range in {
		if _, ok := known[k]; !ok {
			errs[join(path, k)] = "is not a setting"
		}
	}
	for _, f := range fields {
		p := join(path, f.Key)
		raw, present := in[f.Key]
		if f.Kind == Secret {
			// A secret is never part of the document; SplitSecrets takes it out first. Reaching here means the
			// caller passed one in a place that cannot hold it.
			continue
		}
		if !present {
			out[f.Key] = cloneValue(f.Default)
			continue
		}
		v, err := normalizeValue(f, raw, p, errs)
		if err != "" {
			errs[p] = err
			continue
		}
		out[f.Key] = v
	}
	return out
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func toInt(raw any) (int, bool) {
	switch x := raw.(type) {
	case float64:
		if x != float64(int(x)) {
			return 0, false
		}
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	}
	return 0, false
}

func toStrings(raw any) ([]string, bool) {
	switch x := raw.(type) {
	case nil:
		return []string{}, true
	case []string:
		return append([]string{}, x...), true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func normalizeValue(f Field, raw any, path string, errs FieldErrors) (any, string) {
	switch f.Kind {
	case Bool:
		b, ok := raw.(bool)
		if !ok {
			return nil, "must be true or false"
		}
		return b, ""
	case Int:
		n, ok := toInt(raw)
		if !ok {
			return nil, "must be a whole number"
		}
		if n < f.Min || n > f.Max {
			return nil, fmt.Sprintf("must be between %d and %d", f.Min, f.Max)
		}
		return n, ""
	case String, Text, URL, Regex:
		s, ok := raw.(string)
		if !ok {
			return nil, "must be text"
		}
		s = strings.TrimSpace(s)
		if hasControl(s, f.Kind == Text) || !utf8.ValidString(s) {
			return nil, "contains characters that are not allowed"
		}
		if s == "" {
			if f.Required {
				return nil, "is required"
			}
			return "", ""
		}
		if n := utf8.RuneCountInString(s); (f.Min > 0 && n < f.Min) || (f.Max > 0 && n > f.Max) {
			return nil, fmt.Sprintf("must be %d to %d characters", f.Min, f.Max)
		}
		switch f.Kind {
		case URL:
			u, err := url.Parse(s)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
				return nil, "must be an http or https address without a password in it"
			}
		case Regex:
			if _, err := regexp.Compile(s); err != nil {
				return nil, "is not a valid regular expression"
			}
		}
		return s, ""
	case Enum:
		s, ok := raw.(string)
		if !ok || (!optsSet(f.Options)[s] && !(s == "" && !f.Required)) {
			return nil, "is not one of the offered choices"
		}
		return s, ""
	case Multi:
		ss, ok := toStrings(raw)
		if !ok {
			return nil, "must be a list"
		}
		set := optsSet(f.Options)
		seen := map[string]bool{}
		for _, s := range ss {
			if !set[s] || seen[s] {
				return nil, "has a choice that is not offered or is repeated"
			}
			seen[s] = true
		}
		if f.Min > 0 && len(ss) < f.Min {
			return nil, fmt.Sprintf("needs at least %d choice(s)", f.Min)
		}
		return toAny(ss), ""
	case Tags:
		ss, ok := toStrings(raw)
		if !ok {
			return nil, "must be a list of text values"
		}
		max := f.Max
		if max == 0 {
			max = 50
		}
		if len(ss) > max {
			return nil, fmt.Sprintf("at most %d values", max)
		}
		out := make([]string, 0, len(ss))
		seen := map[string]bool{}
		for _, s := range ss {
			s = strings.TrimSpace(s)
			if s == "" || utf8.RuneCountInString(s) > 100 || hasControl(s, false) {
				return nil, "each value is 1 to 100 characters of plain text"
			}
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		return toAny(out), ""
	case Time:
		s, ok := raw.(string)
		if !ok || !timeRe.MatchString(s) {
			return nil, "must be a time like 22:30"
		}
		return s, ""
	case Timezone:
		s, ok := raw.(string)
		if !ok {
			return nil, "must be text"
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return "", ""
		}
		if _, err := time.LoadLocation(s); err != nil || strings.ContainsAny(s, " \\") {
			return nil, "is not a known time zone (use a name like Europe/Berlin)"
		}
		return s, ""
	case Emails:
		ss, ok := toStrings(raw)
		if !ok {
			return nil, "must be a list of e-mail addresses"
		}
		if f.Max > 0 && len(ss) > f.Max {
			return nil, fmt.Sprintf("at most %d addresses", f.Max)
		}
		out := make([]string, 0, len(ss))
		seen := map[string]bool{}
		for _, s := range ss {
			s = strings.TrimSpace(s)
			a, err := mail.ParseAddress(s)
			if err != nil || a.Address != s || len(s) > 254 || strings.ContainsAny(s, "\r\n") {
				return nil, fmt.Sprintf("%q is not a plain e-mail address", s)
			}
			k := strings.ToLower(s)
			if !seen[k] {
				seen[k] = true
				out = append(out, s)
			}
		}
		return toAny(out), ""
	case CIDRs:
		ss, ok := toStrings(raw)
		if !ok {
			return nil, "must be a list of addresses or networks"
		}
		if f.Max > 0 && len(ss) > f.Max {
			return nil, fmt.Sprintf("at most %d entries", f.Max)
		}
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !strings.Contains(s, "/") {
				ip := net.ParseIP(s)
				if ip == nil {
					return nil, fmt.Sprintf("%q is not an IP address or network (like 10.0.0.0/8)", s)
				}
				out = append(out, ip.String())
				continue
			}
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Sprintf("%q is not an IP address or network (like 10.0.0.0/8)", s)
			}
			out = append(out, n.String())
		}
		return toAny(out), ""
	case List:
		arr, ok := raw.([]any)
		if !ok {
			if raw == nil {
				arr = []any{}
			} else {
				return nil, "must be a list"
			}
		}
		if f.Max > 0 && len(arr) > f.Max {
			return nil, fmt.Sprintf("at most %d items", f.Max)
		}
		items := make([]any, 0, len(arr))
		seenID := map[string]bool{}
		seenKey := map[string]bool{}
		for i, e := range arr {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, "has an item that is not an object"
			}
			ip := fmt.Sprintf("%s[%d]", path, i)
			// Secret fields of items travel separately (SplitSecrets); drop them here so they are never stored in data.
			clean := map[string]any{}
			for k, v := range m {
				if fld, ok := findField(f.Fields, k); ok && fld.Kind == Secret {
					continue
				}
				clean[k] = v
			}
			item := normalizeObject(f.Fields, clean, ip, errs, false)
			if id, ok := item["id"].(string); ok {
				if id != "" && !idRe.MatchString(id) {
					errs[ip+".id"] = "is not valid"
				}
				if id != "" && seenID[id] {
					errs[ip+".id"] = "is repeated"
				}
				seenID[id] = true
			}
			if f.ItemKey != "" {
				if k, _ := item[f.ItemKey].(string); k != "" {
					if seenKey[k] {
						errs[ip+"."+f.ItemKey] = "is repeated"
					}
					seenKey[k] = true
				}
			}
			for _, sub := range f.Fields {
				if sub.Validate != nil && sub.Kind != Secret {
					if err := sub.Validate(item[sub.Key], item); err != nil {
						errs[join(ip, sub.Key)] = err.Error()
					}
				}
			}
			items = append(items, item)
		}
		if f.Fixed {
			want := optsSet(findOptions(f))
			if len(items) != len(want) || len(seenKey) != len(want) {
				return nil, "must keep all of its built-in items"
			}
			for k := range seenKey {
				if !want[k] {
					return nil, "has an item that is not built in"
				}
			}
		}
		return items, ""
	}
	return nil, "has an unsupported type"
}

func findField(fs []Field, key string) (Field, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

func findOptions(f Field) []Option {
	if f.ItemKey != "" {
		if k, ok := findField(f.Fields, f.ItemKey); ok {
			return k.Options
		}
	}
	return nil
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
