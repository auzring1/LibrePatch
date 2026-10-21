package settings

import "fmt"

func init() {
	for i := range Sections {
		switch Sections[i].ID {
		case "security":
			Sections[i].Cross = crossSecurity
		case "notifications":
			Sections[i].Cross = crossNotifications
		case "reports":
			Sections[i].Cross = crossReports
		case "devices":
			Sections[i].Cross = crossDevices
		case "updates":
			Sections[i].Cross = crossUpdates
		}
	}
}

func crossSecurity(vals map[string]any, _ map[string]bool, a Actor) FieldErrors {
	errs := FieldErrors{}
	v := V(vals)
	if list := v.Strings("ip_allowlist"); len(list) > 0 && a.IP != "" && !InAllowlist(list, a.IP) {
		errs["ip_allowlist"] = fmt.Sprintf("does not include your own address (%s), so saving it would lock you out", a.IP)
	}
	if v.Bool("login_banner_enabled") && v.Str("login_banner") == "" {
		errs["login_banner"] = "is required when the notice is shown"
	}
	return errs
}

func crossNotifications(vals map[string]any, secrets map[string]bool, _ Actor) FieldErrors {
	errs := FieldErrors{}
	v := V(vals)
	if v.Bool("email_enabled") {
		if v.Str("smtp_host") == "" {
			errs["smtp_host"] = "is required to send e-mail"
		}
		if v.Str("from_address") == "" {
			errs["from_address"] = "is required to send e-mail"
		}
		if (v.Str("smtp_username") != "") != secrets["smtp_password"] {
			errs["smtp_password"] = "needs a user name and a password together, or neither"
		}
	}
	if v.Bool("email_enabled") && v.Str("smtp_security") == "none" && (v.Str("smtp_username") != "" || secrets["smtp_password"]) {
		errs["smtp_security"] = "a login needs an encrypted connection: choose STARTTLS or TLS, or clear the user name and password"
	}
	if v.Bool("quiet_hours_enabled") && v.Str("quiet_start") == v.Str("quiet_end") {
		errs["quiet_end"] = "must differ from the start"
	}
	for i, r := range v.Items("rules") {
		if r.Bool("enabled") && r.Bool("email") && len(r.Strings("recipients")) == 0 {
			errs[fmt.Sprintf("rules[%d].recipients", i)] = "add at least one recipient or turn off e-mail for this rule"
		}
		if r.Bool("enabled") && !r.Bool("email") && !r.Bool("webhook") {
			errs[fmt.Sprintf("rules[%d].email", i)] = "choose e-mail, webhooks or both"
		}
		if r.Bool("enabled") && r.Int("threshold") == 0 {
			switch r.Str("event") {
			case "device_offline":
				errs[fmt.Sprintf("rules[%d].threshold", i)] = "must be at least 1 hour"
			case "restart_pending_long":
				errs[fmt.Sprintf("rules[%d].threshold", i)] = "must be at least 1 day"
			case "low_disk":
				errs[fmt.Sprintf("rules[%d].threshold", i)] = "must be at least 1 GB"
			}
		}
	}
	return errs
}

func crossReports(vals map[string]any, _ map[string]bool, _ Actor) FieldErrors {
	errs := FieldErrors{}
	for i, sc := range V(vals).Items("schedules") {
		if sc.Bool("enabled") && len(sc.Strings("recipients")) == 0 {
			errs[fmt.Sprintf("schedules[%d].recipients", i)] = "add at least one recipient"
		}
	}
	return errs
}

func crossDevices(vals map[string]any, _ map[string]bool, _ Actor) FieldErrors {
	errs := FieldErrors{}
	for i, f := range V(vals).Items("custom_fields") {
		opts := f.Strings("options")
		switch f.Str("type") {
		case "select":
			if len(opts) == 0 {
				errs[fmt.Sprintf("custom_fields[%d].options", i)] = "add at least one choice"
			}
			if len(opts) > 50 {
				errs[fmt.Sprintf("custom_fields[%d].options", i)] = "at most 50 choices"
			}
			for _, o := range opts {
				if o == "" || len(o) > 100 {
					errs[fmt.Sprintf("custom_fields[%d].options", i)] = "each choice is 1 to 100 characters"
				}
			}
		default:
			if len(opts) > 0 {
				errs[fmt.Sprintf("custom_fields[%d].options", i)] = "only a choice field has choices"
			}
		}
	}
	return errs
}

func crossUpdates(vals map[string]any, _ map[string]bool, _ Actor) FieldErrors {
	errs := FieldErrors{}
	v := V(vals)
	if v.Bool("window_enabled") && len(v.Strings("window_days")) == 0 {
		errs["window_days"] = "choose at least one day"
	}
	return errs
}
