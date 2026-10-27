package settings

import (
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"strings"
)

// Permissions guarding each section. Administrators hold all of them; the operator role is given the ones that are
// day-to-day configuration (notifications, devices, reports). Security, data, integrations and the rest stay with
// administrators. Sections are never delegable to an API token.
const (
	PermAppearance    = "settings:appearance"
	PermSecurity      = "settings:security"
	PermNotifications = "settings:notifications"
	PermUpdates       = "settings:updates"
	PermDevices       = "settings:devices"
	PermReports       = "settings:reports"
	PermData          = "settings:data"
	PermIntegrations  = "settings:integrations"
	// PermAll is the existing administrator permission; it guards export, import and the About section.
	PermAll = "settings:write"
)

// Events are the things that can notify someone or call a webhook.
var Events = []Option{
	{"failed_install", "An install or update failed on a device"},
	{"update_held", "An update or software version was held because a ring missed its success threshold"},
	{"software_approval_needed", "A new software version is waiting for your approval"},
	{"device_offline", "A device has not reported for a while"},
	{"agent_out_of_date", "A device runs an older agent than the target release"},
	{"restart_pending_long", "A device has needed a restart for too long"},
	{"low_disk", "The system drive of a device is nearly full"},
	{"bitlocker_off", "A disk on a device is not protected by BitLocker"},
	{"os_end_of_support", "A device runs an operating system that is out of support or about to be"},
	{"exploited_vulnerability", "A vulnerability that is known to be exploited affects devices"},
}

// EventDoc documents an event for the integrations page: when it fires and the shape of its payload.
type EventDoc struct {
	Event   string         `json:"event"`
	When    string         `json:"when"`
	Payload map[string]any `json:"payload"`
}

// EventReference is the readable list of webhook events with example payloads.
func EventReference() []EventDoc {
	common := func(extra map[string]any) map[string]any {
		p := map[string]any{"id": "7f0c6c3e-0f8e-4d57-9c5d-4f4d7d2f1c11", "event": "", "time": "2026-01-15T09:30:00Z", "organization": "Example Organization"}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	doc := func(ev, when string, extra map[string]any) EventDoc {
		p := common(extra)
		p["event"] = ev
		return EventDoc{Event: ev, When: when, Payload: p}
	}
	return []EventDoc{
		doc("failed_install", "A job that installs, updates or removes software or a Windows update ends in failure.",
			map[string]any{"device": map[string]any{"id": "…", "hostname": "PC-0142"}, "job": map[string]any{"id": "…", "title": "Install 7-Zip 24.08", "reason": "exit code 1603"}}),
		doc("update_held", "A ring missed its success threshold, so the Windows update or software version is held back from later rings.",
			map[string]any{"update": map[string]any{"id": "…", "title": "2026-01 Cumulative Update (KB5099999)"}, "ring": "Pilot", "reason": "3 of 10 devices failed"}),
		doc("software_approval_needed", "A new version of a package that a software policy keeps updated is waiting for an administrator's approval (sent once per package and version).",
			map[string]any{"package": map[string]any{"name": "7-Zip"}, "version": "24.09"}),
		doc("device_offline", "A device has not reported for at least the configured number of hours (sent once per outage).",
			map[string]any{"device": map[string]any{"id": "…", "hostname": "PC-0142"}, "hours_offline": 30}),
		doc("agent_out_of_date", "A device reports an agent version older than the rollout's target release (sent once per device and release).",
			map[string]any{"device": map[string]any{"id": "…", "hostname": "PC-0142"}, "agent_version": "1.2.0", "target_version": "1.3.0"}),
		doc("restart_pending_long", "A device that is online needs a restart and has not restarted for at least the configured number of days (sent at most once a week per device).",
			map[string]any{"device": map[string]any{"id": "…", "hostname": "PC-0142"}, "days_without_restart": 12}),
		doc("low_disk", "The system drive of an online device has less than the configured number of gigabytes free (sent at most once a week per device).",
			map[string]any{"device": map[string]any{"id": "…", "hostname": "PC-0142"}, "free_gb": 4.2}),
		doc("bitlocker_off", "A disk on a device reports that BitLocker is off (sent at most once a month per device).",
			map[string]any{"device": map[string]any{"id": "…", "hostname": "PC-0142"}, "disks": "C:"}),
		doc("os_end_of_support", "A device runs an operating system whose support has ended, or ends within the configured number of days (sent once per device and operating system release).",
			map[string]any{"device": map[string]any{"id": "…", "hostname": "PC-0142"}, "os": "Windows 11 24H2", "end_of_support": "2026-10-13", "days_left": -6}),
		doc("exploited_vulnerability", "A vulnerability on the CISA list of known exploited vulnerabilities affects at least one device (sent once per CVE; needs the vulnerability lookup turned on).",
			map[string]any{"cve": "CVE-2026-0001", "name": "Google Chromium V8 Type Confusion Vulnerability", "devices": 4, "fix_due": "2026-10-22", "ransomware": false}),
		doc("test", "An administrator pressed 'Send test' on a webhook.", map[string]any{"message": "This is a test delivery."}),
	}
}

// Sections is the registry: every setting the product has. Add a field here and the API, validation, export/import,
// audit trail, search and the console's form follow; a test checks that every field has a label, help and a default
// that passes its own validation.
var Sections = []Section{
	appearance, security, notifications, sso, updates, devices, downloads, scripts, reports, data, integrations, vulnerabilities,
}

// ByID returns a section.
func ByID(id string) (Section, bool) {
	for _, s := range Sections {
		if s.ID == id {
			return s, true
		}
	}
	return Section{}, false
}

var appearance = Section{
	ID: "appearance", Label: "Appearance", Perm: PermAppearance,
	Description: "How the console looks and formats dates for everyone, unless a person chooses otherwise. Themes and their organization-wide policy are below.",
	Fields: []Field{
		{Key: "default_density", Label: "Default table density", Kind: Enum, Default: "comfortable", Effect: Live,
			Help:    "Row height of tables for people who have not picked one in their account menu.",
			Options: []Option{{"comfortable", "Comfortable"}, {"compact", "Compact"}}},
		{Key: "sidebar_style", Label: "Sidebar style", Kind: Enum, Default: "expanded", Effect: Live,
			Help:    "Whether the navigation starts wide, with labels, or narrow, as icons only. People can change it for themselves with the button under the navigation.",
			Options: []Option{{"expanded", "Expanded, with labels"}, {"rail", "Narrow, icons only"}}},
		{Key: "date_format", Label: "Date format", Kind: Enum, Default: "locale", Effect: Live,
			Help:    "How dates are written in tables and pages.",
			Options: []Option{{"locale", "Follow the language and region"}, {"iso", "2026-01-31"}, {"dmy", "31/01/2026"}, {"mdy", "01/31/2026"}}},
		{Key: "time_format", Label: "Time format", Kind: Enum, Default: "locale", Effect: Live,
			Help:    "24-hour or 12-hour clock.",
			Options: []Option{{"locale", "Follow the language and region"}, {"24h", "24-hour (17:30)"}, {"12h", "12-hour (5:30 PM)"}}},
		{Key: "time_zone", Label: "Time zone", Kind: Timezone, Default: "", Effect: Live, Placeholder: "Europe/Berlin",
			Help: "The time zone times are shown in. Leave empty to show each person's own browser time zone."},
		{Key: "locale", Label: "Language and region", Kind: Enum, Default: "en-US", Effect: Live,
			Help: "Number and date formatting. The console's text is English; this does not translate it.",
			Options: []Option{{"en-US", "English (United States)"}, {"en-GB", "English (United Kingdom)"}, {"en-CA", "English (Canada)"}, {"en-AU", "English (Australia)"},
				{"de-DE", "Deutsch (Deutschland)"}, {"fr-FR", "Français (France)"}, {"es-ES", "Español (España)"}, {"nl-NL", "Nederlands"}, {"sv-SE", "Svenska"}}},
		{Key: "first_day_of_week", Label: "First day of the week", Kind: Enum, Default: "monday", Effect: Live,
			Help:    "Used by calendars and weekly report schedules.",
			Options: []Option{{"sunday", "Sunday"}, {"monday", "Monday"}, {"saturday", "Saturday"}}},
	},
}

var security = Section{
	ID: "security", Label: "Security", Perm: PermSecurity,
	Description: "Sign-in, sessions and access to the console. Multi-factor authentication is always required and cannot be turned off here.",
	Fields: []Field{
		{Key: "session_idle_minutes", Label: "Sign out after inactivity", Kind: Int, Default: 30, Min: 5, Max: 1440, Unit: "minutes", Effect: Live,
			Help: "A session with no activity for this long ends. Applies to new activity from now on."},
		{Key: "session_absolute_hours", Label: "Longest session", Kind: Int, Default: 12, Min: 1, Max: 72, Unit: "hours", Effect: Live,
			Help: "A session ends this long after sign-in even if it is in use. People then sign in again (with their second factor)."},
		{Key: "password_min_length", Label: "Minimum password length", Kind: Int, Default: 12, Min: 12, Max: 128, Unit: "characters", Effect: Live,
			Help: "For new passwords and password changes. Cannot be lowered below 12: long passphrases are stronger than complexity rules, and commonly used passwords are always refused."},
		{Key: "lockout_threshold", Label: "Lock an account after failed sign-ins", Kind: Int, Default: 10, Min: 3, Max: 20, Unit: "attempts", Effect: Live,
			Help: "Wrong passwords or second-factor codes in a row before the account is locked."},
		{Key: "lockout_minutes", Label: "Lockout duration", Kind: Int, Default: 15, Min: 1, Max: 1440, Unit: "minutes", Effect: Live,
			Help: "How long a locked account stays locked. An administrator can reset the account sooner."},
		{Key: "allow_security_keys", Label: "Allow security keys as a second factor", Kind: Bool, Default: true, Effect: Live,
			Help: "When off, people cannot add new security keys (the authenticator app is always how an account first gets its second factor). Keys people already have keep working."},
		{Key: "ip_allowlist", Label: "Console IP allow-list", Kind: CIDRs, Default: []any{}, Max: 50, Effect: Live, Placeholder: "10.20.0.0/16",
			Help: "When not empty, only these addresses and networks can reach the console and its API (agents are not affected). Your own current address must be in the list, or the change is refused. If you lock yourself out anyway, start the server with LIBREPATCH_IGNORE_IP_ALLOWLIST=true, fix the list, and restart without it."},
		{Key: "api_token_max_days", Label: "Longest API token lifetime", Kind: Int, Default: 365, Min: 1, Max: 365, Unit: "days", Effect: Live,
			Help: "New API tokens cannot be valid for longer than this. Existing tokens keep their expiry."},
		{Key: "login_banner_enabled", Label: "Show a notice on the sign-in page", Kind: Bool, Default: false, Effect: Live,
			Help: "Shows the text below before sign-in, for example a consent or authorized-use notice."},
		{Key: "login_banner", Label: "Notice text", Kind: Text, Default: "", Max: 2000, ShowIf: "login_banner_enabled", Effect: Live,
			Help: "Plain text, up to 2000 characters. Visible to anyone who can reach the sign-in page, so do not put anything private in it."},
		{Key: "login_banner_require_ack", Label: "Require people to accept the notice", Kind: Bool, Default: false, ShowIf: "login_banner_enabled", Effect: Live,
			Help: "People must tick a box saying they accept the notice before the sign-in form appears."},
	},
}

var notifications = Section{
	ID: "notifications", Label: "Notifications", Perm: PermNotifications,
	Description: "E-mail delivery, quiet hours and which events notify whom. Webhook endpoints are set up under Integrations; each rule can send to them.",
	Fields: []Field{
		{Key: "email_enabled", Label: "Send e-mail", Kind: Bool, Default: false, Effect: Live,
			Help: "Turn on to send notifications and scheduled reports by e-mail. Nothing is sent until the mail server below works (use Send test)."},
		{Key: "smtp_host", Label: "Mail server", Kind: String, Default: "", Max: 253, Placeholder: "smtp.example.org", ShowIf: "email_enabled", Effect: Live,
			Help: "Host name of your SMTP relay."},
		{Key: "smtp_port", Label: "Port", Kind: Int, Default: 587, Min: 1, Max: 65535, ShowIf: "email_enabled", Effect: Live,
			Help: "Usually 587 (STARTTLS), 465 (TLS from the start) or 25."},
		{Key: "smtp_security", Label: "Connection security", Kind: Enum, Default: "starttls", ShowIf: "email_enabled", Effect: Live,
			Help:    "The server's certificate is always verified. 'None' is only for a relay on a trusted internal network.",
			Options: []Option{{"starttls", "STARTTLS (upgrade the connection)"}, {"tls", "TLS from the start"}, {"none", "None (plain text, internal relays only)"}}},
		{Key: "smtp_username", Label: "User name", Kind: String, Default: "", Max: 254, ShowIf: "email_enabled", Effect: Live,
			Help: "Leave empty if the relay does not need a login."},
		{Key: "smtp_password", Label: "Password", Kind: Secret, Max: 512, ShowIf: "email_enabled", Effect: Live,
			Help: "Stored encrypted and never shown again. Leave empty to keep the saved one."},
		{Key: "from_address", Label: "From address", Kind: String, Default: "", Max: 254, Placeholder: "librepatch@example.org", ShowIf: "email_enabled", Effect: Live,
			Help: "The sender of every message.",
			Validate: func(v any, _ map[string]any) error {
				s, _ := v.(string)
				if s != "" && (!strings.Contains(s, "@") || strings.ContainsAny(s, " <>\r\n")) {
					return errors.New("must be a plain e-mail address")
				}
				return nil
			}},
		{Key: "quiet_hours_enabled", Label: "Use quiet hours", Kind: Bool, Default: false, Effect: Live,
			Help: "Messages that arrive during quiet hours are held and sent when they end (rules can opt out)."},
		{Key: "quiet_start", Label: "Quiet hours begin", Kind: Time, Default: "22:00", ShowIf: "quiet_hours_enabled", Effect: Live, Help: "Local time in the time zone below."},
		{Key: "quiet_end", Label: "Quiet hours end", Kind: Time, Default: "07:00", ShowIf: "quiet_hours_enabled", Effect: Live, Help: "Local time in the time zone below. May be earlier than the start (overnight)."},
		{Key: "quiet_time_zone", Label: "Quiet hours time zone", Kind: Timezone, Default: "UTC", ShowIf: "quiet_hours_enabled", Effect: Live, Placeholder: "Europe/Berlin",
			Help: "Time zone of the quiet hours."},
		{Key: "rules", Label: "Event rules", Kind: List, Fixed: true, ItemKey: "event", Effect: Live,
			Help: "One rule per event. Recipients are the people who get the e-mail; the threshold depends on the event.",
			Default: []any{
				ruleDefault("failed_install", false, 0),
				ruleDefault("update_held", false, 0),
				ruleDefault("software_approval_needed", false, 0),
				ruleDefault("device_offline", false, 24),
				ruleDefault("agent_out_of_date", false, 7),
				ruleDefault("restart_pending_long", false, 7),
				ruleDefault("low_disk", false, 10),
				ruleDefault("bitlocker_off", false, 0),
				ruleDefault("os_end_of_support", false, 90),
				ruleDefault("exploited_vulnerability", false, 0),
			},
			Fields: []Field{
				{Key: "event", Label: "Event", Kind: Enum, Required: true, Options: Events, Default: "failed_install", Effect: Live, Help: "What happened."},
				{Key: "enabled", Label: "Notify", Kind: Bool, Default: false, Effect: Live, Help: "Turn the rule on."},
				{Key: "email", Label: "By e-mail", Kind: Bool, Default: true, Effect: Live, Help: "Send an e-mail to the recipients."},
				{Key: "webhook", Label: "To webhooks", Kind: Bool, Default: true, Effect: Live, Help: "Call every enabled webhook that listens for this event."},
				{Key: "recipients", Label: "Recipients", Kind: Emails, Default: []any{}, Max: 20, Effect: Live, Placeholder: "oncall@example.org", Help: "E-mail addresses. Required when the rule sends e-mail."},
				{Key: "threshold", Label: "Threshold", Kind: Int, Default: 0, Min: 0, Max: 720, Effect: Live,
					Help: "Device offline: hours without a report. Agent out of date: days after a release before devices count as late. Restart pending too long: days without a restart. Low disk: gigabytes free on the system drive. Operating system end of support: days before the end to warn (0 warns only once support has ended). Other events ignore it."},
				{Key: "quiet_hours", Label: "Hold during quiet hours", Kind: Bool, Default: true, Effect: Live, Help: "Wait for the end of quiet hours instead of sending at once."},
			}},
	},
}

func ruleDefault(event string, enabled bool, threshold int) map[string]any {
	return map[string]any{"event": event, "enabled": enabled, "email": true, "webhook": true, "recipients": []any{}, "threshold": threshold, "quiet_hours": true}
}

var weekdays = []Option{{"monday", "Monday"}, {"tuesday", "Tuesday"}, {"wednesday", "Wednesday"}, {"thursday", "Thursday"}, {"friday", "Friday"}, {"saturday", "Saturday"}, {"sunday", "Sunday"}}

var updates = Section{
	ID: "updates", Label: "Update defaults", Perm: PermUpdates,
	Description: "Switch Windows updates on or off, and set the starting values for new update rings and auto-approval rules, so each one does not have to be filled in from scratch. Existing rings and rules are not changed. The update source and driver switch are on Automations, on the Windows tab.",
	Fields: []Field{
		{Key: "windows_updates_enabled", Label: "Manage Windows updates", Kind: Bool, Default: true, Effect: Live,
			Help: "Off turns every Windows update feature off for everyone: the Windows updates pages and the Windows tab under Automations disappear, devices stop scanning for Windows updates and nothing is approved or installed. Software updates, update rings for software and restarts keep working. Switch it off when another tool (WSUS, Intune, Windows Update for Business) manages Windows updates."},
		{Key: "ring_restart", Label: "Restart policy for new rings", Kind: Enum, Default: "outside_active_hours", Effect: Prefill,
			Help:    "What a new ring does about restarts after installing.",
			Options: []Option{{"never", "Never restart automatically"}, {"outside_active_hours", "Restart outside active hours"}, {"deadline", "Restart by a deadline"}}},
		{Key: "active_start", Label: "Active hours begin", Kind: Time, Default: "08:00", Effect: Prefill, Help: "Devices are not restarted between the start and the end of the active hours."},
		{Key: "active_end", Label: "Active hours end", Kind: Time, Default: "17:00", Effect: Prefill, Help: "Local time on the device."},
		{Key: "restart_deadline_hours", Label: "Restart deadline", Kind: Int, Default: 24, Min: 1, Max: 168, Unit: "hours", Effect: Prefill, Help: "For 'by a deadline': restart at the latest this long after installing."},
		{Key: "restart_notify_minutes", Label: "Warning before a restart", Kind: Int, Default: 15, Min: 1, Max: 1440, Unit: "minutes", Effect: Prefill, Help: "How long the countdown shown to signed-in users lasts."},
		{Key: "window_enabled", Label: "New rings use a maintenance window", Kind: Bool, Default: false, Effect: Prefill, Help: "Installs only start inside the window."},
		{Key: "window_days", Label: "Window days", Kind: Multi, Default: []any{"saturday", "sunday"}, Options: weekdays, ShowIf: "window_enabled", Effect: Prefill, Help: "Days the window is open."},
		{Key: "window_start", Label: "Window opens", Kind: Time, Default: "22:00", ShowIf: "window_enabled", Effect: Prefill, Help: "Local time on the device."},
		{Key: "window_end", Label: "Window closes", Kind: Time, Default: "05:00", ShowIf: "window_enabled", Effect: Prefill, Help: "May be earlier than the opening time (overnight)."},
		{Key: "rule_include_drivers", Label: "New rules also approve drivers", Kind: Bool, Default: false, ShowIf: "windows_updates_enabled", Effect: Prefill, Help: "Drivers are riskier to install unattended, so the default is off."},
		{Key: "rule_delay_days", Label: "New rules wait after release", Kind: Int, Default: 7, Min: 0, Max: 365, Unit: "days", ShowIf: "windows_updates_enabled", Effect: Prefill, Help: "Days an update must have been out before a rule approves it."},
		{Key: "rule_templates", Label: "Auto-approval rule templates", Kind: List, Default: []any{
			map[string]any{"id": "tpl-security", "name": "Security and critical, after a week", "classifications": []any{"Security Updates", "Critical Updates"}, "severities": []any{"Critical", "Important"}, "include_drivers": false, "delay_days": 7},
			map[string]any{"id": "tpl-definitions", "name": "Definition updates, right away", "classifications": []any{"Definition Updates"}, "severities": []any{}, "include_drivers": false, "delay_days": 0},
		}, Max: 20, ShowIf: "windows_updates_enabled", Effect: Prefill, Help: "Named starting points offered when you add a rule. A template does nothing by itself.",
			Fields: []Field{
				{Key: "id", Label: "Id", Kind: String, Default: "", Max: 64, Effect: Prefill, Help: "Assigned automatically."},
				{Key: "name", Label: "Name", Kind: String, Required: true, Default: "New template", Min: 1, Max: 100, Effect: Prefill, Help: "Shown when choosing a template."},
				{Key: "classifications", Label: "Classifications", Kind: Multi, Default: []any{}, Effect: Prefill, Help: "Empty means any.",
					Options: []Option{{"Security Updates", "Security Updates"}, {"Critical Updates", "Critical Updates"}, {"Definition Updates", "Definition Updates"}, {"Drivers", "Drivers"}, {"Feature Packs", "Feature Packs"}, {"Service Packs", "Service Packs"}, {"Update Rollups", "Update Rollups"}, {"Updates", "Updates"}, {"Upgrades", "Upgrades"}, {"Tools", "Tools"}}},
				{Key: "severities", Label: "Severities", Kind: Multi, Default: []any{}, Effect: Prefill, Help: "Empty means any.",
					Options: []Option{{"Critical", "Critical"}, {"Important", "Important"}, {"Moderate", "Moderate"}, {"Low", "Low"}, {"Unrated", "Unrated"}}},
				{Key: "include_drivers", Label: "Also approve drivers", Kind: Bool, Default: false, Effect: Prefill, Help: "Whether the rule approves driver updates."},
				{Key: "delay_days", Label: "Wait after release", Kind: Int, Default: 7, Min: 0, Max: 365, Unit: "days", Effect: Prefill, Help: "Days after release before the rule approves."},
			}},
	},
}

// DeviceColumns are the columns of the device table that an administrator can choose to show by default.
var DeviceColumns = []Option{
	{"hostname", "Device"}, {"status", "Status"}, {"connection", "Connection"}, {"os", "Operating system"}, {"model", "Model"},
	{"user", "User"}, {"software", "Software"}, {"seen", "Last seen"}, {"agent", "Agent"}, {"restart", "Restart"},
}

var devices = Section{
	ID: "devices", Label: "Device defaults", Perm: PermDevices,
	Description: "When a device counts as offline or stale, whether queued file deletions count as a pending restart, how devices are named, extra fields you want to record, and which columns the device list starts with.",
	Fields: []Field{
		{Key: "offline_hours", Label: "Offline after", Kind: Int, Default: 24, Min: 1, Max: 720, Unit: "hours", Effect: Live,
			Help: "A device that has not reported for this long is listed as needing attention on the dashboard."},
		{Key: "queued_deletes_need_restart", Label: "Queued file deletions count as a pending restart", Kind: Bool, Default: false, Effect: Live,
			Help: "Installers and updaters (Edge, Firefox, Office, antivirus) queue leftover files for deletion at the next restart, and queue new ones again within hours, so counting them makes PCs show \"restart pending\" several times a day. Off (recommended): they are listed on the device page but do not mark it as needing a restart, change compliance or trigger a restart. Takes effect as each device next reports, within about 30 minutes. Renames and replacements queued for the next restart always count."},
		{Key: "stale_cleanup_days", Label: "Delete revoked devices after", Kind: Int, Default: 0, Min: 0, Max: 3650, Unit: "days", Effect: Live,
			Help: "Revoked or retired devices not seen for this long are deleted, with everything stored about them (the audit log keeps the record). 0 keeps them forever. Active devices are never deleted by this."},
		{Key: "naming_pattern", Label: "Expected device name pattern", Kind: Regex, Default: "", Max: 200, Placeholder: "^(PC|LT)-[0-9]{4}$", Effect: Live,
			Help: "A regular expression. Devices whose name does not match are flagged in the device list. Empty turns the check off."},
		{Key: "custom_fields", Label: "Custom device fields", Kind: List, Default: []any{}, Max: 20, ItemKey: "key", Effect: Live,
			Help: "Extra information to record about each device, such as an asset tag or owner. Values are edited on the device page and shown in the device list.",
			Fields: []Field{
				{Key: "id", Label: "Id", Kind: String, Default: "", Max: 64, Effect: Live, Help: "Assigned automatically."},
				{Key: "key", Label: "Key", Kind: String, Required: true, Default: "", Min: 1, Max: 30, Placeholder: "asset_tag", Effect: Live,
					Help: "Lower-case letters, digits and underscores, starting with a letter. Cannot be changed later without losing the values.",
					Validate: func(v any, _ map[string]any) error {
						s, _ := v.(string)
						if !slugRe.MatchString(s) {
							return errors.New("use lower-case letters, digits and underscores, starting with a letter")
						}
						return nil
					}},
				{Key: "label", Label: "Label", Kind: String, Required: true, Default: "", Min: 1, Max: 60, Effect: Live, Help: "Shown to people."},
				{Key: "type", Label: "Type", Kind: Enum, Default: "text", Required: true, Effect: Live, Help: "What kind of value it holds.",
					Options: []Option{{"text", "Text"}, {"select", "Choice from a list"}, {"date", "Date"}}},
				{Key: "options", Label: "Choices", Kind: Tags, Default: []any{}, Max: 50, Effect: Live, Help: "For a choice field: the allowed values."},
				{Key: "show_in_list", Label: "Show in the device list", Kind: Bool, Default: true, Effect: Live, Help: "Adds a column to the device list."},
			}},
		{Key: "default_columns", Label: "Device list columns", Kind: Multi, Default: []any{"hostname", "status", "connection", "os", "user", "seen", "agent"}, Min: 1, Options: DeviceColumns, Effect: Live,
			Help: "The columns the device list shows for people who have not arranged their own."},
	},
}

var downloads = Section{
	ID: "downloads", Label: "Downloads", Perm: PermDevices,
	Description: "How devices get the installers they install. By default each device downloads from the vendor (or from this server) itself.",
	Fields: []Field{
		{Key: "peer_cache", Label: "Share downloads between computers on the same network", Kind: Bool, Default: false, Effect: Live,
			Help: "A device that has installed a program keeps the installer and hands it to other devices on the same network, so a few hundred PCs do not each download it from the internet. Every file is still checked against the fingerprint signed into the job, wherever it came from, and devices only talk to each other with their own certificates. It opens a port on each device (the agent adds the Windows Firewall rule for private and domain networks) and uses disk space on each. Takes effect as devices reconnect; an agent installed with a limit on its allowed jobs that leaves out peer_cache never shares."},
		{Key: "peer_cache_mb", Label: "Disk space for shared installers on each device", Kind: Int, Default: 2048, Min: 256, Max: 20480, Unit: "MB", ShowIf: "peer_cache", Effect: Live,
			Help: "The oldest installers are removed first when the limit is reached; installers unused for two weeks are removed. Turning sharing off empties the cache."},
		{Key: "peer_cache_port", Label: "Port for sharing", Kind: Int, Default: 7421, Min: 1024, Max: 65535, ShowIf: "peer_cache", Effect: Live,
			Help: "TCP port each device listens on, for other devices on the same network only. Change it only if something else uses it."},
	},
}

var sso = Section{
	ID: "sso", Label: "Single sign-on", Perm: PermSecurity,
	Description: "Let people sign in with your company account (Microsoft Entra ID, or any provider that speaks OpenID Connect) instead of a password stored here. Register this server as an application with your provider first; the sign-in address to give it is shown on the Single sign-on page. A local administrator account with its own password always keeps working, so a broken provider can never lock you out.",
	Fields: []Field{
		{Key: "enabled", Label: "Allow sign-in with a company account", Kind: Bool, Default: false, Effect: Live,
			Help: "Adds a button to the sign-in page. Local accounts keep working."},
		{Key: "label", Label: "Button text", Kind: String, Default: "Microsoft", Max: 40, ShowIf: "enabled", Effect: Live, Help: "The button reads “Sign in with …”."},
		{Key: "issuer", Label: "Issuer address", Kind: URL, Default: "", Max: 300, ShowIf: "enabled", Effect: Live,
			Placeholder: "https://login.microsoftonline.com/<directory id>/v2.0",
			Help:        "For Microsoft Entra ID: https://login.microsoftonline.com/ + your directory (tenant) ID + /v2.0. It must be a specific directory, not “common”. Must start with https://.",
			Validate: func(v any, all map[string]any) error {
				s, _ := v.(string)
				if on, _ := all["enabled"].(bool); on && !strings.HasPrefix(s, "https://") {
					return errors.New("the issuer address must start with https://")
				}
				return nil
			}},
		{Key: "client_id", Label: "Application (client) ID", Kind: String, Default: "", Max: 200, ShowIf: "enabled", Effect: Live, Help: "From the application registration at your provider."},
		{Key: "client_secret", Label: "Client secret", Kind: Secret, Max: 500, ShowIf: "enabled", Effect: Live, Help: "A client secret created for this application. Stored encrypted and never shown again; leave empty to keep the saved one."},
		{Key: "role_claim", Label: "Where roles come from", Kind: Enum, Default: "roles", ShowIf: "enabled", Effect: Live,
			Options: []Option{{"roles", "App roles (the roles claim)"}, {"groups", "Groups (the groups claim, object IDs for Entra ID)"}},
			Help:    "Which claim of the sign-in token is matched against the list below. App roles are the tidier choice for Entra ID; groups are limited to about 200 per person."},
		{Key: "role_map", Label: "Who gets which role", Kind: List, Default: []any{}, Max: 50, ItemKey: "value", ShowIf: "enabled", Effect: Live,
			Help: "A person gets the highest role of every line that matches what the provider says about them. Nobody who matches no line, and has no role set here by hand, can sign in.",
			Fields: []Field{
				{Key: "value", Label: "Role or group value", Kind: String, Required: true, Default: "", Min: 1, Max: 200, Effect: Live, Help: "The text the provider sends, for example the app role name or the group's object ID."},
				{Key: "role", Label: "Role here", Kind: Enum, Default: "readonly", Required: true, Effect: Live,
					Options: []Option{{"admin", "Administrator"}, {"operator", "Operator"}, {"readonly", "Read-only"}}, Help: "Applies to the whole organization."},
			}},
		{Key: "auto_create", Label: "Create accounts on first sign-in", Kind: Bool, Default: true, ShowIf: "enabled", Effect: Live,
			Help: "A person the provider lets in and the list above gives a role gets an account the first time. Off: only people who already have an account here (and have been linked) can sign in."},
		{Key: "link_by_email", Label: "Link existing accounts by email address", Kind: Bool, Default: false, ShowIf: "enabled", Effect: Live,
			Help: "If a local account has the same email address as the person signing in, connect the two on first sign-in. Turn this on only if your provider guarantees that people cannot choose their own email address (a single Entra ID directory does). Off: such a person is turned away and an administrator has to sort it out."},
		{Key: "allowed_domains", Label: "Only these email domains", Kind: Tags, Default: []any{}, Max: 20, ShowIf: "enabled", Effect: Live, Help: "Optional extra limit, for example example.org. Empty means any domain."},
		{Key: "idp_mfa_counts", Label: "The provider's multi-factor check replaces the second factor here", Kind: Bool, Default: false, ShowIf: "enabled", Effect: Live,
			Help: "Off (recommended): after signing in with the company account, people still confirm with an authenticator app or security key kept here. On: if the provider says the person used multi-factor (the amr claim contains “mfa”), no second step is asked; if it does not say so, it is asked."},
	},
}

var scripts = Section{
	ID: "scripts", Label: "Scripts", Perm: PermSecurity,
	Description: "Running scripts on devices is the most powerful thing this product can do: code you wrote runs as SYSTEM on the computers you choose. Only administrators can use it, every step is in the audit log, and a computer can be excluded for good by installing its agent with --no-scripts (or ALLOWSCRIPTS=0 in the MSI); the server cannot switch that off again.",
	Fields: []Field{
		{Key: "enabled", Label: "Allow running scripts", Kind: Bool, Default: true, Effect: Live,
			Help: "On: administrators can run scripts from the Scripts page on every computer whose agent allows it (all of them, unless one was installed with --no-scripts). Off: no script can be run and a run that is waiting for approval cannot be approved; the library stays and nothing is deleted."},
		{Key: "require_approval", Label: "A second administrator must approve every run", Kind: Bool, Default: false, Effect: Live,
			Help: "A run waits until another administrator (not the person who asked) approves exactly the script that was requested. Recommended whenever you have two or more administrators. With only one administrator nobody could approve, so it is off by default."},
	},
}

var reportKinds = []Option{{"compliance", "Patch compliance"}, {"missing_updates", "Missing updates"}, {"inventory", "Device inventory"}}

var reports = Section{
	ID: "reports", Label: "Scheduled reports", Perm: PermReports,
	Description: "Reports e-mailed on a schedule as PDF or CSV. Needs working e-mail under Notifications. The header carries your organization and product names from Branding.",
	Fields: []Field{
		{Key: "header_note", Label: "Header line", Kind: String, Default: "", Max: 200, Effect: Live, Placeholder: "Confidential, for IT management only",
			Help: "An extra line under the report title, for example a classification. Empty adds nothing."},
		{Key: "schedules", Label: "Schedules", Kind: List, Default: []any{}, Max: 20, Effect: Live,
			Help: "Each schedule sends one report to its recipients. Times are in the server's configured time zone below.",
			Fields: []Field{
				{Key: "id", Label: "Id", Kind: String, Default: "", Max: 64, Effect: Live, Help: "Assigned automatically."},
				{Key: "name", Label: "Name", Kind: String, Required: true, Default: "Weekly compliance", Min: 1, Max: 100, Effect: Live, Help: "Shown in the e-mail subject."},
				{Key: "enabled", Label: "Enabled", Kind: Bool, Default: true, Effect: Live, Help: "Paused schedules send nothing."},
				{Key: "report", Label: "Report", Kind: Enum, Default: "compliance", Required: true, Options: reportKinds, Effect: Live, Help: "What to send."},
				{Key: "format", Label: "Format", Kind: Enum, Default: "pdf", Required: true, Effect: Live, Help: "PDF to read, CSV to analyse.", Options: []Option{{"pdf", "PDF"}, {"csv", "CSV"}}},
				{Key: "frequency", Label: "Repeat", Kind: Enum, Default: "weekly", Required: true, Effect: Live, Help: "How often.", Options: []Option{{"daily", "Every day"}, {"weekly", "Every week"}, {"monthly", "Every month"}}},
				{Key: "weekday", Label: "Day of the week", Kind: Enum, Default: "monday", Options: weekdays, Effect: Live, Help: "For weekly schedules."},
				{Key: "day_of_month", Label: "Day of the month", Kind: Int, Default: 1, Min: 1, Max: 28, Effect: Live, Help: "For monthly schedules (1 to 28, so every month has it)."},
				{Key: "time", Label: "Time", Kind: Time, Default: "07:00", Effect: Live, Help: "When to send."},
				{Key: "recipients", Label: "Recipients", Kind: Emails, Default: []any{}, Max: 20, Effect: Live, Placeholder: "it-manager@example.org", Help: "At least one address."},
			}},
		{Key: "time_zone", Label: "Schedule time zone", Kind: Timezone, Default: "UTC", Effect: Live, Placeholder: "Europe/Berlin", Help: "The time zone schedule times are read in."},
	},
}

var data = Section{
	ID: "data", Label: "Data and retention", Perm: PermData,
	Description: "How long history is kept. The audit log is append-only and hash-chained, so the server never prunes it; export old entries from the Audit log page if you need to archive them.",
	Fields: []Field{
		{Key: "job_history_days", Label: "Keep finished jobs for", Kind: Int, Default: 365, Min: 0, Max: 3650, Unit: "days", Effect: Live,
			Help: "Finished, failed and cancelled jobs older than this are deleted. 0 keeps them forever. Jobs still in progress and the audit log are never touched."},
		{Key: "software_history_days", Label: "Keep software change history for", Kind: Int, Default: 730, Min: 0, Max: 3650, Unit: "days", Effect: Live,
			Help: "The record of programs added, removed or updated on each device (the History tab). Older entries are deleted. 0 keeps them forever. The software currently installed is never touched."},
		{Key: "compliance_history_days", Label: "Keep compliance history for", Kind: Int, Default: 400, Min: 30, Max: 1095, Unit: "days", Effect: Live,
			Help: "How far back the dashboard's compliance chart can go. Older daily snapshots are deleted."},
		{Key: "notification_log_days", Label: "Keep the notification log for", Kind: Int, Default: 90, Min: 7, Max: 730, Unit: "days", Effect: Live,
			Help: "Sent and failed e-mails and webhook deliveries, with the error if there was one."},
	},
}

var vulnerabilities = Section{
	ID: "vulnerabilities", Label: "Vulnerability data", Perm: PermIntegrations,
	Description: "Where the server gets the public lists of known vulnerabilities to match against what is installed on your devices. Nothing about your devices is sent: the server only downloads the lists and does the matching itself.",
	Fields: []Field{
		{Key: "enabled", Label: "Look up known vulnerabilities", Kind: Bool, Default: false, Effect: Live,
			Help: "Turns on the daily download of the CISA list of exploited vulnerabilities and, for the programs and Windows versions your devices have, of the NIST National Vulnerability Database. The Vulnerabilities page works with whatever has been downloaded."},
		{Key: "kev_url", Label: "CISA exploited-vulnerabilities list", Kind: URL, Default: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", Max: 500, Effect: Live,
			Help: "Change this only to download from a mirror of your own (for example when the server cannot reach the internet directly)."},
		{Key: "nvd_url", Label: "NIST vulnerability database", Kind: URL, Default: "https://services.nvd.nist.gov/rest/json/cves/2.0", Max: 500, Effect: Live,
			Help: "The address of the NVD CVE API, version 2.0. Change this only to use a mirror that answers the same way."},
		{Key: "nvd_api_key", Label: "NVD API key", Kind: Secret, Max: 200, Effect: Live,
			Help: "Optional. Without a key the NVD allows 5 requests per 30 seconds, so the first download takes a few minutes; a free key (requested from NIST) raises that tenfold. Stored encrypted and never shown again."},
	},
}

var integrations = Section{
	ID: "integrations", Label: "Integrations", Perm: PermIntegrations,
	Description: "Outgoing webhooks and the reference for what they send. API tokens are created on each person's Account page (administrators can see and revoke all of them under Users and roles).",
	Fields: []Field{
		{Key: "webhooks", Label: "Webhooks", Kind: List, Default: []any{}, Max: 20, Effect: Live,
			Help: "Each webhook receives a JSON POST for the events it listens to, signed with HMAC-SHA256 in the X-" + brand.Name + "-Signature header so the receiver can check where it came from.",
			Fields: []Field{
				{Key: "id", Label: "Id", Kind: String, Default: "", Max: 64, Effect: Live, Help: "Assigned automatically."},
				{Key: "name", Label: "Name", Kind: String, Required: true, Default: "New webhook", Min: 1, Max: 100, Effect: Live, Help: "Shown in the log."},
				{Key: "enabled", Label: "Enabled", Kind: Bool, Default: true, Effect: Live, Help: "Paused webhooks receive nothing."},
				{Key: "url", Label: "URL", Kind: URL, Required: true, Default: "", Max: 500, Placeholder: "https://hooks.example.org/librepatch", Effect: Live,
					Help: "Where to POST. Use https; plain http is only for receivers on a trusted internal network."},
				{Key: "secret", Label: "Signing secret", Kind: Secret, Max: 200, Effect: Live, Help: "Used to sign each delivery. Stored encrypted and never shown again; leave empty to keep the saved one."},
				{Key: "clear_secret", Label: "Remove the saved secret", Kind: Bool, Default: false, Effect: Live, Help: "Deliveries are then sent unsigned."},
				{Key: "events", Label: "Events", Kind: Multi, Default: []any{"failed_install", "update_held"}, Options: Events, Min: 1, Effect: Live, Help: "Which events to send. Rules under Notifications decide whether an event is sent at all."},
			}},
	},
}

// Check validates the registry itself: every field is documented, has a type-correct default, and ids are unique.
func Check() error {
	ids := map[string]bool{}
	for _, s := range Sections {
		if s.ID == "" || ids[s.ID] || s.Label == "" || s.Description == "" || s.Perm == "" {
			return fmt.Errorf("section %q is incomplete or repeated", s.ID)
		}
		ids[s.ID] = true
		if err := checkFields(s.ID, s.Fields); err != nil {
			return err
		}
		if _, errs := s.Normalize(s.Defaults()); len(errs) > 0 {
			return fmt.Errorf("section %s: its defaults do not pass its own validation: %v", s.ID, errs)
		}
	}
	return nil
}

func checkFields(where string, fs []Field) error {
	seen := map[string]bool{}
	for _, f := range fs {
		p := where + "." + f.Key
		if f.Key == "" || seen[f.Key] {
			return fmt.Errorf("%s: empty or repeated key", p)
		}
		seen[f.Key] = true
		if f.Label == "" || f.Help == "" || f.Kind == "" || f.Effect == "" {
			return fmt.Errorf("%s: label, help, kind and effect are required", p)
		}
		if f.Kind == Int && f.Max <= f.Min {
			return fmt.Errorf("%s: an int needs a range", p)
		}
		if (f.Kind == Enum || f.Kind == Multi) && len(f.Options) == 0 {
			return fmt.Errorf("%s: options are required", p)
		}
		if f.Kind == List {
			if err := checkFields(p, f.Fields); err != nil {
				return err
			}
		}
	}
	return nil
}
