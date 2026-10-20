# Settings reference

*This file is generated from the settings registry (internal/server/settings/registry.go) by
go run ./internal/server/settings/gen. Edit the registry, not this file. A test fails when it is out of date.*

## How settings work

* **Where.** Console: Settings (left navigation, search box at the top). Every section is a form with a help text under
  each field, a "Reset to default" link, an "unsaved changes" bar, and a prompt before you leave with unsaved edits.
* **Validation.** The server checks every value against its declaration (type, range, choices, length, shape) and refuses
  the whole save with a message per field; the console's checks are a convenience only. Unknown keys are refused.
* **Audit.** Every save writes `update` to the audit log with the section, the new revision and, per changed
  setting, the value before and after. Secrets are never written to the log (only "(set)" or "(cleared)"). Test sends,
  exports, imports and support-bundle downloads are audited too.
* **Concurrency.** A section has a revision. Saving with an older revision answers 409 so two administrators cannot
  silently overwrite each other.
* **Storage and versions.** One JSON document per section (`settings_sections`), with a schema version
  (currently 1). A document from a newer server is refused, not guessed at. Reads are cached for up to 30 seconds and
  are invalidated on save; callers always get a copy.
* **Secrets** (mail password, webhook secrets) are sealed with the server's master key, kept apart from the values, never
  returned by the API, never exported, never in the support bundle. In a form, leave a secret empty to keep it.
* **Export and import.** Settings > Export settings downloads a JSON file of every section's values (no secrets, no
  branding images). Import checks the file first (dry run) and applies it only if every section is valid; it needs
  the same permissions as editing the sections. Branding (names, colors, texts, images) has its own page and is not part of the file.
* **Who may change what.** Each section has its own permission. Administrators hold all of them; the operator role holds
  notifications, device defaults and scheduled reports; read-only people hold none. Export, import and About need the
  administrator permission `settings:write`. API tokens cannot hold settings permissions (except the older `settings:write`).
  Site-scoped roles never grant 
* **Effect.** "in effect": the server or console acts on it now. "starting value": used when someone creates a ring or a
  rule; existing ones are not changed. "stored only": saved and validated, nothing uses it yet (nothing at the moment).

## Appearance

Permission: `settings:appearance`. How the console looks and formats dates for everyone, unless a person chooses otherwise. Themes and their organization-wide policy are below.

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Default table density** (`default_density`) | enum | `comfortable` | comfortable, compact | in effect | Row height of tables for people who have not picked one in their account menu. |
| **Sidebar style** (`sidebar_style`) | enum | `expanded` | expanded, rail | in effect | Whether the navigation starts wide, with labels, or narrow, as icons only. People can change it for themselves with the button under the navigation. |
| **Date format** (`date_format`) | enum | `locale` | locale, iso, dmy, mdy | in effect | How dates are written in tables and pages. |
| **Time format** (`time_format`) | enum | `locale` | locale, 24h, 12h | in effect | 24-hour or 12-hour clock. |
| **Time zone** (`time_zone`) | timezone | empty |  | in effect | The time zone times are shown in. Leave empty to show each person's own browser time zone. |
| **Language and region** (`locale`) | enum | `en-US` | en-US, en-GB, en-CA, en-AU, de-DE, fr-FR, es-ES, nl-NL, sv-SE | in effect | Number and date formatting. The console's text is English; this does not translate it. |
| **First day of the week** (`first_day_of_week`) | enum | `monday` | sunday, monday, saturday | in effect | Used by calendars and weekly report schedules. |

## Security

Permission: `settings:security`. Sign-in, sessions and access to the console. Multi-factor authentication is always required and cannot be turned off here.

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Sign out after inactivity** (`session_idle_minutes`) | int | `30` | 5 to 1440 minutes | in effect | A session with no activity for this long ends. Applies to new activity from now on. |
| **Longest session** (`session_absolute_hours`) | int | `12` | 1 to 72 hours | in effect | A session ends this long after sign-in even if it is in use. People then sign in again (with their second factor). |
| **Minimum password length** (`password_min_length`) | int | `12` | 12 to 128 characters | in effect | For new passwords and password changes. Cannot be lowered below 12: long passphrases are stronger than complexity rules, and commonly used passwords are always refused. |
| **Lock an account after failed sign-ins** (`lockout_threshold`) | int | `10` | 3 to 20 attempts | in effect | Wrong passwords or second-factor codes in a row before the account is locked. |
| **Lockout duration** (`lockout_minutes`) | int | `15` | 1 to 1440 minutes | in effect | How long a locked account stays locked. An administrator can reset the account sooner. |
| **Allow security keys as a second factor** (`allow_security_keys`) | bool | `true` |  | in effect | When off, people cannot add new security keys (the authenticator app is always how an account first gets its second factor). Keys people already have keep working. |
| **Console IP allow-list** (`ip_allowlist`) | cidrs | empty | up to 50 entries | in effect | When not empty, only these addresses and networks can reach the console and its API (agents are not affected). Your own current address must be in the list, or the change is refused. If you lock yourself out anyway, start the server with LIBREPATCH_IGNORE_IP_ALLOWLIST=true, fix the list, and restart without it. |
| **Longest API token lifetime** (`api_token_max_days`) | int | `365` | 1 to 365 days | in effect | New API tokens cannot be valid for longer than this. Existing tokens keep their expiry. |
| **Show a notice on the sign-in page** (`login_banner_enabled`) | bool | `false` |  | in effect | Shows the text below before sign-in, for example a consent or authorized-use notice. |
| **Notice text** (`login_banner`) | text | empty | up to 2000 characters | in effect | Plain text, up to 2000 characters. Visible to anyone who can reach the sign-in page, so do not put anything private in it. |
| **Require people to accept the notice** (`login_banner_require_ack`) | bool | `false` |  | in effect | People must tick a box saying they accept the notice before the sign-in form appears. |

## Notifications

Permission: `settings:notifications`. E-mail delivery, quiet hours and which events notify whom. Webhook endpoints are set up under Integrations; each rule can send to them.

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Send e-mail** (`email_enabled`) | bool | `false` |  | in effect | Turn on to send notifications and scheduled reports by e-mail. Nothing is sent until the mail server below works (use Send test). |
| **Mail server** (`smtp_host`) | string | empty | up to 253 characters | in effect | Host name of your SMTP relay. |
| **Port** (`smtp_port`) | int | `587` | 1 to 65535 | in effect | Usually 587 (STARTTLS), 465 (TLS from the start) or 25. |
| **Connection security** (`smtp_security`) | enum | `starttls` | starttls, tls, none | in effect | The server's certificate is always verified. 'None' is only for a relay on a trusted internal network. |
| **User name** (`smtp_username`) | string | empty | up to 254 characters | in effect | Leave empty if the relay does not need a login. |
| **Password** (`smtp_password`) | secret | none | up to 512 characters | in effect | Stored encrypted and never shown again. Leave empty to keep the saved one. |
| **From address** (`from_address`) | string | empty | up to 254 characters | in effect | The sender of every message. |
| **Use quiet hours** (`quiet_hours_enabled`) | bool | `false` |  | in effect | Messages that arrive during quiet hours are held and sent when they end (rules can opt out). |
| **Quiet hours begin** (`quiet_start`) | time | `22:00` |  | in effect | Local time in the time zone below. |
| **Quiet hours end** (`quiet_end`) | time | `07:00` |  | in effect | Local time in the time zone below. May be earlier than the start (overnight). |
| **Quiet hours time zone** (`quiet_time_zone`) | timezone | `UTC` |  | in effect | Time zone of the quiet hours. |
| **Event rules** (`rules`) | list | 10 built-in item(s) |  | in effect | One rule per event. Recipients are the people who get the e-mail; the threshold depends on the event. |

**Each item of “Event rules”:**

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Event** (`event`) | enum | `failed_install` | failed_install, update_held, software_approval_needed, device_offline, agent_out_of_date, restart_pending_long, low_disk, bitlocker_off, os_end_of_support, exploited_vulnerability | in effect | What happened. |
| **Notify** (`enabled`) | bool | `false` |  | in effect | Turn the rule on. |
| **By e-mail** (`email`) | bool | `true` |  | in effect | Send an e-mail to the recipients. |
| **To webhooks** (`webhook`) | bool | `true` |  | in effect | Call every enabled webhook that listens for this event. |
| **Recipients** (`recipients`) | emails | empty | up to 20 entries | in effect | E-mail addresses. Required when the rule sends e-mail. |
| **Threshold** (`threshold`) | int | `0` | 0 to 720 | in effect | Device offline: hours without a report. Agent out of date: days after a release before devices count as late. Restart pending too long: days without a restart. Low disk: gigabytes free on the system drive. Operating system end of support: days before the end to warn (0 warns only once support has ended). Other events ignore it. |
| **Hold during quiet hours** (`quiet_hours`) | bool | `true` |  | in effect | Wait for the end of quiet hours instead of sending at once. |

## Update defaults

Permission: `settings:updates`. Starting values for new update rings and auto-approval rules, so each one does not have to be filled in from scratch. Existing rings and rules are not changed. The update source and driver switch are on the Update rings and rules page.

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Restart policy for new rings** (`ring_restart`) | enum | `outside_active_hours` | never, outside_active_hours, deadline | starting value | What a new ring does about restarts after installing. |
| **Active hours begin** (`active_start`) | time | `08:00` |  | starting value | Devices are not restarted between the start and the end of the active hours. |
| **Active hours end** (`active_end`) | time | `17:00` |  | starting value | Local time on the device. |
| **Restart deadline** (`restart_deadline_hours`) | int | `24` | 1 to 168 hours | starting value | For 'by a deadline': restart at the latest this long after installing. |
| **Warning before a restart** (`restart_notify_minutes`) | int | `15` | 1 to 1440 minutes | starting value | How long the countdown shown to signed-in users lasts. |
| **New rings use a maintenance window** (`window_enabled`) | bool | `false` |  | starting value | Installs only start inside the window. |
| **Window days** (`window_days`) | multi | `saturday, sunday` | monday, tuesday, wednesday, thursday, friday, saturday, sunday | starting value | Days the window is open. |
| **Window opens** (`window_start`) | time | `22:00` |  | starting value | Local time on the device. |
| **Window closes** (`window_end`) | time | `05:00` |  | starting value | May be earlier than the opening time (overnight). |
| **New rules also approve drivers** (`rule_include_drivers`) | bool | `false` |  | starting value | Drivers are riskier to install unattended, so the default is off. |
| **New rules wait after release** (`rule_delay_days`) | int | `7` | 0 to 365 days | starting value | Days an update must have been out before a rule approves it. |
| **Auto-approval rule templates** (`rule_templates`) | list | 2 built-in item(s) | up to 20 entries | starting value | Named starting points offered when you add a rule. A template does nothing by itself. |

**Each item of “Auto-approval rule templates”:**

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Id** (`id`) | string | empty | up to 64 characters | starting value | Assigned automatically. |
| **Name** (`name`) | string | `New template` | up to 100 characters | starting value | Shown when choosing a template. |
| **Classifications** (`classifications`) | multi | empty | Security Updates, Critical Updates, Definition Updates, Drivers, Feature Packs, Service Packs, Update Rollups, Updates, Upgrades, Tools | starting value | Empty means any. |
| **Severities** (`severities`) | multi | empty | Critical, Important, Moderate, Low, Unrated | starting value | Empty means any. |
| **Also approve drivers** (`include_drivers`) | bool | `false` |  | starting value | Whether the rule approves driver updates. |
| **Wait after release** (`delay_days`) | int | `7` | 0 to 365 days | starting value | Days after release before the rule approves. |

## Device defaults

Permission: `settings:devices`. When a device counts as offline or stale, whether queued file deletions count as a pending restart, how devices are named, extra fields you want to record, and which columns the device list starts with.

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Offline after** (`offline_hours`) | int | `24` | 1 to 720 hours | in effect | A device that has not reported for this long is listed as needing attention on the dashboard. |
| **Queued file deletions count as a pending restart** (`queued_deletes_need_restart`) | bool | `false` |  | in effect | Installers and updaters (Edge, Firefox, Office, antivirus) queue leftover files for deletion at the next restart, and queue new ones again within hours, so counting them makes PCs show "restart pending" several times a day. Off (recommended): they are listed on the device page but do not mark it as needing a restart, change compliance or trigger a restart. Takes effect as each device next reports, within about 30 minutes. Renames and replacements queued for the next restart always count. |
| **Delete revoked devices after** (`stale_cleanup_days`) | int | `0` | 0 to 3650 days | in effect | Revoked or retired devices not seen for this long are deleted, with everything stored about them (the audit log keeps the record). 0 keeps them forever. Active devices are never deleted by this. |
| **Expected device name pattern** (`naming_pattern`) | regex | empty | up to 200 characters | in effect | A regular expression. Devices whose name does not match are flagged in the device list. Empty turns the check off. |
| **Custom device fields** (`custom_fields`) | list | empty | up to 20 entries | in effect | Extra information to record about each device, such as an asset tag or owner. Values are edited on the device page and shown in the device list. |
| **Device list columns** (`default_columns`) | multi | `hostname, status, connection, os, user, seen, agent` | hostname, status, connection, os, model, user, software, seen, agent, restart | in effect | The columns the device list shows for people who have not arranged their own. |

**Each item of “Custom device fields”:**

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Id** (`id`) | string | empty | up to 64 characters | in effect | Assigned automatically. |
| **Key** (`key`) | string | empty | up to 30 characters | in effect | Lower-case letters, digits and underscores, starting with a letter. Cannot be changed later without losing the values. |
| **Label** (`label`) | string | empty | up to 60 characters | in effect | Shown to people. |
| **Type** (`type`) | enum | `text` | text, select, date | in effect | What kind of value it holds. |
| **Choices** (`options`) | tags | empty | up to 50 entries | in effect | For a choice field: the allowed values. |
| **Show in the device list** (`show_in_list`) | bool | `true` |  | in effect | Adds a column to the device list. |

## Scheduled reports

Permission: `settings:reports`. Reports e-mailed on a schedule as PDF or CSV. Needs working e-mail under Notifications. The header carries your organization and product names from Branding.

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Header line** (`header_note`) | string | empty | up to 200 characters | in effect | An extra line under the report title, for example a classification. Empty adds nothing. |
| **Schedules** (`schedules`) | list | empty | up to 20 entries | in effect | Each schedule sends one report to its recipients. Times are in the server's configured time zone below. |
| **Schedule time zone** (`time_zone`) | timezone | `UTC` |  | in effect | The time zone schedule times are read in. |

**Each item of “Schedules”:**

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Id** (`id`) | string | empty | up to 64 characters | in effect | Assigned automatically. |
| **Name** (`name`) | string | `Weekly compliance` | up to 100 characters | in effect | Shown in the e-mail subject. |
| **Enabled** (`enabled`) | bool | `true` |  | in effect | Paused schedules send nothing. |
| **Report** (`report`) | enum | `compliance` | compliance, missing_updates, inventory | in effect | What to send. |
| **Format** (`format`) | enum | `pdf` | pdf, csv | in effect | PDF to read, CSV to analyse. |
| **Repeat** (`frequency`) | enum | `weekly` | daily, weekly, monthly | in effect | How often. |
| **Day of the week** (`weekday`) | enum | `monday` | monday, tuesday, wednesday, thursday, friday, saturday, sunday | in effect | For weekly schedules. |
| **Day of the month** (`day_of_month`) | int | `1` | 1 to 28 | in effect | For monthly schedules (1 to 28, so every month has it). |
| **Time** (`time`) | time | `07:00` |  | in effect | When to send. |
| **Recipients** (`recipients`) | emails | empty | up to 20 entries | in effect | At least one address. |

## Data and retention

Permission: `settings:data`. How long history is kept. The audit log is append-only and hash-chained, so the server never prunes it; export old entries from the Audit log page if you need to archive them.

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Keep finished jobs for** (`job_history_days`) | int | `365` | 0 to 3650 days | in effect | Finished, failed and cancelled jobs older than this are deleted. 0 keeps them forever. Jobs still in progress and the audit log are never touched. |
| **Keep software change history for** (`software_history_days`) | int | `730` | 0 to 3650 days | in effect | The record of programs added, removed or updated on each device (the History tab). Older entries are deleted. 0 keeps them forever. The software currently installed is never touched. |
| **Keep compliance history for** (`compliance_history_days`) | int | `400` | 30 to 1095 days | in effect | How far back the dashboard's compliance chart can go. Older daily snapshots are deleted. |
| **Keep the notification log for** (`notification_log_days`) | int | `90` | 7 to 730 days | in effect | Sent and failed e-mails and webhook deliveries, with the error if there was one. |

## Integrations

Permission: `settings:integrations`. Outgoing webhooks and the reference for what they send. API tokens are created on each person's Account page (administrators can see and revoke all of them under Users and roles).

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Webhooks** (`webhooks`) | list | empty | up to 20 entries | in effect | Each webhook receives a JSON POST for the events it listens to, signed with HMAC-SHA256 in the X-LibrePatch-Signature header so the receiver can check where it came from. |

**Each item of “Webhooks”:**

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Id** (`id`) | string | empty | up to 64 characters | in effect | Assigned automatically. |
| **Name** (`name`) | string | `New webhook` | up to 100 characters | in effect | Shown in the log. |
| **Enabled** (`enabled`) | bool | `true` |  | in effect | Paused webhooks receive nothing. |
| **URL** (`url`) | url | empty | up to 500 characters | in effect | Where to POST. Use https; plain http is only for receivers on a trusted internal network. |
| **Signing secret** (`secret`) | secret | none | up to 200 characters | in effect | Used to sign each delivery. Stored encrypted and never shown again; leave empty to keep the saved one. |
| **Remove the saved secret** (`clear_secret`) | bool | `false` |  | in effect | Deliveries are then sent unsigned. |
| **Events** (`events`) | multi | `failed_install, update_held` | failed_install, update_held, software_approval_needed, device_offline, agent_out_of_date, restart_pending_long, low_disk, bitlocker_off, os_end_of_support, exploited_vulnerability | in effect | Which events to send. Rules under Notifications decide whether an event is sent at all. |

## Vulnerability data

Permission: `settings:integrations`. Where the server gets the public lists of known vulnerabilities to match against what is installed on your devices. Nothing about your devices is sent: the server only downloads the lists and does the matching itself.

| Setting | Type | Default | Limits | Effect | What it does |
|---|---|---|---|---|---|
| **Look up known vulnerabilities** (`enabled`) | bool | `false` |  | in effect | Turns on the daily download of the CISA list of exploited vulnerabilities and, for the programs and Windows versions your devices have, of the NIST National Vulnerability Database. The Vulnerabilities page works with whatever has been downloaded. |
| **CISA exploited-vulnerabilities list** (`kev_url`) | url | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | up to 500 characters | in effect | Change this only to download from a mirror of your own (for example when the server cannot reach the internet directly). |
| **NIST vulnerability database** (`nvd_url`) | url | `https://services.nvd.nist.gov/rest/json/cves/2.0` | up to 500 characters | in effect | The address of the NVD CVE API, version 2.0. Change this only to use a mirror that answers the same way. |
| **NVD API key** (`nvd_api_key`) | secret | none | up to 200 characters | in effect | Optional. Without a key the NVD allows 5 requests per 30 seconds, so the first download takes a few minutes; a free key (requested from NIST) raises that tenfold. Stored encrypted and never shown again. |

## Pages that are not schema-driven

* **General** (per-user installs policy), permission `settings:write` to change, `catalog:read` to see: the default for how deployments treat copies of an app that users installed for themselves.
* **Branding**, permission `branding:write`: organization and product name, colors, sign-in texts, support contact, report footer, images. Theme choices live under Appearance.
* **About**, permission `settings:write`: version, build, database and license state, and the support bundle (a zip with configuration, settings, counts and the latest audit and notification entries; never secrets, keys, tokens, certificates or device data).

## Not done yet (honest list)

* The audit log is never pruned: it is append-only and hash-chained, and verification starts at the first entry. Retention for it needs a checkpoint design.
* Scheduled report PDFs use a monospaced table layout (the header carries the report logo, names and brand color).
* Custom device fields are text, choice and date; numbers and multi-select are not supported, and group filters treat all of them as text.
* "Language" sets number and date formatting only; the console's text is English.
* Maintenance windows and restart policy defaults pre-fill new update rings; there is no organization-wide window that overrides rings.
