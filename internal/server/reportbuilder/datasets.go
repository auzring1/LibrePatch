// Package reportbuilder runs reports. A report is a Spec: which data to read (a dataset), which columns to show, which
// filters to apply and which devices to include (sites, a group). Every column and every comparison comes from the
// allow-lists in this file; the person's text only ever travels as a bound parameter, never inside the SQL string.
package reportbuilder

// Kind says how a column's values are compared, aligned and written.
type Kind string

const (
	KText   Kind = "text"
	KNumber Kind = "number"
	KBool   Kind = "bool"
	KTime   Kind = "time"
)

const gib = "1073741824.0"

// Column is one column a dataset can show or filter on.
type Column struct {
	ID    string
	Label string
	Kind  Kind
	Group string // the heading the column picker lists it under
	// Choices lists the values a text column can hold, when there are only a few (the console offers a pick list).
	Choices []string
	expr    string // SQL over the dataset's FROM; an allow-listed constant
	agg     bool   // an aggregate: filters on it go to HAVING
	width   int    // PDF width in characters
}

// Dataset is one kind of data a report can read.
type Dataset struct {
	ID          string
	Label       string
	Description string
	// NeedsWindowsUpdates marks data that only exists when the organization manages Windows updates.
	NeedsWindowsUpdates bool
	DefaultColumns      []string
	DefaultSort         string
	DefaultDesc         bool
	Columns             []Column
	from                string
	groupBy             string
	where               string // extra conditions that always apply
}

// safeInt turns a JSON text value into a number without ever failing on garbage.
func safeInt(e string) string {
	return "(CASE WHEN " + e + " ~ '^[0-9]+$' THEN (" + e + ")::bigint END)"
}

func gb(e string) string { return "round(" + e + "/" + gib + ", 1)" }

const devFrom = `devices d JOIN sites s ON s.id = d.site_id`

// The same restart rule as the patch compliance report (see ComplianceReport in db/queries/policies.sql).
const patchReboot = `(d.pending_reboot OR CASE WHEN d.wu_reboot_required AND d.wu_scanned_at IS NOT NULL AND d.last_seen_at IS NOT NULL AND d.uptime_s > 0
	THEN d.wu_scanned_at >= d.last_seen_at - make_interval(secs => d.uptime_s::float8) ELSE d.wu_reboot_required END)`

// A device is not compliant with an approved or critical update missing or a failed install; with none of those it is
// compliant only if it scanned within a week (dashboard.StaleAfter).
const patchState = `(CASE WHEN p.approved_missing > 0 OR p.critical_missing > 0 OR p.failed > 0 THEN 'Not compliant'
	WHEN d.wu_scanned_at IS NULL OR d.wu_scanned_at < now() - interval '7 days' THEN 'Not scanned lately' ELSE 'Compliant' END)`

var deviceColumns = []Column{
	{ID: "hostname", Label: "Device", Kind: KText, Group: "Device", expr: "d.hostname", width: 24},
	{ID: "site", Label: "Site", Kind: KText, Group: "Device", expr: "s.name", width: 16},
	{ID: "online", Label: "Online", Kind: KBool, Group: "Device", expr: "d.online", width: 6},
	{ID: "last_seen", Label: "Last seen", Kind: KTime, Group: "Device", expr: "d.last_seen_at", width: 16},
	{ID: "enrolled", Label: "Enrolled", Kind: KTime, Group: "Device", expr: "d.enrolled_at", width: 16},
	{ID: "user", Label: "Signed-in user", Kind: KText, Group: "Device", expr: "d.logged_on_user", width: 18},
	{ID: "ip", Label: "Last IP address", Kind: KText, Group: "Device", expr: "d.last_ip", width: 15},
	{ID: "agent", Label: "Agent version", Kind: KText, Group: "Device", expr: "d.agent_version", width: 10},
	{ID: "uptime_days", Label: "Uptime (days)", Kind: KNumber, Group: "Device", expr: "round(d.uptime_s / 86400.0, 1)", width: 8},
	{ID: "restart", Label: "Waiting for a restart", Kind: KBool, Group: "Device", expr: "d.pending_reboot", width: 8},
	{ID: "software_count", Label: "Programs installed", Kind: KNumber, Group: "Device", expr: "d.software_count", width: 8},
	{ID: "manufacturer", Label: "Manufacturer", Kind: KText, Group: "Hardware", expr: "d.manufacturer", width: 16},
	{ID: "model", Label: "Model", Kind: KText, Group: "Hardware", expr: "d.model", width: 22},
	{ID: "serial", Label: "Serial number", Kind: KText, Group: "Hardware", expr: "d.serial", width: 16},
	{ID: "chassis", Label: "Type", Kind: KText, Group: "Hardware", expr: "d.chassis", width: 10},
	{ID: "cpu", Label: "Processor", Kind: KText, Group: "Hardware", expr: "d.hardware->>'cpu_model'", width: 30},
	{ID: "cores", Label: "Logical cores", Kind: KNumber, Group: "Hardware", expr: safeInt("d.hardware->>'cpu_logical_cores'"), width: 6},
	{ID: "ram_gb", Label: "Memory (GB)", Kind: KNumber, Group: "Hardware", expr: gb("d.ram_bytes"), width: 8},
	{ID: "bios", Label: "BIOS version", Kind: KText, Group: "Hardware", expr: "d.hardware->>'bios_version'", width: 16},
	{ID: "domain", Label: "Domain", Kind: KText, Group: "Hardware", expr: "d.hardware->>'domain'", width: 16},
	{ID: "system_free_gb", Label: "System drive free (GB)", Kind: KNumber, Group: "Hardware", expr: gb("d.system_drive_free_bytes"), width: 8},
	{ID: "os", Label: "Operating system", Kind: KText, Group: "Operating system", expr: "d.os_caption", width: 26},
	{ID: "os_version", Label: "Windows version", Kind: KText, Group: "Operating system", expr: "d.hardware->>'os_display_version'", width: 8},
	{ID: "os_build", Label: "OS build", Kind: KText, Group: "Operating system", expr: "d.os_build", width: 12},
	{ID: "arch", Label: "Architecture", Kind: KText, Group: "Operating system", expr: "d.arch", width: 8},
}

var diskColumns = []Column{
	{ID: "hostname", Label: "Device", Kind: KText, Group: "Device", expr: "d.hostname", width: 24},
	{ID: "site", Label: "Site", Kind: KText, Group: "Device", expr: "s.name", width: 16},
	{ID: "model", Label: "Model", Kind: KText, Group: "Device", expr: "d.model", width: 22},
	{ID: "user", Label: "Signed-in user", Kind: KText, Group: "Device", expr: "d.logged_on_user", width: 18},
	{ID: "drive", Label: "Drive", Kind: KText, Group: "Disk", expr: "k->>'mount'", width: 8},
	{ID: "filesystem", Label: "File system", Kind: KText, Group: "Disk", expr: "k->>'filesystem'", width: 8},
	{ID: "size_gb", Label: "Size (GB)", Kind: KNumber, Group: "Disk", expr: gb(safeInt("k->>'size_bytes'")), width: 9},
	{ID: "free_gb", Label: "Free (GB)", Kind: KNumber, Group: "Disk", expr: gb(safeInt("k->>'free_bytes'")), width: 9},
	{ID: "free_pct", Label: "Free (%)", Kind: KNumber, Group: "Disk", expr: "round(100.0 * " + safeInt("k->>'free_bytes'") + " / NULLIF(" + safeInt("k->>'size_bytes'") + ", 0), 1)", width: 8},
	{ID: "bitlocker", Label: "BitLocker", Kind: KText, Group: "Disk", expr: "k->>'bitlocker'", width: 12,
		Choices: []string{"protected", "unprotected", "encrypting", "decrypting", "unknown", "unsupported"}},
}

var softwareColumns = []Column{
	{ID: "hostname", Label: "Device", Kind: KText, Group: "Device", expr: "d.hostname", width: 24},
	{ID: "site", Label: "Site", Kind: KText, Group: "Device", expr: "s.name", width: 16},
	{ID: "user", Label: "Signed-in user", Kind: KText, Group: "Device", expr: "d.logged_on_user", width: 18},
	{ID: "name", Label: "Program", Kind: KText, Group: "Program", expr: "si.name", width: 36},
	{ID: "version", Label: "Version", Kind: KText, Group: "Program", expr: "si.version", width: 16},
	{ID: "publisher", Label: "Publisher", Kind: KText, Group: "Program", expr: "si.publisher", width: 24},
	{ID: "scope", Label: "Installed for", Kind: KText, Group: "Program", expr: "si.scope", width: 8, Choices: []string{"machine", "user"}},
	{ID: "source", Label: "Found in", Kind: KText, Group: "Program", expr: "si.source", width: 8},
	{ID: "install_date", Label: "Install date", Kind: KText, Group: "Program", expr: "si.install_date", width: 12},
	{ID: "location", Label: "Install location", Kind: KText, Group: "Program", expr: "si.install_location", width: 30},
	{ID: "last_seen", Label: "Last seen", Kind: KTime, Group: "Program", expr: "si.last_seen_at", width: 16},
	{ID: "system_component", Label: "Windows component", Kind: KBool, Group: "Program", expr: "si.system_component", width: 8},
}

var titleColumns = []Column{
	{ID: "name", Label: "Program", Kind: KText, Group: "Program", expr: "st.display_name", width: 36},
	{ID: "publisher", Label: "Publisher", Kind: KText, Group: "Program", expr: "st.display_publisher", width: 24},
	{ID: "devices", Label: "Devices", Kind: KNumber, Group: "Counts", expr: "count(DISTINCT si.device_id)", agg: true, width: 8},
	{ID: "installs", Label: "Installs", Kind: KNumber, Group: "Counts", expr: "count(*)", agg: true, width: 8},
	{ID: "versions", Label: "Versions in use", Kind: KNumber, Group: "Counts", expr: "count(DISTINCT si.version)", agg: true, width: 8},
	{ID: "newest", Label: "Newest version", Kind: KText, Group: "Counts", expr: "(array_agg(si.version ORDER BY si.version_key DESC NULLS LAST))[1]", agg: true, width: 16},
}

var versionColumns = []Column{
	{ID: "name", Label: "Program", Kind: KText, Group: "Program", expr: "st.display_name", width: 36},
	{ID: "publisher", Label: "Publisher", Kind: KText, Group: "Program", expr: "st.display_publisher", width: 24},
	{ID: "version", Label: "Version", Kind: KText, Group: "Program", expr: "si.version", width: 18},
	{ID: "devices", Label: "Devices", Kind: KNumber, Group: "Counts", expr: "count(DISTINCT si.device_id)", agg: true, width: 8},
}

var patchColumns = []Column{
	{ID: "hostname", Label: "Device", Kind: KText, Group: "Device", expr: "d.hostname", width: 24},
	{ID: "site", Label: "Site", Kind: KText, Group: "Device", expr: "s.name", width: 16},
	{ID: "online", Label: "Online", Kind: KBool, Group: "Device", expr: "d.online", width: 6},
	{ID: "os", Label: "Operating system", Kind: KText, Group: "Device", expr: "d.os_caption", width: 26},
	{ID: "state", Label: "Patch state", Kind: KText, Group: "Patching", expr: patchState, width: 18, Choices: []string{"Compliant", "Not compliant", "Not scanned lately"}},
	{ID: "approved_missing", Label: "Approved missing", Kind: KNumber, Group: "Patching", expr: "p.approved_missing", width: 8},
	{ID: "critical_missing", Label: "Critical missing", Kind: KNumber, Group: "Patching", expr: "p.critical_missing", width: 8},
	{ID: "failed", Label: "Failed installs", Kind: KNumber, Group: "Patching", expr: "p.failed", width: 8},
	{ID: "restart", Label: "Restart needed", Kind: KBool, Group: "Patching", expr: patchReboot, width: 8},
	{ID: "last_scan", Label: "Last Windows Update scan", Kind: KTime, Group: "Patching", expr: "d.wu_scanned_at", width: 16},
}

var datasets = []Dataset{
	{
		ID: "devices", Label: "Devices", Description: "One row per device: hardware, operating system and status.",
		DefaultColumns: []string{"hostname", "site", "os", "manufacturer", "model", "serial", "last_seen"}, DefaultSort: "hostname",
		Columns: deviceColumns, from: devFrom,
	},
	{
		ID: "disks", Label: "Disks", Description: "One row per drive of every device: size, free space and BitLocker.",
		DefaultColumns: []string{"hostname", "site", "drive", "size_gb", "free_gb", "free_pct", "bitlocker"}, DefaultSort: "hostname",
		Columns: diskColumns,
		from: devFrom + ` CROSS JOIN LATERAL jsonb_array_elements(
			CASE WHEN jsonb_typeof(d.hardware->'disks') = 'array' THEN d.hardware->'disks' ELSE '[]'::jsonb END) k`,
	},
	{
		ID: "software", Label: "Installed software", Description: "One row per program on every device.",
		DefaultColumns: []string{"hostname", "name", "version", "publisher"}, DefaultSort: "hostname",
		Columns: softwareColumns,
		from:    devFrom + ` JOIN software_installs si ON si.device_id = d.id`,
	},
	{
		ID: "programs", Label: "Programs (count of devices)", Description: "One row per program: on how many devices it is installed and in how many versions.",
		DefaultColumns: []string{"name", "publisher", "devices", "versions", "newest"}, DefaultSort: "devices", DefaultDesc: true,
		Columns: titleColumns,
		from:    devFrom + ` JOIN software_installs si ON si.device_id = d.id JOIN software_titles st ON st.id = si.title_id`,
		groupBy: "st.id", where: "NOT si.system_component",
	},
	{
		ID: "versions", Label: "Program versions (count of devices)", Description: "One row per program and version: how many devices run it.",
		DefaultColumns: []string{"name", "version", "publisher", "devices"}, DefaultSort: "name",
		Columns: versionColumns,
		from:    devFrom + ` JOIN software_installs si ON si.device_id = d.id JOIN software_titles st ON st.id = si.title_id`,
		groupBy: "st.id, si.version", where: "NOT si.system_component",
	},
	{
		ID: "patching", Label: "Patch state", Description: "One row per device: missing and failed Windows updates, and when it last scanned.",
		NeedsWindowsUpdates: true,
		DefaultColumns:      []string{"hostname", "site", "state", "approved_missing", "critical_missing", "failed", "last_scan"}, DefaultSort: "hostname",
		Columns: patchColumns,
		from: devFrom + ` LEFT JOIN LATERAL (
			SELECT count(*) FILTER (WHERE a.decision = 'approved')::int AS approved_missing,
			       count(*) FILTER (WHERE u.severity = 'Critical' AND COALESCE(a.decision, '') <> 'declined')::int AS critical_missing,
			       count(*) FILTER (WHERE du.state = 'failed')::int AS failed
			FROM device_updates du
			LEFT JOIN wu_updates u ON u.org_id = d.org_id AND u.update_id = du.update_id
			LEFT JOIN wu_approvals a ON a.org_id = d.org_id AND a.update_id = du.update_id
			WHERE du.device_id = d.id AND du.state IN ('missing', 'downloaded', 'failed')) p ON true`,
	},
}

// Datasets lists the data a report can read.
func Datasets() []Dataset { return datasets }

// DatasetByID finds one dataset.
func DatasetByID(id string) (*Dataset, bool) {
	for i := range datasets {
		if datasets[i].ID == id {
			return &datasets[i], true
		}
	}
	return nil, false
}

// Column finds one column of the dataset.
func (d *Dataset) Column(id string) (*Column, bool) {
	for i := range d.Columns {
		if d.Columns[i].ID == id {
			return &d.Columns[i], true
		}
	}
	return nil, false
}

// Width is the column's width in the PDF, in characters.
func (c *Column) Width() int { return c.width }
