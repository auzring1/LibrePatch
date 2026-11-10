package reportbuilder

// Category groups the ready-made reports in the console.
const (
	CatSoftware = "software"
	CatHardware = "hardware"
	CatPatching = "patching"
	CatDevices  = "devices"
)

// Builtin is a ready-made report. People cannot change it, but "Customize" copies it into a custom report.
type Builtin struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Spec        Spec   `json:"spec"`
}

func f(col, op, val string) Filter { return Filter{Column: col, Op: op, Value: val} }

var builtins = []Builtin{
	{ID: "software-installed", Category: CatSoftware, Name: "Installed software",
		Description: "Every program on every device, with version and publisher. Windows components are left out.",
		Spec:        Spec{Dataset: "software", Columns: []string{"hostname", "site", "name", "version", "publisher", "scope", "install_date"}, Filters: []Filter{f("system_component", "is", "false")}, Sort: &Sort{Column: "hostname"}}},
	{ID: "software-programs", Category: CatSoftware, Name: "Programs by number of devices",
		Description: "Each program once, with how many devices have it and how many versions are in use.",
		Spec:        Spec{Dataset: "programs", Columns: []string{"name", "publisher", "devices", "versions", "newest"}, Sort: &Sort{Column: "devices", Desc: true}}},
	{ID: "software-versions", Category: CatSoftware, Name: "Program versions in use",
		Description: "Each program and version with the number of devices running it. Shows where old versions are left.",
		Spec:        Spec{Dataset: "versions", Columns: []string{"name", "version", "publisher", "devices"}, Sort: &Sort{Column: "name"}}},
	{ID: "software-user-installs", Category: CatSoftware, Name: "Programs installed by users",
		Description: "Programs installed for one person only, outside the managed machine-wide installs.",
		Spec:        Spec{Dataset: "software", Columns: []string{"hostname", "user", "name", "version", "publisher", "install_date"}, Filters: []Filter{f("scope", "eq", "user"), f("system_component", "is", "false")}, Sort: &Sort{Column: "name"}}},

	{ID: "hardware-inventory", Category: CatHardware, Name: "Hardware inventory",
		Description: "Manufacturer, model, serial number, processor and memory of every device.",
		Spec:        Spec{Dataset: "devices", Columns: []string{"hostname", "site", "manufacturer", "model", "serial", "chassis", "cpu", "cores", "ram_gb"}, Sort: &Sort{Column: "hostname"}}},
	{ID: "hardware-os", Category: CatHardware, Name: "Operating systems",
		Description: "Windows edition, version and build of every device.",
		Spec:        Spec{Dataset: "devices", Columns: []string{"hostname", "site", "os", "os_version", "os_build", "arch"}, Sort: &Sort{Column: "os"}}},
	{ID: "hardware-disks", Category: CatHardware, Name: "Disks and BitLocker",
		Description: "Every drive with size, free space and BitLocker state.",
		Spec:        Spec{Dataset: "disks", Columns: []string{"hostname", "site", "drive", "filesystem", "size_gb", "free_gb", "free_pct", "bitlocker"}, Sort: &Sort{Column: "hostname"}}},
	{ID: "hardware-low-disk", Category: CatHardware, Name: "Low disk space",
		Description: "Drives with less than 15% free, the fullest first.",
		Spec:        Spec{Dataset: "disks", Columns: []string{"hostname", "site", "drive", "size_gb", "free_gb", "free_pct"}, Filters: []Filter{f("free_pct", "lt", "15")}, Sort: &Sort{Column: "free_pct"}}},
	{ID: "hardware-unencrypted", Category: CatHardware, Name: "Drives without BitLocker",
		Description: "Drives that BitLocker does not protect.",
		Spec:        Spec{Dataset: "disks", Columns: []string{"hostname", "site", "drive", "size_gb", "bitlocker"}, Filters: []Filter{f("bitlocker", "eq", "unprotected")}, Sort: &Sort{Column: "hostname"}}},

	{ID: "patching-compliance", Category: CatPatching, Name: "Patch compliance",
		Description: "Every device with its patch state, missing and failed updates and last scan.",
		Spec:        Spec{Dataset: "patching", Columns: []string{"hostname", "site", "state", "approved_missing", "critical_missing", "failed", "restart", "last_scan", "os"}, Sort: &Sort{Column: "hostname"}}},
	{ID: "patching-attention", Category: CatPatching, Name: "Devices needing patches",
		Description: "Devices that are not compliant or have not scanned lately.",
		Spec:        Spec{Dataset: "patching", Columns: []string{"hostname", "site", "state", "approved_missing", "critical_missing", "failed", "last_scan"}, Filters: []Filter{f("state", "ne", "Compliant")}, Sort: &Sort{Column: "critical_missing", Desc: true}}},

	{ID: "devices-status", Category: CatDevices, Name: "Device status",
		Description: "Which devices are online, when they were last seen, their agent version and who is signed in.",
		Spec:        Spec{Dataset: "devices", Columns: []string{"hostname", "site", "online", "last_seen", "agent", "user", "uptime_days", "restart"}, Sort: &Sort{Column: "hostname"}}},
	{ID: "devices-not-seen", Category: CatDevices, Name: "Not seen for 30 days",
		Description: "Devices that have not contacted the server for a month. Candidates for retiring.",
		Spec:        Spec{Dataset: "devices", Columns: []string{"hostname", "site", "last_seen", "model", "serial", "user"}, Filters: []Filter{f("last_seen", "older_than_days", "30")}, Sort: &Sort{Column: "last_seen"}}},
	{ID: "devices-restart", Category: CatDevices, Name: "Waiting for a restart",
		Description: "Devices that need a restart to finish installing something.",
		Spec:        Spec{Dataset: "devices", Columns: []string{"hostname", "site", "user", "uptime_days", "last_seen"}, Filters: []Filter{f("restart", "is", "true")}, Sort: &Sort{Column: "uptime_days", Desc: true}}},
}

// Builtins lists the ready-made reports.
func Builtins() []Builtin { return builtins }

// BuiltinByID finds one ready-made report.
func BuiltinByID(id string) (*Builtin, bool) {
	for i := range builtins {
		if builtins[i].ID == id {
			return &builtins[i], true
		}
	}
	return nil, false
}

// IsBuiltin reports whether id names a ready-made report.
func IsBuiltin(id string) bool { _, ok := BuiltinByID(id); return ok }
