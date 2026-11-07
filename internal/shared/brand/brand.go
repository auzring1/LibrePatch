// Package brand is the single source of truth for the product name.
//
// Nothing else in the Go code may spell the product name in a string: use these constants. The web
// console receives the same values at build time (web/src/brand.generated.ts, written by `go generate`,
// checked by `make check-generated`), and the MSI build receives them as WiX variables
// (installer/windows/build.ps1 and scripts/build-msi.sh call `go run ./internal/shared/brand/gen -wix`).
// The test in this package fails if the previous name or a stray copy of the current one reaches a
// user-visible string anywhere in the repository.
package brand

//go:generate go run ./gen -ts ../../../web/src/brand.generated.ts

const (
	// Name is the product name shown to people.
	Name = "LibrePatch"
	// AgentName is the name of the endpoint agent as shown on a machine (service display name, MSI, file properties).
	AgentName = Name + " Agent"
	// Company is the vendor (the manufacturer in the MSI and in the file properties, the copyright holder).
	Company = "The LibrePatch contributors"
	// Slug is the lower-case stem of command and file names (librepatch-server, librepatch-agent.exe, ...).
	Slug = "librepatch"
)

// Names of what the agent leaves on a machine. They are derived from Name so that they cannot drift apart.
const (
	// ServiceName is the Windows service.
	ServiceName = Name + "Agent"
	// FolderName is the folder under Program Files (the agent's program) and under ProgramData (its data).
	FolderName = Name
	// StageFolderName is the ProgramData folder where installers are staged for per-user installs.
	StageFolderName = Name + "Stage"
	// SetupFolderName is the folder where the MSI stages the agent executable before it runs the installer step.
	SetupFolderName = Name + "Setup"
	// RollbackTask is the scheduled task that restores the previous version after a failed self-update.
	RollbackTask = `\` + Name + `\rollback-check`
	// KeyPrefix prefixes the names of the device keys in the Windows key store.
	KeyPrefix = Name + "-Agent-Device-"
)

// File and protocol names derived from Slug. The agent's executable has the same name wherever it is
// (downloaded, installed in its slot directories, started by the service).
const (
	// AgentExe is the agent's file name.
	AgentExe = Slug + "-agent.exe"
	// VersionBanner is what `<agent> version` prints before the version number. An agent reads it from a freshly
	// staged binary during self-update, so it is part of the update protocol.
	VersionBanner = Slug + "-agent"
	// ManifestProduct is the "product" value of a signed agent release manifest.
	ManifestProduct = Slug + "-agent"
)
