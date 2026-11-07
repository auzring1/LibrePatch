// Package installer holds the install-engine logic shared by server and agent:
// argument validation, per-type command builders, exit-code mapping and safe
// archive extraction. Everything here is pure Go so it is unit-tested on Linux.
package installer

import "fmt"

// Type is an installer technology. Names match catalog_installers.installer_type.
type Type string

const (
	MSI      Type = "msi"
	MSIX     Type = "msix"
	Inno     Type = "inno"
	NSIS     Type = "nsis"
	Burn     Type = "burn"
	EXE      Type = "exe"
	Portable Type = "portable"
	Zip      Type = "zip"
)

// Scope is machine-wide or per-user.
type Scope string

const (
	Machine Scope = "machine"
	User    Scope = "user"
)

// Outcome is the result class of an installer run.
type Outcome int

const (
	Success Outcome = iota + 1
	RebootRequired
	Retryable
	Failed
)

func (o Outcome) String() string {
	switch o {
	case Success:
		return "success"
	case RebootRequired:
		return "reboot_required"
	case Retryable:
		return "retryable"
	case Failed:
		return "failed"
	}
	return fmt.Sprintf("outcome(%d)", int(o))
}

// Valid reports whether t is a known type.
func (t Type) Valid() bool {
	switch t {
	case MSI, MSIX, Inno, NSIS, Burn, EXE, Portable, Zip:
		return true
	}
	return false
}

// RunsProcess reports whether installing this type starts a child process.
func (t Type) RunsProcess() bool {
	switch t {
	case MSI, Inno, NSIS, Burn, EXE:
		return true
	}
	return false
}
