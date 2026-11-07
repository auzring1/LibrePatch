package inventory

import "errors"

// ErrRegNotExist means a registry key (or value) does not exist.
var ErrRegNotExist = errors.New("registry key not found")

// ErrProfileGone means a user profile's folder no longer exists (the account was deleted but its registry entry stayed). The
// scan skips such a profile quietly: its software is gone with the folder.
var ErrProfileGone = errors.New("the profile folder no longer exists")

// RegNode is a read-only view of one registry key. The Windows implementation
// wraps golang.org/x/sys/windows/registry; tests use an in-memory tree.
type RegNode interface {
	// SubKeyNames lists the immediate subkeys.
	SubKeyNames() ([]string, error)
	// Open opens a subkey by relative path (backslash separated).
	Open(path string) (RegNode, error)
	// String reads a REG_SZ/REG_EXPAND_SZ value (expanded).
	String(name string) (string, bool)
	// DWord reads a REG_DWORD value.
	DWord(name string) (uint32, bool)
	Close()
}
