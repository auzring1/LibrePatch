// Package rebootstate decides whether a Windows PC really needs a restart.
//
// The markers differ a lot in how much they mean. Windows servicing and Windows Update say a restart is
// needed to finish an update, and a pending computer rename does too. The Session Manager's
// PendingFileRenameOperations is different: installers and updaters (Edge, Firefox, Office, antivirus, drivers) use it
// for housekeeping, mostly "delete this leftover file at the next boot", and they queue new entries again within
// hours. Counting every entry made PCs show "restart pending" several times a day. So a queued deletion is reported on
// its own and does not count as a pending restart unless the administrator asks for it (the server decides, see the
// "Count queued file deletions" setting); a queued rename or replace still does.
package rebootstate

import "strings"

// Reasons a restart is needed (the values travel to the server and appear in the console).
const (
	ReasonServicing     = "component_based_servicing"
	ReasonWindowsUpdate = "windows_update"
	ReasonFileRename    = "pending_file_rename"
	ReasonComputerName  = "computer_rename"
)

// maxSamples bounds how many queued deletions are listed for the console.
const maxSamples = 10

// State is what the PC reports about restarts.
type State struct {
	// Reasons lists the markers that mean a restart is needed. No reason, no restart pending.
	Reasons []string
	// DeleteCount is how many files are queued for deletion at the next boot. It never sets Reasons.
	DeleteCount int
	// DeleteSamples are the first few of them, for display.
	DeleteSamples []string
}

// Pending reports whether Windows itself needs a restart (queued deletions excluded).
func (s State) Pending() bool { return len(s.Reasons) > 0 }

// FileOps is the content of PendingFileRenameOperations, split by what Windows will do.
type FileOps struct {
	Deletes []string // files to delete at boot
	Renames []string // files to move or replace at boot ("source -> destination")
}

// ParsePendingFileRenames reads the value of PendingFileRenameOperations: a list of pairs, a source and a
// destination, where an empty destination means "delete the source". Paths start with the native prefix \??\, and a
// source may carry a flag prefix such as "*1". A destination starting with "!" replaces an existing file. A lone
// source at the end (an odd list) is treated as a deletion.
func ParsePendingFileRenames(v []string) FileOps {
	var ops FileOps
	for i := 0; i < len(v); i += 2 {
		src := cleanPath(v[i])
		dst := ""
		if i+1 < len(v) {
			dst = cleanPath(v[i+1])
		}
		switch {
		case src == "":
			// A pair without a source does nothing.
		case dst == "":
			ops.Deletes = append(ops.Deletes, src)
		default:
			ops.Renames = append(ops.Renames, src+" -> "+dst)
		}
	}
	return ops
}

// cleanPath removes the flag prefix ("*1"), the replace marker ("!") and the native prefix (\??\) from one entry.
func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "*") {
		i := 1
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		s = s[i:]
	}
	s = strings.TrimPrefix(s, "!")
	return strings.TrimPrefix(s, `\??\`)
}

// Classify turns the parsed file operations into the part of a State they contribute.
func (o FileOps) Classify(s *State) {
	if len(o.Renames) > 0 {
		s.Reasons = append(s.Reasons, ReasonFileRename)
	}
	s.DeleteCount = len(o.Deletes)
	n := len(o.Deletes)
	if n > maxSamples {
		n = maxSamples
	}
	s.DeleteSamples = append([]string(nil), o.Deletes[:n]...)
}
