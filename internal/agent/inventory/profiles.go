package inventory

import (
	"sort"
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// Profile is one user profile on the device.
type Profile struct {
	SID       string
	Username  string
	Domain    string
	Path      string
	LastLogon int64 // unix seconds, 0 = unknown
	Loaded    bool  // hive loaded under HKU: a session, or any program or service still running as the user
	SignedIn  bool  // the user has an interactive session (active or disconnected)
	IsAdmin   bool
}

// Lookup resolves a SID to its account and local-admin membership. Platforms
// implement it with LookupAccountSid / NetUserGetLocalGroups.
type Lookup func(sid string) (username, domain string, isAdmin bool)

// IsUserSID reports whether sid is a real user account SID: local or domain
// (S-1-5-21-...) or Azure AD (S-1-12-1-...), not a service/system profile.
func IsUserSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
}

// ParseProfileList reads HKLM\...\ProfileList. loaded reports whether the
// user's hive is currently loaded under HKU.
func ParseProfileList(hklm RegNode, loaded func(sid string) bool, lookup Lookup) ([]Profile, error) {
	pl, err := hklm.Open(profileListKey)
	if err != nil {
		return nil, err
	}
	defer pl.Close()
	sids, err := pl.SubKeyNames()
	if err != nil {
		return nil, err
	}
	var out []Profile
	for _, sid := range sids {
		if !IsUserSID(sid) || len(sid) > 128 {
			continue
		}
		k, err := pl.Open(sid)
		if err != nil {
			continue
		}
		path, _ := k.String("ProfileImagePath")
		lo, _ := k.DWord("LocalProfileLoadTimeLow")
		hi, _ := k.DWord("LocalProfileLoadTimeHigh")
		k.Close()
		if strings.TrimSpace(path) == "" {
			continue
		}
		p := Profile{SID: sid, Path: path, Loaded: loaded != nil && loaded(sid), LastLogon: filetimeToUnix(lo, hi)}
		if lookup != nil {
			p.Username, p.Domain, p.IsAdmin = lookup(sid)
		}
		if p.Username == "" {
			p.Username = baseName(path)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SID < out[j].SID })
	return out, nil
}

func baseName(path string) string {
	path = strings.TrimRight(path, `\/`)
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// filetimeToUnix converts a Windows FILETIME (100 ns since 1601) to unix seconds.
func filetimeToUnix(lo, hi uint32) int64 {
	ft := uint64(hi)<<32 | uint64(lo)
	if ft == 0 {
		return 0
	}
	const epochDiff = 11644473600
	secs := int64(ft/10_000_000) - epochDiff // #nosec G115 -- FILETIME/1e7 fits int64
	if secs < 0 {
		return 0
	}
	return secs
}

func usersToProto(ps []Profile) []*agentv1.DeviceUser {
	out := make([]*agentv1.DeviceUser, 0, len(ps))
	for _, p := range ps {
		out = append(out, &agentv1.DeviceUser{Sid: p.SID, Username: clip(p.Username, 256), Domain: clip(p.Domain, 256),
			ProfilePath: clip(p.Path, maxPath), LastLogon: p.LastLogon, Loaded: p.Loaded, SignedIn: p.SignedIn, IsAdmin: p.IsAdmin})
	}
	return out
}
