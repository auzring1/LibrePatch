package inventory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// MSIProduct is a Windows Installer product from MsiEnumProductsEx.
type MSIProduct struct {
	Code, Name, Version, Publisher, InstallDate, InstallLocation string
	Machine                                                      bool
	SID                                                          string // user-context products
}

// Platform is everything the scanner needs from the operating system.
type Platform interface {
	// HKLM opens the 64-bit view of HKEY_LOCAL_MACHINE.
	HKLM() (RegNode, error)
	// Profiles lists user profiles.
	Profiles() ([]Profile, error)
	// UserHive opens a profile's registry root: HKU\SID when loaded, otherwise
	// NTUSER.DAT loaded privately and read-only. The caller closes it.
	UserHive(p Profile) (RegNode, error)
	MSIProducts() ([]MSIProduct, error)
	ReadDir(path string) ([]DirEntry, error)
	// ProgramFiles is %ProgramFiles%.
	ProgramFiles() string
}

// Scanner implements Collector on top of a Platform.
type Scanner struct {
	P Platform
}

const (
	srcReg64    = agentv1.SoftwareSource_SOFTWARE_SOURCE_REG64
	srcReg32    = agentv1.SoftwareSource_SOFTWARE_SOURCE_REG32
	srcHKU      = agentv1.SoftwareSource_SOFTWARE_SOURCE_HKU
	srcHKU32    = agentv1.SoftwareSource_SOFTWARE_SOURCE_HKU32
	srcMSI      = agentv1.SoftwareSource_SOFTWARE_SOURCE_MSI
	srcAppx     = agentv1.SoftwareSource_SOFTWARE_SOURCE_APPX
	srcPortable = agentv1.SoftwareSource_SOFTWARE_SOURCE_PORTABLE
	scopeMach   = agentv1.SoftwareScope_SOFTWARE_SCOPE_MACHINE
	scopeUser   = agentv1.SoftwareScope_SOFTWARE_SCOPE_USER
)

// Collect scans machine-wide and per-user software and the user list.
func (s *Scanner) Collect(ctx context.Context) (*Scan, error) {
	res := &Scan{}
	hklm, err := s.P.HKLM()
	if err != nil {
		return nil, fmt.Errorf("open HKLM: %w", err)
	}
	defer hklm.Close()

	var items []*agentv1.SoftwareItem
	fail := func(g Group, err error) {
		res.Failed = append(res.Failed, g)
		res.Warnings = append(res.Warnings, fmt.Sprintf("%v: %v", g, err))
	}
	addARP := func(root RegNode, path string, src agentv1.SoftwareSource, scope agentv1.SoftwareScope, sid string) {
		k, err := root.Open(path)
		if errors.Is(err, ErrRegNotExist) {
			return // no such key = no apps of this kind
		}
		if err != nil {
			fail(Group{Source: src, Scope: scope, SID: sid}, err)
			return
		}
		defer k.Close()
		got, err := scanUninstall(k, src, scope, sid)
		if err != nil {
			fail(Group{Source: src, Scope: scope, SID: sid}, err)
			return
		}
		items = append(items, got...)
	}

	// Machine scope.
	addARP(hklm, hklmUninstall, srcReg64, scopeMach, "")
	addARP(hklm, hklmUninstall32, srcReg32, scopeMach, "")

	// Profiles and per-user software.
	profiles, perr := s.P.Profiles()
	if perr != nil {
		res.Failed = append(res.Failed, Group{Scope: scopeUser})
		res.Warnings = append(res.Warnings, "list profiles: "+perr.Error())
	}
	known := map[string]bool{}
	for _, p := range profiles {
		known[p.SID] = true
	}
	res.Users = usersToProto(profiles)
	for _, p := range profiles {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		hive, err := s.P.UserHive(p)
		if errors.Is(err, ErrProfileGone) {
			continue // the profile's folder was deleted: its software is gone too, and there is nothing to warn about
		}
		if err != nil {
			// A profile that cannot be read this pass must keep its old items.
			fail(Group{Scope: scopeUser, SID: p.SID}, err)
			continue
		}
		addARP(hive, userUninstall, srcHKU, scopeUser, p.SID)
		addARP(hive, userUninstall32, srcHKU32, scopeUser, p.SID)
		hive.Close()
		if got, err := scanPortable(s.P.ReadDir, p.Path+`\`+userPortableRel, scopeUser, p.SID); err == nil {
			items = append(items, got...)
		}
	}
	if pf := s.P.ProgramFiles(); pf != "" {
		if got, err := scanPortable(s.P.ReadDir, pf+`\`+machinePortableRel, scopeMach, ""); err == nil {
			items = append(items, got...)
		}
	}

	// AppX / MSIX.
	if got, err := scanAppx(hklm, known); err == nil {
		items = append(items, got...)
	} else if !errors.Is(err, ErrRegNotExist) {
		fail(Group{Source: srcAppx}, err)
	}

	// Windows Installer products that are not in any Uninstall key.
	have := map[string]bool{}
	for _, it := range items {
		if it.ProductCode != "" {
			have[productID(it.Key.Scope, it.Key.UserSid, it.ProductCode)] = true
		}
	}
	if prods, err := s.P.MSIProducts(); err != nil {
		fail(Group{Source: srcMSI}, err)
	} else {
		for _, p := range prods {
			scope, sid := scopeMach, ""
			if !p.Machine {
				scope, sid = scopeUser, p.SID
			}
			code := strings.ToUpper(p.Code)
			if have[productID(scope, sid, code)] || strings.TrimSpace(p.Name) == "" {
				continue
			}
			it := &agentv1.SoftwareItem{
				Key:  &agentv1.SoftwareItemKey{Source: srcMSI, Scope: scope, UserSid: sid, ItemKey: code},
				Name: p.Name, Version: p.Version, Publisher: p.Publisher, InstallDate: p.InstallDate,
				InstallLocation: p.InstallLocation, ProductCode: code,
			}
			sanitize(it)
			items = append(items, it)
		}
	}

	items = dropPortableDuplicates(items)
	items = dedupe(items)
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i].Key, items[j].Key
		switch {
		case a.Scope != b.Scope:
			return a.Scope < b.Scope
		case a.UserSid != b.UserSid:
			return a.UserSid < b.UserSid
		case a.Source != b.Source:
			return a.Source < b.Source
		}
		return a.ItemKey < b.ItemKey
	})
	if len(items) > MaxItems {
		items, res.Truncated = items[:MaxItems], true
	}
	res.Items = items
	return res, ctx.Err()
}

func productID(scope agentv1.SoftwareScope, sid, code string) string {
	return fmt.Sprintf("%d|%s|%s", scope, sid, code)
}

// dropPortableDuplicates removes a portable package directory when winget also
// registered it in an Uninstall key (same scope, same user, same key name).
func dropPortableDuplicates(items []*agentv1.SoftwareItem) []*agentv1.SoftwareItem {
	reg := map[string]bool{}
	for _, it := range items {
		if it.Key.Source != srcPortable {
			reg[fmt.Sprintf("%d|%s|%s", it.Key.Scope, it.Key.UserSid, it.Key.ItemKey)] = true
		}
	}
	out := items[:0]
	for _, it := range items {
		if it.Key.Source == srcPortable && reg[fmt.Sprintf("%d|%s|%s", it.Key.Scope, it.Key.UserSid, it.Key.ItemKey)] {
			continue
		}
		out = append(out, it)
	}
	return out
}

// dedupe keeps the first item per full key (keys must be unique per device).
func dedupe(items []*agentv1.SoftwareItem) []*agentv1.SoftwareItem {
	seen := make(map[string]bool, len(items))
	out := items[:0]
	for _, it := range items {
		k := string(ItemKeyBytes(it.Key))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, it)
	}
	return out
}
