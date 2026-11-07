package inventory

import (
	"errors"
	"strings"
)

// fakeNode is an in-memory registry key.
type fakeNode struct {
	subs   map[string]*fakeNode
	strs   map[string]string
	dwords map[string]uint32
}

func node() *fakeNode {
	return &fakeNode{subs: map[string]*fakeNode{}, strs: map[string]string{}, dwords: map[string]uint32{}}
}

// at returns (creating) the node at a backslash path.
func (n *fakeNode) at(path string) *fakeNode {
	cur := n
	for _, p := range strings.Split(path, `\`) {
		if p == "" {
			continue
		}
		next, ok := cur.subs[p]
		if !ok {
			next = node()
			cur.subs[p] = next
		}
		cur = next
	}
	return cur
}

func (n *fakeNode) set(name, val string) *fakeNode { n.strs[name] = val; return n }
func (n *fakeNode) dw(name string, v uint32) *fakeNode {
	n.dwords[name] = v
	return n
}

func (n *fakeNode) SubKeyNames() ([]string, error) {
	var out []string
	for k := range n.subs {
		out = append(out, k)
	}
	return out, nil
}

func (n *fakeNode) Open(path string) (RegNode, error) {
	cur := n
	for _, p := range strings.Split(path, `\`) {
		next, ok := cur.subs[p]
		if !ok {
			return nil, ErrRegNotExist
		}
		cur = next
	}
	return cur, nil
}

func (n *fakeNode) String(name string) (string, bool) { v, ok := n.strs[name]; return v, ok }
func (n *fakeNode) DWord(name string) (uint32, bool)  { v, ok := n.dwords[name]; return v, ok }
func (n *fakeNode) Close()                            {}

// addApp adds an Uninstall entry.
func addApp(root *fakeNode, uninstallPath, key, name, version string) *fakeNode {
	k := root.at(uninstallPath + `\` + key)
	k.set("DisplayName", name)
	if version != "" {
		k.set("DisplayVersion", version)
	}
	return k
}

// fakePlatform implements Platform from in-memory data.
type fakePlatform struct {
	hklm     *fakeNode
	hives    map[string]*fakeNode // SID -> hive root
	hiveErr  map[string]error
	profiles []Profile
	profErr  error
	msi      []MSIProduct
	msiErr   error
	dirs     map[string][]DirEntry
	pf       string
}

func newFakePlatform() *fakePlatform {
	return &fakePlatform{hklm: node(), hives: map[string]*fakeNode{}, hiveErr: map[string]error{}, dirs: map[string][]DirEntry{}, pf: `C:\Program Files`}
}

func (f *fakePlatform) HKLM() (RegNode, error)             { return f.hklm, nil }
func (f *fakePlatform) Profiles() ([]Profile, error)       { return f.profiles, f.profErr }
func (f *fakePlatform) MSIProducts() ([]MSIProduct, error) { return f.msi, f.msiErr }
func (f *fakePlatform) ProgramFiles() string               { return f.pf }
func (f *fakePlatform) UserHive(p Profile) (RegNode, error) {
	if err := f.hiveErr[p.SID]; err != nil {
		return nil, err
	}
	h, ok := f.hives[p.SID]
	if !ok {
		return nil, errors.New("no hive")
	}
	return h, nil
}
func (f *fakePlatform) ReadDir(path string) ([]DirEntry, error) {
	d, ok := f.dirs[path]
	if !ok {
		return nil, ErrRegNotExist
	}
	return d, nil
}

const (
	sidAlice = "S-1-5-21-111-222-333-1001"
	sidBob   = "S-1-5-21-111-222-333-1002"
)
