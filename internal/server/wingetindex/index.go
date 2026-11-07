// Package wingetindex keeps a local copy of the winget community source index and matches installed programs to it.
//
// The index is the file the winget client itself uses to recognise installed programs and to know the newest version of
// each package (https://cdn.winget.microsoft.com/cache/source2.msix: a signed MSIX, which is a zip file holding a SQLite
// database). It lists about 15,000 packages with their newest version, the Windows product codes and normalized names
// that identify them, and nothing about installers: those still come from the package manifests when an update is
// deployed (package catalog, source.go).
//
// What this gives an administrator: "Software updates" can show an update for an installed program without anyone
// importing that program into the catalog first. Nothing is installed without an explicit action, and a package that
// was never tested still asks for the confirmation it always did.
package wingetindex

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Package is one entry of the index.
type Package struct {
	ID            string // Google.Chrome
	Name          string // Google Chrome
	Moniker       string
	LatestVersion string
	// Keys that identify an installed program as this package.
	ProductCodes   []string // Windows Installer product codes and the registry key names of other installers (lower case)
	NormNames      []string // winget-normalized display names, as the index stores them
	NormPublishers []string
}

// Snapshot is the parsed index.
type Snapshot struct {
	Packages []Package
	// Modified is when Microsoft last wrote the index.
	Modified time.Time
}

const (
	maxIndexFile = 256 << 20 // uncompressed database
	indexPath    = "Public/index.db"
)

// ParseMSIX reads the index out of the downloaded source2.msix.
func ParseMSIX(msix []byte) (snap *Snapshot, err error) {
	// The hand-written SQLite reader runs on bytes from the network inside a background goroutine, where a panic would end
	// the whole server. Turn one into an error: the old index stays in use and the console shows the reason.
	defer func() {
		if r := recover(); r != nil {
			snap, err = nil, fmt.Errorf("wingetindex: the index could not be read (%v)", r)
		}
	}()
	zr, err := zip.NewReader(bytes.NewReader(msix), int64(len(msix)))
	if err != nil {
		return nil, fmt.Errorf("wingetindex: the download is not a package file: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != indexPath {
			continue
		}
		if f.UncompressedSize64 > maxIndexFile {
			return nil, errors.New("wingetindex: the index database is unreasonably large")
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		db, err := io.ReadAll(io.LimitReader(rc, maxIndexFile+1))
		if err != nil {
			return nil, err
		}
		if len(db) > maxIndexFile {
			return nil, errors.New("wingetindex: the index database is unreasonably large")
		}
		return ParseDB(db)
	}
	return nil, errors.New("wingetindex: the package holds no index database")
}

// ParseDB reads the index from the SQLite file itself.
func ParseDB(db []byte) (*Snapshot, error) {
	d, err := openSQLite(db)
	if err != nil {
		return nil, err
	}
	tabs, err := d.tables()
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{}
	// metadata: the format must be the one this reader understands.
	major := ""
	if err := d.scanTable(tabs, "metadata", func(_ int64, r []Value) error {
		if len(r) < 2 {
			return nil
		}
		switch r[0].Text() {
		case "majorVersion":
			major = r[1].Text()
		case "lastwritetime":
			if secs, err := strconv.ParseInt(r[1].Text(), 10, 64); err == nil && secs > 0 {
				snap.Modified = time.Unix(secs, 0).UTC()
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if major != "2" {
		return nil, fmt.Errorf("wingetindex: index format version %q is not supported (expected 2)", major)
	}

	byRow := map[int64]int{}
	if err := d.scanTable(tabs, "packages", func(rowid int64, r []Value) error {
		// rowid INTEGER PRIMARY KEY is stored as NULL in column 0; id, name, moniker, latest_version follow.
		if len(r) < 5 {
			return corrupt("a package row has %d columns", len(r))
		}
		p := Package{ID: strings.TrimSpace(r[1].Text()), Name: strings.TrimSpace(r[2].Text()), Moniker: strings.TrimSpace(r[3].Text()), LatestVersion: strings.TrimSpace(r[4].Text())}
		if p.ID == "" || p.LatestVersion == "" {
			return nil
		}
		byRow[rowid] = len(snap.Packages)
		snap.Packages = append(snap.Packages, p)
		return nil
	}); err != nil {
		return nil, err
	}
	// The key tables are WITHOUT ROWID: (key, package row).
	keys := []struct {
		table string
		add   func(p *Package, v string)
		lower bool
	}{
		{"productcodes2", func(p *Package, v string) { p.ProductCodes = append(p.ProductCodes, v) }, true},
		{"norm_names2", func(p *Package, v string) { p.NormNames = append(p.NormNames, v) }, false},
		{"norm_publishers2", func(p *Package, v string) { p.NormPublishers = append(p.NormPublishers, v) }, false},
	}
	for _, k := range keys {
		if err := d.scanTable(tabs, k.table, func(_ int64, r []Value) error {
			if len(r) < 2 {
				return nil
			}
			i, ok := byRow[r[1].Int()]
			if !ok {
				return nil
			}
			v := strings.TrimSpace(r[0].Text())
			if k.lower {
				v = strings.ToLower(v)
			}
			if v != "" {
				k.add(&snap.Packages[i], v)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if len(snap.Packages) < 100 { // the real index has thousands; a handful means we read the wrong thing
		return nil, fmt.Errorf("wingetindex: the index holds only %d packages", len(snap.Packages))
	}
	return snap, nil
}

// extractDB returns the database file inside a package (used by tests).
func extractDB(msix []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(msix), int64(len(msix)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name == indexPath {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxIndexFile))
		}
	}
	return nil, errors.New("no index")
}
