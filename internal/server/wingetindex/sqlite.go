package wingetindex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

// A minimal, read-only reader for the SQLite file format, enough to read the tables of the winget source index.
//
// Why not a SQLite driver: the index is a small file that is read once a day, and this server is a static binary with a
// short list of dependencies. The reader supports what an ordinary database file written by SQLite uses (rowid tables
// and WITHOUT ROWID tables, interior pages, overflow pages, UTF-8) and refuses the rest (write-ahead log, other text
// encodings). It never allocates more than the input holds, bounds every offset, and stops on a cycle or on absurd
// depth, because the file comes from the network.
//
// Format reference: https://www.sqlite.org/fileformat2.html

var errCorrupt = errors.New("wingetindex: the index database is damaged or unsupported")

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errCorrupt, fmt.Sprintf(format, a...))
}

const (
	maxDepth    = 24
	maxCells    = 5_000_000 // rows scanned from one table
	headerBytes = 100
)

type sqliteDB struct {
	b        []byte
	pageSize int
	usable   int
	pages    int
}

func openSQLite(b []byte) (*sqliteDB, error) {
	if len(b) < headerBytes || string(b[:16]) != "SQLite format 3\x00" {
		return nil, corrupt("not a SQLite database")
	}
	ps := int(binary.BigEndian.Uint16(b[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps > 65536 || ps&(ps-1) != 0 {
		return nil, corrupt("page size %d", ps)
	}
	if b[18] != 1 || b[19] != 1 {
		return nil, corrupt("write-ahead-log databases are not supported")
	}
	if enc := binary.BigEndian.Uint32(b[56:60]); enc > 1 {
		return nil, corrupt("text encoding %d is not UTF-8", enc)
	}
	reserved := int(b[20])
	usable := ps - reserved
	if usable < 480 {
		return nil, corrupt("usable page size %d", usable)
	}
	pages := len(b) / ps
	if pages < 1 {
		return nil, corrupt("empty database")
	}
	return &sqliteDB{b: b, pageSize: ps, usable: usable, pages: pages}, nil
}

func (d *sqliteDB) page(n int) ([]byte, error) {
	if n < 1 || n > d.pages {
		return nil, corrupt("page %d is outside the file (%d pages)", n, d.pages)
	}
	off := (n - 1) * d.pageSize
	return d.b[off : off+d.pageSize], nil
}

// Value is one column of a record.
type Value struct {
	kind byte // 0 null, 1 integer, 2 float, 3 text, 4 blob
	i    int64
	f    float64
	b    []byte
}

// Int returns the integer value (0 for anything else).
func (v Value) Int() int64 {
	switch v.kind {
	case 1:
		return v.i
	case 2:
		if v.f >= math.MinInt64 && v.f <= math.MaxInt64 {
			return int64(v.f)
		}
	}
	return 0
}

// Text returns the text value ("" for a null; a blob is returned as its bytes).
func (v Value) Text() string {
	switch v.kind {
	case 3, 4:
		return string(v.b)
	case 1:
		return fmt.Sprint(v.i)
	}
	return ""
}

// IsNull reports an SQL NULL.
func (v Value) IsNull() bool { return v.kind == 0 }

func varint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	if len(b) >= 9 {
		return v<<8 | uint64(b[8]), 9
	}
	return 0, 0
}

func decodeRecord(p []byte) ([]Value, error) {
	hl, n := varint(p)
	if n == 0 || hl < uint64(n) || hl > uint64(len(p)) { // #nosec G115 -- n is a byte count of 0 to 9 and len(p) is not negative
		return nil, corrupt("record header")
	}
	var types []uint64
	for pos := n; pos < int(hl); { // #nosec G115 -- hl was checked to be at most len(p) above
		t, m := varint(p[pos:hl])
		if m == 0 {
			return nil, corrupt("record serial type")
		}
		types = append(types, t)
		pos += m
		if len(types) > 2000 {
			return nil, corrupt("record with too many columns")
		}
	}
	vals := make([]Value, len(types))
	pos := int(hl) // #nosec G115 -- hl was checked to be at most len(p) above
	take := func(k int) ([]byte, error) {
		if k < 0 || pos+k > len(p) {
			return nil, corrupt("record body")
		}
		s := p[pos : pos+k]
		pos += k
		return s, nil
	}
	for i, t := range types {
		switch {
		case t == 0:
		case t >= 1 && t <= 6:
			sizes := [...]int{0, 1, 2, 3, 4, 6, 8}
			s, err := take(sizes[t])
			if err != nil {
				return nil, err
			}
			var x int64
			if s[0]&0x80 != 0 {
				x = -1
			}
			for _, c := range s {
				x = x<<8 | int64(c)
			}
			vals[i] = Value{kind: 1, i: x}
		case t == 7:
			s, err := take(8)
			if err != nil {
				return nil, err
			}
			vals[i] = Value{kind: 2, f: math.Float64frombits(binary.BigEndian.Uint64(s))}
		case t == 8:
			vals[i] = Value{kind: 1, i: 0}
		case t == 9:
			vals[i] = Value{kind: 1, i: 1}
		case t == 10 || t == 11:
			return nil, corrupt("reserved serial type")
		case t%2 == 0:
			s, err := take(int(t-12) / 2) // #nosec G115 -- take rejects a negative or oversized length, so a wrapped value is refused
			if err != nil {
				return nil, err
			}
			vals[i] = Value{kind: 4, b: s}
		default:
			s, err := take(int(t-13) / 2) // #nosec G115 -- take rejects a negative or oversized length, so a wrapped value is refused
			if err != nil {
				return nil, err
			}
			vals[i] = Value{kind: 3, b: s}
		}
	}
	return vals, nil
}

// payload returns the full payload of a cell whose local part starts at p[0:], following overflow pages.
func (d *sqliteDB) payload(p []byte, total int, index bool) ([]byte, error) {
	u := d.usable
	var maxLocal int
	if index {
		maxLocal = (u-12)*64/255 - 23
	} else {
		maxLocal = u - 35
	}
	minLocal := (u-12)*32/255 - 23
	if total <= maxLocal {
		if total > len(p) {
			return nil, corrupt("cell payload runs past its page")
		}
		return p[:total], nil
	}
	local := minLocal + (total-minLocal)%(u-4)
	if local > maxLocal {
		local = minLocal
	}
	if local+4 > len(p) {
		return nil, corrupt("cell overflow pointer runs past its page")
	}
	out := make([]byte, 0, total)
	out = append(out, p[:local]...)
	next := int(binary.BigEndian.Uint32(p[local : local+4]))
	for hops := 0; len(out) < total; hops++ {
		if next == 0 || hops > total/(u-4)+2 {
			return nil, corrupt("overflow chain ends early")
		}
		pg, err := d.page(next)
		if err != nil {
			return nil, err
		}
		next = int(binary.BigEndian.Uint32(pg[:4]))
		need := min(total-len(out), u-4)
		out = append(out, pg[4:4+need]...)
	}
	return out, nil
}

// scan walks the b-tree rooted at root and calls fn for every row, in key order. For a table b-tree, rowid is the row's
// rowid; for an index b-tree (which is how a WITHOUT ROWID table is stored) it is 0 and the record holds the columns.
func (d *sqliteDB) scan(root int, index bool, fn func(rowid int64, rec []Value) error) error {
	seen := map[int]bool{}
	rows := 0
	var walk func(n, depth int) error
	walk = func(n, depth int) error {
		if depth > maxDepth {
			return corrupt("b-tree is too deep")
		}
		if seen[n] {
			return corrupt("b-tree page %d is visited twice", n)
		}
		seen[n] = true
		pg, err := d.page(n)
		if err != nil {
			return err
		}
		h := 0
		if n == 1 {
			h = headerBytes
		}
		typ := pg[h]
		interior := typ == 0x02 || typ == 0x05
		switch {
		case index && typ != 0x02 && typ != 0x0a, !index && typ != 0x05 && typ != 0x0d:
			return corrupt("page %d has type %#x", n, typ)
		}
		ncell := int(binary.BigEndian.Uint16(pg[h+3 : h+5]))
		hdr := 8
		if interior {
			hdr = 12
		}
		ptrs := h + hdr
		if ptrs+2*ncell > len(pg) {
			return corrupt("page %d cell pointers run past the page", n)
		}
		right := 0
		if interior {
			right = int(binary.BigEndian.Uint32(pg[h+8 : h+12]))
		}
		for c := 0; c < ncell; c++ {
			off := int(binary.BigEndian.Uint16(pg[ptrs+2*c : ptrs+2*c+2]))
			if off < ptrs || off >= len(pg) {
				return corrupt("page %d cell offset %d", n, off)
			}
			cell := pg[off:]
			switch typ {
			case 0x05: // table interior: left child, rowid key
				if len(cell) < 5 {
					return corrupt("short cell")
				}
				if err := walk(int(binary.BigEndian.Uint32(cell[:4])), depth+1); err != nil {
					return err
				}
			case 0x0d: // table leaf: payload size, rowid, payload
				total, m := varint(cell)
				rid, m2 := varint(cell[min(m, len(cell)):])
				if m == 0 || m2 == 0 || total > uint64(len(d.b)) {
					return corrupt("table cell")
				}
				pl, err := d.payload(cell[m+m2:], int(total), false) // #nosec G115 -- total was checked to be at most the file size above
				if err != nil {
					return err
				}
				rec, err := decodeRecord(pl)
				if err != nil {
					return err
				}
				if rows++; rows > maxCells {
					return corrupt("too many rows")
				}
				if err := fn(int64(rid), rec); err != nil { // #nosec G115 -- a SQLite rowid is a signed 64-bit integer stored as its two's complement
					return err
				}
			case 0x02, 0x0a: // index interior: left child, payload size, payload; index leaf: payload size, payload
				if typ == 0x02 {
					if len(cell) < 5 {
						return corrupt("short cell")
					}
					if err := walk(int(binary.BigEndian.Uint32(cell[:4])), depth+1); err != nil {
						return err
					}
					cell = cell[4:]
				}
				total, m := varint(cell)
				if m == 0 || total > uint64(len(d.b)) {
					return corrupt("index cell")
				}
				pl, err := d.payload(cell[m:], int(total), true) // #nosec G115 -- total was checked to be at most the file size above
				if err != nil {
					return err
				}
				rec, err := decodeRecord(pl)
				if err != nil {
					return err
				}
				if rows++; rows > maxCells {
					return corrupt("too many rows")
				}
				if err := fn(0, rec); err != nil {
					return err
				}
			}
		}
		if interior {
			return walk(right, depth+1)
		}
		return nil
	}
	return walk(root, 0)
}

type tableInfo struct {
	root         int
	withoutRowid bool
}

// tables reads sqlite_master.
func (d *sqliteDB) tables() (map[string]tableInfo, error) {
	out := map[string]tableInfo{}
	err := d.scan(1, false, func(_ int64, r []Value) error {
		if len(r) < 5 || r[0].Text() != "table" {
			return nil
		}
		out[strings.ToLower(r[1].Text())] = tableInfo{root: int(r[3].Int()), withoutRowid: strings.Contains(strings.ToUpper(r[4].Text()), "WITHOUT ROWID")}
		return nil
	})
	return out, err
}

// scanTable calls fn for every row of the named table. rowid is meaningful for ordinary tables only.
func (d *sqliteDB) scanTable(tabs map[string]tableInfo, name string, fn func(rowid int64, rec []Value) error) error {
	t, ok := tabs[strings.ToLower(name)]
	if !ok {
		return corrupt("table %s is missing", name)
	}
	return d.scan(t.root, t.withoutRowid, fn)
}
