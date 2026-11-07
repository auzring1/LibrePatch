package hardware

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SMBIOSInfo is the subset of SMBIOS we report.
type SMBIOSInfo struct {
	BIOSVersion  string
	Manufacturer string
	Product      string
	Serial       string
	UUID         string
	Chassis      string
}

// ParseSMBIOS parses a raw SMBIOS structure table (as returned by
// GetSystemFirmwareTable('RSMB') after its 8-byte header, or
// /sys/firmware/dmi/tables/DMI). It is defensive: malformed input yields
// partial results, never a panic.
func ParseSMBIOS(table []byte, major, minor byte) SMBIOSInfo {
	var info SMBIOSInfo
	for off := 0; off+4 <= len(table); {
		typ := table[off]
		length := int(table[off+1])
		if length < 4 || off+length > len(table) {
			break
		}
		formatted := table[off : off+length]
		// Strings follow the formatted area, each NUL-terminated, set ends with double NUL.
		strStart := off + length
		end := strStart
		for end+1 < len(table) && !(table[end] == 0 && table[end+1] == 0) {
			end++
		}
		strs := splitStrings(table[strStart:min(end+1, len(table))])
		get := func(idx int) string {
			if idx >= len(formatted) {
				return ""
			}
			n := int(formatted[idx])
			if n == 0 || n > len(strs) {
				return ""
			}
			return clean(strs[n-1])
		}
		switch typ {
		case 0: // BIOS
			info.BIOSVersion = get(0x05)
		case 1: // System
			info.Manufacturer = get(0x04)
			info.Product = get(0x05)
			info.Serial = get(0x07)
			if len(formatted) >= 0x18 {
				info.UUID = formatUUID(formatted[0x08:0x18], major, minor)
			}
		case 3: // Chassis
			if len(formatted) > 0x05 {
				info.Chassis = chassisName(formatted[0x05] & 0x7f)
			}
		case 127:
			return info
		}
		off = end + 2
	}
	return info
}

func splitStrings(b []byte) []string {
	var out []string
	for _, s := range strings.Split(string(b), "\x00") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func clean(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s))
	switch strings.ToLower(s) {
	case "", "to be filled by o.e.m.", "default string", "system serial number", "not specified", "none", "0":
		return ""
	}
	return s
}

// formatUUID follows SMBIOS 2.6+: the first three fields are little-endian.
func formatUUID(b []byte, major, minor byte) string {
	allSame := true
	for _, x := range b {
		if x != b[0] {
			allSame = false
		}
	}
	if allSame && (b[0] == 0x00 || b[0] == 0xff) {
		return "" // not present / not settable
	}
	le := major > 2 || (major == 2 && minor >= 6)
	d1, d2, d3 := binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8])
	if le {
		d1, d2, d3 = binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8])
	}
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X", d1, d2, d3, b[8:10], b[10:16])
}

var chassisTypes = map[byte]string{
	1: "other", 2: "unknown", 3: "desktop", 4: "low-profile-desktop", 5: "pizza-box", 6: "mini-tower", 7: "tower",
	8: "portable", 9: "laptop", 10: "notebook", 11: "hand-held", 12: "docking-station", 13: "all-in-one",
	14: "sub-notebook", 15: "space-saving", 16: "lunch-box", 17: "main-server-chassis", 18: "expansion-chassis",
	23: "rack-mount", 24: "sealed-case-pc", 30: "tablet", 31: "convertible", 32: "detachable", 33: "iot-gateway",
	34: "embedded-pc", 35: "mini-pc", 36: "stick-pc",
}

func chassisName(t byte) string {
	if n, ok := chassisTypes[t]; ok {
		return n
	}
	return fmt.Sprintf("type-%d", t)
}
