package hardware

import (
	"testing"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func structure(typ byte, formatted []byte, strs ...string) []byte {
	b := append([]byte{typ, byte(4 + len(formatted)), 0, 0}, formatted...)
	if len(strs) == 0 {
		return append(b, 0, 0)
	}
	for _, s := range strs {
		b = append(b, s...)
		b = append(b, 0)
	}
	return append(b, 0)
}

func TestParseSMBIOS(t *testing.T) {
	// Type 0: vendor=1, version=2 at offset 0x05 (formatted index relative to start incl header).
	bios := structure(0, []byte{1, 2, 0, 0, 0, 0}, "Vendor", "1.2.3")
	uuid := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	sysFmt := append([]byte{1, 2, 0, 3}, uuid...) // manufacturer=1 product=2 version=0 serial=3
	system := structure(1, sysFmt, "Contoso", "Model X", "SN-123")
	chassis := structure(3, []byte{1, 10}, "Contoso") // type 10 = notebook
	table := append(append(append(bios, system...), chassis...), structure(127, nil)...)
	info := ParseSMBIOS(table, 3, 4)
	if info.BIOSVersion != "1.2.3" || info.Manufacturer != "Contoso" || info.Product != "Model X" || info.Serial != "SN-123" {
		t.Fatalf("%+v", info)
	}
	if info.UUID != "00112233-4455-6677-8899-AABBCCDDEEFF" {
		t.Fatalf("uuid %s", info.UUID)
	}
	if info.Chassis != "notebook" {
		t.Fatalf("chassis %s", info.Chassis)
	}
}

func TestParseSMBIOSMalformedNeverPanics(t *testing.T) {
	inputs := [][]byte{nil, {1}, {1, 200, 0, 0}, {1, 4, 0, 0, 'a'}, {0, 2, 0, 0}, make([]byte, 100)}
	for _, in := range inputs {
		_ = ParseSMBIOS(in, 3, 0)
	}
}

func FuzzParseSMBIOS(f *testing.F) {
	f.Add(structure(1, make([]byte, 0x14), "a", "b", "c"), byte(3), byte(0))
	f.Fuzz(func(t *testing.T, b []byte, major, minor byte) { _ = ParseSMBIOS(b, major, minor) })
}

func TestFingerprintIgnoresVolatile(t *testing.T) {
	a := &agentv1.HardwareInventory{Hostname: "h", BootTime: 1, Disks: []*agentv1.Disk{{Mount: "C:", SizeBytes: 10, FreeBytes: 5}}}
	b := &agentv1.HardwareInventory{Hostname: "h", BootTime: 2, Disks: []*agentv1.Disk{{Mount: "C:", SizeBytes: 10, FreeBytes: 7}}}
	if string(Fingerprint(a)) != string(Fingerprint(b)) {
		t.Fatal("volatile fields changed fingerprint")
	}
	b.Hostname = "other"
	if string(Fingerprint(a)) == string(Fingerprint(b)) {
		t.Fatal("hostname change not detected")
	}
}
