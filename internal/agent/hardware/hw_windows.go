//go:build windows

package hardware

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/rebootstate"
)

var (
	kernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemFirmwareTable = kernel32.NewProc("GetSystemFirmwareTable")
	procGlobalMemoryStatusEx   = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64         = kernel32.NewProc("GetTickCount64")
	procGetDiskFreeSpaceExW    = kernel32.NewProc("GetDiskFreeSpaceExW")
	wtsapi32                   = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInfo    = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

// Windows collects inventory via native APIs and the registry (no WMI).
type Windows struct{}

// New returns the platform collector.
func New() Collector { return Windows{} }

// Collect implements Collector.
func (Windows) Collect(ctx context.Context) (*agentv1.HardwareInventory, error) {
	hw := &agentv1.HardwareInventory{Arch: runtime.GOARCH}
	hw.Hostname, _ = os.Hostname()
	hw.Fqdn = computerNameEx(windows.ComputerNameDnsFullyQualified)
	hw.Domain = computerNameEx(windows.ComputerNameDnsDomain)

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		hw.OsCaption = regString(k, "ProductName")
		hw.OsDisplayVersion = regString(k, "DisplayVersion")
		if hw.OsDisplayVersion == "" {
			hw.OsDisplayVersion = regString(k, "ReleaseId")
		}
		hw.OsEdition = regString(k, "EditionID")
		if b, err := strconv.ParseUint(regString(k, "CurrentBuildNumber"), 10, 32); err == nil {
			hw.OsBuild = uint32(b)
		}
		if ubr, _, err := k.GetIntegerValue("UBR"); err == nil {
			hw.OsUbr = uint32(ubr) // #nosec G115 -- registry DWORD
		}
		maj, _, _ := k.GetIntegerValue("CurrentMajorVersionNumber")
		minr, _, _ := k.GetIntegerValue("CurrentMinorVersionNumber")
		hw.OsVersion = strconv.FormatUint(maj, 10) + "." + strconv.FormatUint(minr, 10) + "." + strconv.FormatUint(uint64(hw.OsBuild), 10)
		_ = k.Close()
	}
	// Windows 11 still reports "Windows 10 ..." in ProductName.
	if hw.OsBuild >= 22000 && strings.HasPrefix(hw.OsCaption, "Windows 10") {
		hw.OsCaption = "Windows 11" + strings.TrimPrefix(hw.OsCaption, "Windows 10")
	}

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		hw.CpuModel = strings.TrimSpace(regString(k, "ProcessorNameString"))
		_ = k.Close()
	}
	hw.CpuLogicalCores = uint32(runtime.NumCPU()) // #nosec G115
	hw.RamBytes = totalRAM()

	if s, err := smbios(); err == nil {
		hw.Manufacturer, hw.Model, hw.Serial, hw.SmbiosUuid = s.Manufacturer, s.Product, s.Serial, s.UUID
		hw.Chassis, hw.BiosVersion = s.Chassis, s.BIOSVersion
	}
	hw.Disks = fixedDisks()
	annotateBitlocker(hw.Disks)
	hw.Interfaces = Interfaces()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		hw.LastLoggedOnUser = regString(k, "LastLoggedOnUser")
		_ = k.Close()
	}
	rs := rebootstate.Check()
	hw.PendingRebootReasons = rs.Reasons
	hw.PendingReboot = rs.Pending()
	hw.QueuedFileDeleteCount = uint32(rs.DeleteCount) // #nosec G115 -- a registry list, far below 2^32
	hw.QueuedFileDeletes = rs.DeleteSamples
	hw.Timezone, _ = time.Now().Zone()
	hw.BootTime = time.Now().Add(-uptime()).Unix()
	return hw, ctx.Err()
}

// Heartbeat implements Collector.
func (Windows) Heartbeat(context.Context) (*agentv1.Heartbeat, error) {
	hb := &agentv1.Heartbeat{UptimeS: uint64(uptime().Seconds()), LoggedOnUser: consoleUser()}
	rs := rebootstate.Check()
	hb.PendingReboot = rs.Pending()
	hb.QueuedFileDeletes = rs.DeleteCount > 0
	sys := os.Getenv("SystemDrive")
	if sys == "" {
		sys = "C:"
	}
	_, free := diskSpace(sys + `\`)
	hb.SystemDriveFreeBytes = free
	return hb, nil
}

func regString(k registry.Key, name string) string {
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func computerNameEx(format uint32) string {
	n := uint32(256)
	buf := make([]uint16, n)
	if err := windows.GetComputerNameEx(format, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func totalRAM() uint64 {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0
	}
	return m.TotalPhys
}

func uptime() time.Duration {
	r, _, _ := procGetTickCount64.Call()
	return time.Duration(r) * time.Millisecond // #nosec G115 -- milliseconds since boot fit easily in int64
}

// smbios reads the raw table: RawSMBIOSData { BYTE Used20CallingMethod, SMBIOSMajorVersion,
// SMBIOSMinorVersion, DmiRevision; DWORD Length; BYTE SMBIOSTableData[]; }.
func smbios() (SMBIOSInfo, error) {
	const rsmb = 'R'<<24 | 'S'<<16 | 'M'<<8 | 'B'
	n, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, 0, 0)
	if n == 0 || n > 1<<20 {
		return SMBIOSInfo{}, errors.New("SMBIOS unavailable")
	}
	buf := make([]byte, n)
	got, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buf[0])), n)
	if got == 0 || got > n || got < 8 {
		return SMBIOSInfo{}, errors.New("SMBIOS read failed")
	}
	length := binary.LittleEndian.Uint32(buf[4:8])
	data := buf[8:got]
	if int(length) < len(data) {
		data = data[:length]
	}
	return ParseSMBIOS(data, buf[1], buf[2]), nil
}

func diskSpace(root string) (total, free uint64) {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0, 0
	}
	var freeToCaller, tot, totalFree uint64
	r, _, _ := procGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&tot)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return 0, 0
	}
	return tot, totalFree
}

func fixedDisks() []*agentv1.Disk {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []*agentv1.Disk
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		rp, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(rp) != windows.DRIVE_FIXED {
			continue
		}
		total, free := diskSpace(root)
		fs := make([]uint16, 64)
		_ = windows.GetVolumeInformation(rp, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))) // #nosec G115 -- fixed 64-element buffer
		out = append(out, &agentv1.Disk{Mount: root[:2], Filesystem: windows.UTF16ToString(fs), SizeBytes: total, FreeBytes: free})
	}
	return out
}

// consoleUser returns DOMAIN\user of the active console session, if any.
func consoleUser() string {
	sid := windows.WTSGetActiveConsoleSessionId()
	if sid == 0xFFFFFFFF {
		return ""
	}
	q := func(class uintptr) string {
		var buf *uint16
		var n uint32
		r, _, _ := procWTSQuerySessionInfo.Call(0, uintptr(sid), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
		if r == 0 || buf == nil {
			return ""
		}
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
		return windows.UTF16PtrToString(buf)
	}
	const wtsUserName, wtsDomainName = 5, 7
	user := q(wtsUserName)
	if user == "" {
		return ""
	}
	if d := q(wtsDomainName); d != "" {
		return d + `\` + user
	}
	return user
}

// annotateBitlocker fills Disk.Bitlocker; "unsupported" when BitLocker
// management is not available on this edition.
func annotateBitlocker(disks []*agentv1.Disk) {
	status, ok := bitlockerStatus()
	for _, d := range disks {
		switch {
		case !ok:
			d.Bitlocker = "unsupported"
		case status[strings.ToUpper(d.Mount)] != "":
			d.Bitlocker = status[strings.ToUpper(d.Mount)]
		default:
			d.Bitlocker = "unknown"
		}
	}
}
