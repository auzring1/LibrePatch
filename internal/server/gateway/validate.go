package gateway

import (
	"errors"
	"math"
	"strconv"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// validateHardware bounds attacker-controlled inventory (SECURITY T-DEV-2/3).
func validateHardware(hw *agentv1.HardwareInventory) error {
	strs := []string{hw.Hostname, hw.Fqdn, hw.Domain, hw.OsCaption, hw.OsDisplayVersion, hw.OsEdition, hw.OsVersion,
		hw.Arch, hw.Manufacturer, hw.Model, hw.Serial, hw.SmbiosUuid, hw.Chassis, hw.BiosVersion, hw.CpuModel,
		hw.LastLoggedOnUser, hw.Timezone}
	for _, s := range strs {
		if len(s) > 1024 {
			return errors.New("hardware field too long")
		}
	}
	if len(hw.Disks) > 64 || len(hw.Interfaces) > 64 || len(hw.PendingRebootReasons) > 16 || len(hw.QueuedFileDeletes) > 16 {
		return errors.New("too many hardware entries")
	}
	for _, d := range hw.Disks {
		if len(d.Mount) > 256 || len(d.Filesystem) > 64 || len(d.Bitlocker) > 32 {
			return errors.New("disk field too long")
		}
	}
	// Values feed generated bigint/integer columns: keep them in range.
	if hw.RamBytes > 1<<50 || hw.OsBuild > 1_000_000_000 || hw.OsUbr > 1_000_000_000 {
		return errors.New("hardware value out of range")
	}
	for _, n := range hw.Interfaces {
		if len(n.Name) > 256 || len(n.Mac) > 64 || len(n.Addresses) > 32 || len(n.Cidrs) > 32 {
			return errors.New("interface field too long")
		}
		for _, a := range append(append([]string(nil), n.Addresses...), n.Cidrs...) {
			if len(a) > 64 {
				return errors.New("address too long")
			}
		}
	}
	for _, r := range hw.PendingRebootReasons {
		if len(r) > 128 {
			return errors.New("reboot reason too long")
		}
	}
	for _, p := range hw.QueuedFileDeletes {
		if len(p) > 1024 {
			return errors.New("queued file path too long")
		}
	}
	return nil
}

// freeBytes is the system drive's free space from a heartbeat. Zero means "not reported" (an older agent, or a drive
// that could not be read), which is stored as unknown rather than as a full disk.
func freeBytes(hb *agentv1.Heartbeat) *int64 {
	if hb.SystemDriveFreeBytes == 0 {
		return nil
	}
	v := clampI64(hb.SystemDriveFreeBytes)
	return &v
}

func clampI64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

func itoa(v uint32) string { return strconv.FormatUint(uint64(v), 10) }
