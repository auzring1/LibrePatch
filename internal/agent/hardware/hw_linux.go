//go:build linux

package hardware

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Unix is a best-effort collector used by the development/test agent build.
type Unix struct{}

// New returns the platform collector.
func New() Collector { return Unix{} }

func readTrim(p string) string {
	b, err := os.ReadFile(p) // #nosec G304 -- fixed system paths
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Collect implements Collector.
func (Unix) Collect(ctx context.Context) (*agentv1.HardwareInventory, error) {
	hw := &agentv1.HardwareInventory{Arch: runtime.GOARCH, OsCaption: runtime.GOOS}
	hw.Hostname, _ = os.Hostname()
	hw.Fqdn = hw.Hostname
	if f, err := os.Open("/etc/os-release"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "PRETTY_NAME":
				hw.OsCaption = v
			case "VERSION_ID":
				hw.OsDisplayVersion = v
			}
		}
		_ = f.Close()
	}
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		hw.OsVersion = unix.ByteSliceToString(u.Release[:])
	}
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.TrimSpace(k) == "model name" {
				hw.CpuModel = strings.TrimSpace(v)
				break
			}
		}
		_ = f.Close()
	}
	hw.CpuLogicalCores = uint32(runtime.NumCPU()) // #nosec G115
	var si unix.Sysinfo_t
	if unix.Sysinfo(&si) == nil {
		hw.RamBytes = uint64(si.Totalram) * uint64(si.Unit) // #nosec G115
		hw.BootTime = time.Now().Add(-time.Duration(si.Uptime) * time.Second).Unix()
	}
	hw.Manufacturer = readTrim("/sys/class/dmi/id/sys_vendor")
	hw.Model = readTrim("/sys/class/dmi/id/product_name")
	hw.Serial = readTrim("/sys/class/dmi/id/product_serial")
	hw.SmbiosUuid = strings.ToUpper(readTrim("/sys/class/dmi/id/product_uuid"))
	hw.BiosVersion = readTrim("/sys/class/dmi/id/bios_version")
	if t, err := strconv.Atoi(readTrim("/sys/class/dmi/id/chassis_type")); err == nil && t > 0 && t < 128 {
		hw.Chassis = chassisName(byte(t))
	}
	var st unix.Statfs_t
	if unix.Statfs("/", &st) == nil {
		hw.Disks = []*agentv1.Disk{{Mount: "/", SizeBytes: st.Blocks * uint64(st.Bsize), FreeBytes: st.Bavail * uint64(st.Bsize)}} // #nosec G115
	}
	hw.Interfaces = Interfaces()
	hw.Timezone, _ = time.Now().Zone()
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		hw.PendingReboot = true
		hw.PendingRebootReasons = []string{"reboot_required_file"}
	}
	return hw, ctx.Err()
}

// Heartbeat implements Collector.
func (Unix) Heartbeat(context.Context) (*agentv1.Heartbeat, error) {
	hb := &agentv1.Heartbeat{}
	var si unix.Sysinfo_t
	if unix.Sysinfo(&si) == nil {
		hb.UptimeS = uint64(si.Uptime) // #nosec G115
	}
	var st unix.Statfs_t
	if unix.Statfs("/", &st) == nil {
		hb.SystemDriveFreeBytes = st.Bavail * uint64(st.Bsize) // #nosec G115
	}
	_, err := os.Stat("/var/run/reboot-required")
	hb.PendingReboot = err == nil
	return hb, nil
}
