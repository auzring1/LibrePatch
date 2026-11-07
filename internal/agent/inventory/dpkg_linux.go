//go:build linux

package inventory

import (
	"bufio"
	"context"
	"os"
	"os/user"
	"sort"
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// NewCollector returns a development collector that reports dpkg packages as
// machine-scope software and /etc/passwd users. It exists so the Linux test
// build of the agent exercises the real protocol end to end; it is never shipped.
func NewCollector() Collector { return dpkgCollector{} }

type dpkgCollector struct{}

func (dpkgCollector) Collect(ctx context.Context) (*Scan, error) {
	res := &Scan{}
	if f, err := os.Open("/var/lib/dpkg/status"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		cur := map[string]string{}
		flush := func() {
			if cur["Package"] != "" && strings.HasSuffix(cur["Status"], " installed") {
				it := &agentv1.SoftwareItem{
					Key:  &agentv1.SoftwareItemKey{Source: srcReg64, Scope: scopeMach, ItemKey: cur["Package"]},
					Name: cur["Package"], Version: cur["Version"], Publisher: cur["Maintainer"],
				}
				sanitize(it)
				res.Items = append(res.Items, it)
			}
			cur = map[string]string{}
		}
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				flush()
				continue
			}
			if line[0] == ' ' || line[0] == '\t' {
				continue
			}
			if k, v, ok := strings.Cut(line, ": "); ok {
				cur[k] = v
			}
		}
		flush()
	}
	sort.Slice(res.Items, func(i, j int) bool { return res.Items[i].Key.ItemKey < res.Items[j].Key.ItemKey })
	if len(res.Items) > MaxItems {
		res.Items, res.Truncated = res.Items[:MaxItems], true
	}
	if u, err := user.Current(); err == nil {
		res.Users = append(res.Users, &agentv1.DeviceUser{Sid: "S-1-5-21-0-0-0-" + u.Uid, Username: u.Username, ProfilePath: u.HomeDir, Loaded: true})
	}
	return res, ctx.Err()
}
