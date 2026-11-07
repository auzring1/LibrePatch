package jobs

import (
	"context"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// FuzzValidateBodies: job bodies come from the server inside a signed envelope, so a compromised
// server decides every byte. The validators are the agent's last gate before an installer runs;
// they must not panic on any shape of body, and with an empty SID machine-scope rules apply.
func FuzzValidateBodies(f *testing.F) {
	seed := func(m proto.Message) {
		if b, err := proto.Marshal(m); err == nil {
			f.Add(b)
		}
	}
	seed(&agentv1.InstallBody{})
	seed(&agentv1.UninstallBody{})
	seed(&agentv1.JobEnvelope{Type: agentv1.JobType_JOB_TYPE_WU_SCAN})
	f.Fuzz(func(t *testing.T, data []byte) {
		var ib agentv1.InstallBody
		if proto.Unmarshal(data, &ib) == nil {
			_ = ValidateInstall(&ib, "")
			_ = ValidateInstall(&ib, "S-1-5-21-1-2-3-1001")
		}
		var ub agentv1.UninstallBody
		if proto.Unmarshal(data, &ub) == nil {
			_ = ValidateUninstall(&ub, "")
			_ = ValidateUninstall(&ub, "S-1-5-21-1-2-3-1001")
		}
		var env agentv1.JobEnvelope
		if proto.Unmarshal(data, &env) == nil {
			_ = ValidateWU(&env)
		}
		var w agentv1.MaintenanceWindow
		if proto.Unmarshal(data, &w) == nil {
			_ = ValidateWindow(&w)
		}
	})
}

// A vendor download that goes silent must be abandoned instead of blocking the job loop.
func TestStallReaderCancelsSilentDownload(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	r := newStallReader(pr, cancel, 50*time.Millisecond)
	go func() { <-ctx.Done(); _ = pw.CloseWithError(ctx.Err()) }()
	if _, err := r.Read(make([]byte, 8)); err == nil {
		t.Fatal("a read from a silent server returned without an error")
	}
	_ = r.Close()
}
