package jobs

import (
	"fmt"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// AgentUpgradeCode is the Windows Installer upgrade code of the agent's MSI (installer/windows/Package.wxs). It finds the
// installed MSI product, if there is one, without any product code coming from the server.
const AgentUpgradeCode = "{BC09578F-DD80-4ACD-AD99-4A52AF895AC5}"

// selfUninstallWait is how long the removal waits before it starts: time for this process to report the job as done and for the
// server to hear it. An agent that removed itself cannot say so afterwards.
const selfUninstallWait = 15 * time.Second

// agentUninstall removes this agent from the computer. The removal runs in a separate process that waits first, so this job can
// still end as "succeeded" (the server revokes the device when it hears that).
func (e *Engine) agentUninstall() *outcome {
	how, err := e.P.StartSelfUninstall(selfUninstallWait)
	if err != nil {
		return fail("the agent could not start its own removal: %v", err)
	}
	if how == "" {
		how = "agent uninstall"
	}
	return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true,
		Message: short(fmt.Sprintf("the agent removes itself in %d seconds (%s)", int(selfUninstallWait/time.Second), how))}}
}
