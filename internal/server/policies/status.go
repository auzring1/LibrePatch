package policies

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
)

// CheckEvery is how often the server looks at every policy (the housekeeping loop runs Tick every five minutes).
const CheckEvery = 5 * time.Minute

// What a check of a policy found, as a stable code the console can filter and colour by (D132). The sentence that goes
// with it is built in statusOf.
const (
	StateUpToDate          = "up_to_date"          // no targeted device needs anything
	StateUpdating          = "updating"            // a deployment is running or was just created
	StateWaitingApproval   = "waiting_approval"    // an administrator has to approve the version
	StateWaitingDelay      = "waiting_delay"       // the version is younger than the policy's delay
	StateWaitingRing       = "waiting_ring"        // an earlier ring has not finished
	StateHeld              = "held"                // a ring missed its success threshold
	StateRetry             = "retry"               // some devices failed and will be tried again later
	StateGaveUp            = "gave_up"             // some devices failed three times and are left alone
	StateDeclined          = "declined"            // the version was declined
	StateVendor            = "left_to_vendor"      // the app updates itself
	StateExcluded          = "excluded"            // the package is excluded in the catalog
	StateNoVersion         = "no_version"          // the catalog has nothing to install
	StatePackageGone       = "package_missing"     // the package was removed from the catalog
	StateError             = "error"               // the check itself failed
	StateNew               = "new"                 // not checked yet
	StateOff               = "off"                 // the policy is disabled (set by the console from `enabled`)
	StateNoApps            = "no_apps"             // an all-apps policy has no app with an update to handle
	StateFirstCheckSoon    = "first_check_soon"    // an all-apps policy that has not looked yet
	StateAppsWaiting       = "apps_waiting"        // an all-apps policy with apps that wait for approval or a ring
	StateAppsUpdating      = "apps_updating"       // an all-apps policy with apps being updated
	StateAppsAllCurrent    = "apps_all_current"    // an all-apps policy whose apps are all up to date
	StateAppsNeedAttention = "apps_need_attention" // an all-apps policy with held or failed apps
)

// attemptStat counts what filterAttempts left out of a run: devices whose job is still open, devices that failed three
// times, and devices that were handled recently (a retry or the inventory is awaited).
type attemptStat struct{ open, gaveUp, waiting int }

func (a *attemptStat) add(b attemptStat) {
	a.open += b.open
	a.gaveUp += b.gaveUp
	a.waiting += b.waiting
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// statusOf says what a check found. created is how many devices the check just handed a deployment to.
func statusOf(ro *rollout, created int, wait attemptStat) (state, detail string) {
	if ro == nil {
		return StatePackageGone, "The app is no longer in the catalog, so nothing is installed."
	}
	switch ro.blocked {
	case blockExcluded:
		return StateExcluded, "This app is excluded in the catalog, so nothing is installed."
	case blockSelfUpdate:
		return StateVendor, "The app updates itself, so it is left to its vendor. (Change that under the app's overrides.)"
	case blockNoVersion:
		return StateNoVersion, "The catalog has no version of this app that can be installed."
	}
	ver := ro.ver.Version
	need := len(ro.all)
	if need == 0 {
		if ro.policy.Kind == "baseline" {
			return StateUpToDate, fmt.Sprintf("Every targeted device that should have it has %s.", ver)
		}
		return StateUpToDate, fmt.Sprintf("Up to date: no device in the groups has an older version than %s.", ver)
	}
	devices := fmt.Sprintf("%d %s", need, plural(need, "device needs it", "devices need it"))
	switch ro.blocked {
	case blockDeclined:
		return StateDeclined, fmt.Sprintf("Version %s was declined, so it is not installed (%s).", ver, devices)
	case blockPending:
		return StateWaitingApproval, fmt.Sprintf("Waiting for your approval of version %s (%s).", ver, devices)
	case blockDelay:
		return StateWaitingDelay, fmt.Sprintf("Version %s is waiting out the delay until %s (%s).", ver, ro.available.Format("2006-01-02"), devices)
	}
	for _, st := range ro.stages {
		if st.ring != nil && (st.hold.Open || st.holdReason != "") {
			return StateHeld, fmt.Sprintf("Held: ring %q missed its success threshold for %s, so later rings wait until you release it.", st.name, ver)
		}
	}
	if created > 0 {
		return StateUpdating, fmt.Sprintf("Updating %d %s to %s.", created, plural(created, "device", "devices"), ver)
	}
	if wait.open > 0 {
		return StateUpdating, fmt.Sprintf("%d %s installing %s (%s).", wait.open, plural(wait.open, "device is", "devices are"), ver, devices)
	}
	if wait.gaveUp > 0 && wait.waiting == 0 {
		return StateGaveUp, fmt.Sprintf("%d %s failed three times and %s left alone (%s).", wait.gaveUp, plural(wait.gaveUp, "device", "devices"), plural(wait.gaveUp, "is", "are"), devices)
	}
	if wait.waiting > 0 {
		return StateRetry, fmt.Sprintf("%d %s will be tried again later (%s).", wait.waiting, plural(wait.waiting, "device", "devices"), devices)
	}
	var first *stage
	for _, st := range ro.stages {
		if len(st.cands) > 0 && !st.eligible {
			first = st
			break
		}
	}
	if first != nil {
		before := "the ring before it"
		for i, st := range ro.stages {
			if st == first && i > 0 {
				before = fmt.Sprintf("ring %q", ro.stages[i-1].name)
			}
		}
		return StateWaitingRing, fmt.Sprintf("Version %s waits for %s to finish before %q gets it (%s).", ver, before, first.name, devices)
	}
	return StateUpdating, fmt.Sprintf("Version %s is being rolled out (%s).", ver, devices)
}

// setStatus records what a check found.
func (s *Service) setStatus(ctx context.Context, id uuid.UUID, now time.Time, state, detail string, created int, dep *uuid.UUID) {
	var runAt *time.Time
	if created > 0 {
		runAt = &now
	}
	if len(detail) > 500 {
		detail = detail[:500]
	}
	if err := dbq.New(s.Pool).SetPolicyStatus(ctx, dbq.SetPolicyStatusParams{ID: id, CheckedAt: &now, State: state, Detail: detail, RunAt: runAt, DeploymentID: dep}); err != nil {
		s.log().Warn("record policy status", "policy", id, "err", err)
	}
}
