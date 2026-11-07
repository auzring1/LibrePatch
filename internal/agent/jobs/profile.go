package jobs

import (
	"errors"
	"fmt"
	"strings"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// profileDelete removes one user's profile the way Windows does it: registry entry, profile folder and the user's hive together
// (not by deleting a folder). Nothing in use is touched: a profile of someone who is signed in (or has a disconnected session),
// a profile whose registry hive is loaded, and the account this computer signs in to automatically are all refused with the
// reason, so a click on the wrong row cannot take someone's desktop away.
func (e *Engine) profileDelete(env *agentv1.JobEnvelope) *outcome {
	b := env.GetProfileDelete()
	info, err := e.P.ProfileInfo(b.Sid)
	if err != nil {
		return fail("cannot read the profile list: %v", err)
	}
	who := b.Username
	if d, n := e.P.AccountName(b.Sid); n != "" {
		who = n
		if d != "" {
			who = d + `\` + n
		}
	}
	if who == "" {
		who = b.Sid
	}
	if !info.Exists {
		return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, AlreadySatisfied: true,
			Message: short("there is no profile for " + who + " on this computer; nothing to remove")}}
	}
	refuse := func(reason, why string) *outcome {
		return &outcome{reason: reason, res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, Message: short(why)}}
	}
	if e.P.HasSession(b.Sid) {
		return refuse("profile_in_use", who+" is signed in (or has a disconnected session) on this computer, so the profile was not removed. Sign them out first.")
	}
	if info.Loaded {
		return refuse("profile_in_use", "the profile of "+who+" is loaded (a program or service is running as that user), so it was not removed.")
	}
	if ad, an := e.P.AutoLogon(); an != "" {
		if d, n := e.P.AccountName(b.Sid); strings.EqualFold(n, an) && (ad == "" || d == "" || strings.EqualFold(d, ad)) {
			return refuse("profile_protected", who+" is the account this computer signs in to automatically, so the profile was not removed. Turn automatic sign-in off first if you really mean it.")
		}
	}
	if err := e.P.DeleteProfile(b.Sid); err != nil {
		if errors.Is(err, ErrProfileInUse) {
			return refuse("profile_in_use", "Windows refused to remove the profile of "+who+" because it is in use.")
		}
		return fail("Windows could not remove the profile of %s: %v", who, err)
	}
	after, err := e.P.ProfileInfo(b.Sid)
	if err == nil && after.Exists {
		return fail("Windows reported the profile of %s as removed, but it is still listed", who)
	}
	msg := fmt.Sprintf("removed the profile of %s (%s); the account itself was not deleted", who, info.Path)
	if info.Path != "" {
		if _, still, ferr := e.P.FileVersion(info.Path); ferr == nil && still {
			msg += ". Some files in the folder could not be deleted and are still there"
		}
	}
	return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, Message: short(msg)}}
}
