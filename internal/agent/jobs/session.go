package jobs

// sessionSig coalesces user-session notifications (logon, unlock, remote
// connect) from the Windows service control handler into one wake-up.
var sessionSig = make(chan struct{}, 1)

// NotifySessionChange tells the engine a user session changed; waiting
// user-scope jobs are re-evaluated immediately instead of at the next poll.
func NotifySessionChange() {
	select {
	case sessionSig <- struct{}{}:
	default:
	}
}
