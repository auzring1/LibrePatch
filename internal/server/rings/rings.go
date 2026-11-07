// Package rings holds the rule that decides when a staged rollout may move on to its next ring. Windows updates
// (internal/server/updates, D60) and software policies (internal/server/policies, D121) share it, so "a ring has
// proven itself" means the same thing for both.
package rings

import (
	"fmt"
	"time"
)

// Stats is what one ring has done with one update (or one software version).
type Stats struct {
	// Total devices that were given the update; Installed and Failed are those whose attempt has ended.
	Total, Installed, Failed int
	// First is when the first attempt in the ring was made.
	First time.Time
}

// HoldState is whether an administrator-visible hold exists for the ring and the update.
type HoldState struct{ Open, Released bool }

// Ring is the part of a ring definition the gate needs.
type Ring struct {
	Name             string
	SoakHours        int32
	SuccessThreshold int32 // percent of finished devices that must have succeeded
}

// Gate says whether an update has proven itself in a ring well enough for the next ring: enough devices reported, the
// soak time passed, and the success rate meets the threshold. A failure rate above the allowed one raises a hold at
// once (holdReason non-empty) instead of waiting for the soak. needs is whether devices of the ring still need the
// update.
func Gate(st Stats, ring Ring, h HoldState, now time.Time, needs bool) (passed bool, holdReason string) {
	if h.Released {
		return true, ""
	}
	if h.Open {
		return false, ""
	}
	if st.Total == 0 {
		// Nothing was tried here yet. If devices of the ring still need the update the ring has not started (the next
		// ring must wait); if none does there is nothing to learn from this ring.
		return !needs, ""
	}
	finished := st.Installed + st.Failed
	if finished == 0 {
		return false, ""
	}
	if st.Failed*100 > (100-int(ring.SuccessThreshold))*finished {
		return false, fmt.Sprintf("ring %q: %d of %d devices failed to install it (allowed failure rate %d%%)", ring.Name, st.Failed, finished, 100-ring.SuccessThreshold)
	}
	soak := time.Duration(ring.SoakHours) * time.Hour
	elapsed := now.Sub(st.First)
	if elapsed < soak {
		return false, ""
	}
	// At least half of the ring must have reported, unless a week beyond the soak time has passed.
	if finished < (st.Total+1)/2 && elapsed < soak+7*24*time.Hour {
		return false, ""
	}
	return true, ""
}
