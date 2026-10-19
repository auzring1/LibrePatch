package jobs

import (
	"encoding/json"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Store persists job records. The bbolt-backed store implements it.
type Store interface {
	JobPut(id string, rec []byte) error
	JobGet(id string) []byte
	JobAll() (map[string][]byte, error)
	JobDelete(id string) error
	// GetMeta and SetMeta hold small agent-wide values (the pending reboot plan, scan timing).
	GetMeta(key string) []byte
	SetMeta(key string, val []byte) error
}

// Record is the agent's durable view of one accepted job.
type Record struct {
	JobID     string `json:"job_id"`
	Signed    []byte `json:"signed"` // serialized SignedEnvelope, verified on acceptance
	Type      int32  `json:"type"`
	SID       string `json:"sid,omitempty"`
	Attempt   uint32 `json:"attempt"`
	State     int32  `json:"state"` // agentv1.JobState
	Reason    string `json:"reason,omitempty"`
	Tries     uint32 `json:"tries"`    // local retries performed
	NextRun   int64  `json:"next_run"` // unix seconds; 0 = as soon as eligible
	NotBefore int64  `json:"not_before"`
	Expires   int64  `json:"expires"`
	Accepted  int64  `json:"accepted,omitempty"` // when the agent took the job (unix seconds), for the "waited" figure in the log
	Started   int64  `json:"started,omitempty"`
	Finished  int64  `json:"finished,omitempty"`
	Result    []byte `json:"result,omitempty"` // serialized JobResult
	Cancel    bool   `json:"cancel,omitempty"`
	// AwaitRestart marks an agent update that switched slots and waits for the new version to
	// prove itself (or for the safety net to roll back); the loop must not run it again.
	AwaitRestart bool `json:"await_restart,omitempty"`
	// Keep is when a terminal record may be deleted (expires + 24h, like the replay ledger).
	Keep int64 `json:"keep"`
}

func (r *Record) state() agentv1.JobState { return agentv1.JobState(r.State) }

func (r *Record) terminal() bool {
	switch r.state() {
	case agentv1.JobState_JOB_STATE_SUCCEEDED, agentv1.JobState_JOB_STATE_SUCCEEDED_REBOOT, agentv1.JobState_JOB_STATE_FAILED,
		agentv1.JobState_JOB_STATE_EXPIRED, agentv1.JobState_JOB_STATE_CANCELLED, agentv1.JobState_JOB_STATE_REJECTED:
		return true
	}
	return false
}

func (r *Record) envelope() (*agentv1.SignedEnvelope, *agentv1.JobEnvelope, error) {
	se := &agentv1.SignedEnvelope{}
	if err := proto.Unmarshal(r.Signed, se); err != nil {
		return nil, nil, err
	}
	env := &agentv1.JobEnvelope{}
	if err := proto.Unmarshal(se.Payload, env); err != nil {
		return nil, nil, err
	}
	return se, env, nil
}

func (r *Record) result() *agentv1.JobResult {
	if len(r.Result) == 0 {
		return nil
	}
	res := &agentv1.JobResult{}
	if proto.Unmarshal(r.Result, res) != nil {
		return nil
	}
	return res
}

func save(s Store, r *Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.JobPut(r.JobID, b)
}

func load(s Store, id string) *Record {
	b := s.JobGet(id)
	if b == nil {
		return nil
	}
	var r Record
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	return &r
}

func loadAll(s Store) ([]*Record, error) {
	m, err := s.JobAll()
	if err != nil {
		return nil, err
	}
	out := make([]*Record, 0, len(m))
	for _, b := range m {
		var r Record
		if json.Unmarshal(b, &r) == nil {
			out = append(out, &r)
		}
	}
	return out, nil
}
