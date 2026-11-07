package deploy

import (
	"context"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
)

// OfferCancels tells connected devices to drop jobs that were cancelled in the database (others learn on reconnect).
func (s *Service) OfferCancels(ctx context.Context, org uuid.UUID, ids []uuid.UUID) {
	q := dbq.New(s.Pool)
	for _, id := range ids {
		if j, err := q.GetJob(ctx, dbq.GetJobParams{ID: id, OrgID: org}); err == nil && j.CancelPending {
			s.offerCancel(j)
		}
		if j, err := q.GetJob(ctx, dbq.GetJobParams{ID: id, OrgID: org}); err == nil {
			s.publish(org, "job.updated", j.DeviceID, j.ID, uuid.Nil)
		}
	}
}
