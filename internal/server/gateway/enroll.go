package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/pkix"
	"github.com/auzring1/librepatch/internal/shared/text"
)

// errRejected is the single generic error enrollment returns; the
// detailed reason goes only to the audit log (PROTOCOL §4.1).
var errRejected = status.Error(codes.PermissionDenied, "enrollment rejected")

func ticketHash(t string) []byte {
	h := sha256.Sum256([]byte("librepatch/enroll-ticket/v1\x00" + t))
	return h[:]
}

// cleanField trims, strips control characters and bounds length.
func cleanField(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	return text.Truncate(s, max)
}

// Enroll handles first contact from a new agent.
func (g *Gateway) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	ip := peerIP(ctx)
	if !g.enrollIP.Allow(ip) {
		return nil, status.Error(codes.ResourceExhausted, "too many enrollment attempts")
	}
	if len(req.Token) < 40 || len(req.Token) > 128 {
		g.auditEnroll(ctx, nil, ip, "", audit.Denied, "malformed_token", req.Hostname)
		return nil, errRejected
	}
	th := auth.EnrollmentTokenHash(req.Token)
	if !g.enrollToken.Allow(string(th)) {
		return nil, status.Error(codes.ResourceExhausted, "too many enrollment attempts")
	}
	if _, err := pkix.CheckDeviceCSR(req.CsrDer); err != nil {
		g.auditEnroll(ctx, nil, ip, "", audit.Denied, "bad_csr", req.Hostname)
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}
	hostname := cleanField(req.Hostname, 255)
	if hostname == "" {
		return nil, status.Error(codes.InvalidArgument, "hostname required")
	}
	smbios, serial := cleanField(req.SmbiosUuid, 64), cleanField(req.Serial, 128)
	now := g.now()

	var (
		resp       *agentv1.EnrollResult
		orgID      uuid.UUID
		deviceID   = uuid.New()
		denyReason string
	)
	release, gerr := g.enrollGate.acquire(ctx)
	if gerr != nil {
		return nil, status.Error(codes.Unavailable, "the server is busy enrolling devices; try again")
	}
	defer release()
	err := store.Tx(ctx, g.pool, func(tx pgx.Tx, q *dbq.Queries) error {
		tok, err := q.GetEnrollmentTokenByHashForUpdate(ctx, th)
		switch {
		case isNoRows(err):
			denyReason = "unknown_token"
		case err != nil:
			return err
		case tok.RevokedAt != nil:
			denyReason = "token_revoked"
		case !now.Before(tok.ExpiresAt):
			denyReason = "token_expired"
		case tok.UsedCount >= tok.MaxUses:
			denyReason = "token_exhausted"
		}
		if denyReason != "" {
			return errRejected
		}
		orgID = tok.OrgID
		if err := q.IncrementEnrollmentTokenUse(ctx, tok.ID); err != nil {
			return err
		}
		// Known hardware re-enrolling: never silently take over the old identity.
		var replaces *uuid.UUID
		existing, err := q.FindActiveDeviceByHardware(ctx, dbq.FindActiveDeviceByHardwareParams{OrgID: tok.OrgID, SmbiosUuid: smbios, Serial: serial})
		if err == nil {
			replaces = &existing.ID
		} else if !isNoRows(err) {
			return err
		}
		needsApproval := tok.RequireApproval || replaces != nil
		params := dbq.CreateDeviceParams{ID: deviceID, OrgID: tok.OrgID, SiteID: tok.SiteID, Hostname: hostname,
			SmbiosUuid: smbios, Serial: serial, OsBuild: cleanField(req.OsBuild, 64), Arch: cleanField(req.Arch, 32),
			AgentVersion: cleanField(req.AgentVersion, 64), EnrolledVia: &tok.ID, ReplacesDeviceID: replaces}
		resp = &agentv1.EnrollResult{DeviceId: deviceID.String(), OrgId: tok.OrgID.String(),
			IssuingCaDer: g.authority.Issuing.Cert.Raw, RootCaDer: g.authority.Root.Raw,
			JobSigningCertsDer: [][]byte{g.authority.JobSigning.Cert.Raw}}
		if needsApproval {
			ticket := make([]byte, 32)
			if _, err := rand.Read(ticket); err != nil {
				return err
			}
			t := base64.RawURLEncoding.EncodeToString(ticket)
			params.Status = "pending"
			params.EnrollTicketHash = ticketHash(t)
			params.PendingCsr = req.CsrDer
			resp.Status = agentv1.EnrollStatus_ENROLL_STATUS_PENDING
			resp.Ticket = t
			resp.RetryAfterS = uint32(g.cfg.EnrollPollInterval.Seconds())
			if err := q.CreateDevice(ctx, params); err != nil {
				return err
			}
		} else {
			params.Status = "active"
			params.ApprovedAt = &now
			if err := q.CreateDevice(ctx, params); err != nil {
				return err
			}
			certDER, err := g.issue(ctx, q, deviceID, req.CsrDer)
			if err != nil {
				return err
			}
			resp.Status = agentv1.EnrollStatus_ENROLL_STATUS_APPROVED
			resp.ClientCertDer = certDER
		}
		details := map[string]any{"hostname": hostname, "status": params.Status, "token_id": tok.ID.String()}
		if replaces != nil {
			details["replaces_device_id"] = replaces.String()
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &tok.OrgID, ActorType: audit.ActorDevice, ActorID: deviceID.String(),
			ActorIP: ip, Action: "device.enroll", TargetType: "device", TargetIDs: []string{deviceID.String()},
			Outcome: audit.Success, Details: details}, now)
		return err
	})
	if errors.Is(err, errRejected) {
		g.auditEnroll(ctx, nil, ip, "", audit.Denied, denyReason, hostname)
		return nil, errRejected
	}
	if err != nil {
		g.log.Error("enroll", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	g.log.Info("device enrolled", "device", deviceID, "hostname", hostname, "status", resp.Status.String())
	g.events.Publish(orgID, events.Event{Type: events.DeviceEnrolled, DeviceID: deviceID})
	return &agentv1.EnrollResponse{Result: resp}, nil
}

// EnrollStatus is polled by agents whose enrollment awaits approval.
func (g *Gateway) EnrollStatus(ctx context.Context, req *agentv1.EnrollStatusRequest) (*agentv1.EnrollStatusResponse, error) {
	ip := peerIP(ctx)
	if !g.statusIP.Allow(ip) {
		return nil, status.Error(codes.ResourceExhausted, "polling too fast")
	}
	if len(req.Ticket) < 40 || len(req.Ticket) > 128 {
		return nil, errRejected
	}
	now := g.now()
	var res *agentv1.EnrollResult
	var orgID, deviceID uuid.UUID
	err := store.Tx(ctx, g.pool, func(tx pgx.Tx, q *dbq.Queries) error {
		d, err := q.GetDeviceByTicketHash(ctx, ticketHash(req.Ticket))
		if isNoRows(err) {
			return errRejected
		} else if err != nil {
			return err
		}
		orgID, deviceID = d.OrgID, d.ID
		base := &agentv1.EnrollResult{DeviceId: d.ID.String(), OrgId: d.OrgID.String(),
			IssuingCaDer: g.authority.Issuing.Cert.Raw, RootCaDer: g.authority.Root.Raw,
			JobSigningCertsDer: [][]byte{g.authority.JobSigning.Cert.Raw}}
		switch d.Status {
		case "pending":
			base.Status = agentv1.EnrollStatus_ENROLL_STATUS_PENDING
			base.Ticket = req.Ticket
			base.RetryAfterS = uint32(g.cfg.EnrollPollInterval.Seconds())
			res = base
			return nil
		case "active":
			if len(d.PendingCsr) == 0 {
				return errRejected
			}
			certDER, err := g.issue(ctx, q, d.ID, d.PendingCsr)
			if err != nil {
				return err
			}
			if err := q.CompleteDeviceEnrollment(ctx, d.ID); err != nil {
				return err
			}
			base.Status = agentv1.EnrollStatus_ENROLL_STATUS_APPROVED
			base.ClientCertDer = certDER
			res = base
			_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &d.OrgID, ActorType: audit.ActorDevice, ActorID: d.ID.String(),
				ActorIP: ip, Action: "device.certificate_issue", TargetType: "device", TargetIDs: []string{d.ID.String()},
				Outcome: audit.Success, Details: map[string]any{"after": "approval"}}, now)
			return err
		default:
			res = &agentv1.EnrollResult{Status: agentv1.EnrollStatus_ENROLL_STATUS_REJECTED, DeviceId: d.ID.String()}
			return nil
		}
	})
	if errors.Is(err, errRejected) {
		return nil, errRejected
	}
	if err != nil {
		g.log.Error("enroll status", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}
	if res.Status == agentv1.EnrollStatus_ENROLL_STATUS_APPROVED {
		g.events.Publish(orgID, events.Event{Type: events.DeviceUpdated, DeviceID: deviceID})
	}
	return &agentv1.EnrollStatusResponse{Result: res}, nil
}

// issue signs a device certificate and records it.
func (g *Gateway) issue(ctx context.Context, q *dbq.Queries, deviceID uuid.UUID, csr []byte) ([]byte, error) {
	cert, err := g.authority.IssueDeviceCert(csr, deviceID, g.cfg.DeviceCertLifetime, g.now())
	if err != nil {
		return nil, err
	}
	if err := q.InsertDeviceCert(ctx, dbq.InsertDeviceCertParams{Serial: pki.SerialHex(cert), DeviceID: deviceID,
		PublicKeySha256: pki.PublicKeySHA256(cert), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}); err != nil {
		return nil, err
	}
	return cert.Raw, nil
}

func (g *Gateway) auditEnroll(ctx context.Context, org *uuid.UUID, ip, device, outcome, reason, hostname string) {
	_ = audit.Log(ctx, g.pool, audit.Entry{OrgID: org, ActorType: audit.ActorAnonymous, ActorID: device, ActorIP: ip,
		Action: "device.enroll", Outcome: outcome, Details: map[string]any{"reason": reason, "hostname": cleanField(hostname, 255)}})
}
