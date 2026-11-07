package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
)

// SMTPConfig is the mail server the organization configured.
type SMTPConfig struct {
	Host, Username, Password, Security, From, FromName string
	Port                                               int
}

// Attachment is a file on a message.
type Attachment struct {
	Name, Type string
	Data       []byte
}

// Message is one e-mail.
type Message struct {
	To          []string
	Subject     string
	Text        string
	Attachments []Attachment
}

// Mailer sends a message (replaced in tests).
type Mailer interface {
	Send(ctx context.Context, cfg SMTPConfig, m Message) error
}

type smtpMailer struct{}

func (s *Service) mailer() Mailer {
	if s.Mailer != nil {
		return s.Mailer
	}
	return smtpMailer{}
}

// Config reads the saved mail settings. ok is false when e-mail is switched off.
func (s *Service) Config(ctx context.Context, org uuid.UUID) (cfg SMTPConfig, ok bool, err error) {
	ns := s.Settings.Values(ctx, org, "notifications")
	pw, err := s.Settings.Secret(ctx, org, "notifications", "smtp_password")
	if err != nil {
		return cfg, false, err
	}
	_, product := s.names(ctx)
	return SMTPConfig{Host: ns.Str("smtp_host"), Port: ns.Int("smtp_port"), Security: ns.Str("smtp_security"), Username: ns.Str("smtp_username"),
		Password: pw, From: ns.Str("from_address"), FromName: product}, ns.Bool("email_enabled") && ns.Str("smtp_host") != "", nil
}

// SendMail sends a message with the saved settings (used by scheduled reports).
func (s *Service) SendMail(ctx context.Context, org uuid.UUID, m Message) error {
	cfg, ok, err := s.Config(ctx, org)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("e-mail is not set up (Settings > Notifications)")
	}
	return s.mailer().Send(ctx, cfg, m)
}

// TestEmail sends a short message to one address with the saved settings and returns the server's own error text.
func (s *Service) TestEmail(ctx context.Context, org uuid.UUID, to string) error {
	if a, err := mail.ParseAddress(to); err != nil || a.Address != to {
		return errors.New("that is not a plain e-mail address")
	}
	_, product := s.names(ctx)
	return s.SendMail(ctx, org, Message{To: []string{to}, Subject: "Test message from " + product,
		Text: "This is a test message from " + product + ".\r\n\r\nIf you can read it, e-mail notifications and scheduled reports can be delivered.\r\n"})
}

func (s *Service) sendEmailRow(ctx context.Context, r dbq.NotificationOutbox) error {
	var body struct{ Subject, Text string }
	_ = json.Unmarshal(r.Payload, &body)
	_, product := s.names(ctx)
	return s.SendMail(ctx, r.OrgID, Message{To: []string{r.Target}, Subject: "[" + product + "] " + body.Subject, Text: body.Text + "\r\n\r\n-- \r\n" + product + "\r\n"})
}

func clean(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

// Build returns the RFC 5322 message.
func Build(cfg SMTPConfig, m Message, now time.Time, host string) ([]byte, error) {
	if len(m.To) == 0 {
		return nil, errors.New("no recipient")
	}
	var b bytes.Buffer
	from := mail.Address{Name: cfg.FromName, Address: cfg.From}
	for _, a := range append([]string{cfg.From}, m.To...) {
		if p, err := mail.ParseAddress(a); err != nil || p.Address != a {
			return nil, fmt.Errorf("%q is not a plain e-mail address", a)
		}
	}
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", from.String())
	h("To", strings.Join(m.To, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", clean(m.Subject)))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+uuid.NewString()+"@"+clean(host)+">")
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	text := func(w *bytes.Buffer) {
		qp := quotedprintable.NewWriter(w)
		_, _ = qp.Write([]byte(m.Text))
		_ = qp.Close()
	}
	if len(m.Attachments) == 0 {
		h("Content-Type", "text/plain; charset=utf-8")
		h("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		text(&b)
		return b.Bytes(), nil
	}
	mw := multipart.NewWriter(&b)
	h("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
	b.WriteString("\r\n")
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	hdr.Set("Content-Transfer-Encoding", "quoted-printable")
	pw, _ := mw.CreatePart(hdr)
	var tb bytes.Buffer
	text(&tb)
	_, _ = pw.Write(tb.Bytes())
	for _, a := range m.Attachments {
		ah := textproto.MIMEHeader{}
		ah.Set("Content-Type", a.Type+"; name=\""+mime.QEncoding.Encode("utf-8", clean(a.Name))+"\"")
		ah.Set("Content-Disposition", "attachment; filename=\""+mime.QEncoding.Encode("utf-8", clean(a.Name))+"\"")
		ah.Set("Content-Transfer-Encoding", "base64")
		ap, _ := mw.CreatePart(ah)
		enc := base64.StdEncoding.EncodeToString(a.Data)
		for len(enc) > 76 {
			_, _ = ap.Write([]byte(enc[:76] + "\r\n"))
			enc = enc[76:]
		}
		_, _ = ap.Write([]byte(enc + "\r\n"))
	}
	_ = mw.Close()
	return b.Bytes(), nil
}

func (smtpMailer) Send(ctx context.Context, cfg SMTPConfig, m Message) error {
	if cfg.Host == "" || cfg.From == "" {
		return errors.New("the mail server and the From address are not set")
	}
	raw, err := Build(cfg, m, time.Now(), cfg.Host)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if cfg.Security == "tls" {
		conn = tls.Client(conn, tlsCfg)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("the mail server did not greet us: %w", err)
	}
	defer func() { _ = c.Close() }()
	if cfg.Security == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("the mail server does not offer STARTTLS; choose another connection security or fix the server")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS failed (is the server's certificate valid for %s?): %w", cfg.Host, err)
		}
	}
	if cfg.Username != "" {
		if cfg.Security == "none" {
			return errors.New("a login needs an encrypted connection")
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("the mail server refused the login: %w", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return fmt.Errorf("sender refused: %w", err)
	}
	for _, to := range m.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("recipient %s refused: %w", to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
