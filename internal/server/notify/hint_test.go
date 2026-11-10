package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestHint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"the mail server refused the login: 535 5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Tenant", "Authenticated SMTP"},
		{"the mail server refused the login: 535 5.7.8 Username and Password not accepted", "app password"},
		{"sender refused: 550 5.7.60 SMTP; Client does not have permissions to send as this sender", "send as"},
		{"STARTTLS failed (is the server's certificate valid for mail.example.org?): x509: certificate is valid for a.example", "exact host name"},
		{"cannot connect to mail.example.org:25: dial tcp 192.0.2.1:25: i/o timeout", "may connect out"},
		{"the mail server does not offer STARTTLS; choose another connection security or fix the server", "port 465"},
	}
	for _, c := range cases {
		err := Hint(errors.New(c.in))
		if !strings.Contains(err.Error(), c.in) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q -> %q", c.in, err)
		}
	}
	plain := errors.New("recipient x@example.org refused: 550 no such user")
	if Hint(plain) != plain || Hint(nil) != nil {
		t.Error("an unknown error is returned unchanged")
	}
}
