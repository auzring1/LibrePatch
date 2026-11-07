package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sconfig "github.com/auzring1/librepatch/internal/server/config"
	"github.com/auzring1/librepatch/internal/shared/version"
)

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// A stand-in for the project's release page: the two installers and their published SHA-256 files.
func fakeRelease(t *testing.T, ver string, msi, exe []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/server-" + ver + "/librepatch-agent_" + ver + "_windows_"
		switch r.URL.Path {
		case base + "x64.msi":
			_, _ = w.Write(msi)
		case base + "amd64.exe":
			_, _ = w.Write(exe)
		case base + "x64.msi.sha256":
			_, _ = io.WriteString(w, shaHex(msi)+"  x64.msi\n")
		case base + "amd64.exe.sha256":
			_, _ = io.WriteString(w, shaHex(exe)+"  amd64.exe\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The console hands out the agent installers and prints MSI and exe install commands that download them from the server (D112).
func TestAgentDownloadsAndInstallCommands(t *testing.T) {
	const ver = "1.2.3"
	old := version.Version
	version.Version = ver
	t.Cleanup(func() { version.Version = old })
	msi, exe := bytes.Repeat([]byte("MSI!"), 5000), []byte("MZ pretend agent")
	rel := fakeRelease(t, ver, msi, exe)

	h := newHarnessCfg(t, 90*24*time.Hour, func(c *sconfig.Config) { c.AgentDownloads = "github"; c.AgentDownloadBaseURL = rel.URL })
	h.setupAndLogin()

	// The server fetches both by itself, in the background.
	var dl map[string]any
	waitFor(t, 15*time.Second, "both installers fetched", func() bool {
		_, dl = h.do("GET", "/api/v1/agent-downloads", nil, nil)
		items, _ := dl["items"].([]any)
		if len(items) != 2 {
			return false
		}
		for _, it := range items {
			if it.(map[string]any)["available"] != true {
				return false
			}
		}
		return true
	})
	if dl["enabled"] != true || dl["version"] != ver {
		t.Fatalf("status: %v", dl)
	}
	first := dl["items"].([]any)[0].(map[string]any)
	if first["kind"] != "msi" || first["verified"] != true || first["sha256"] != shaHex(msi) || first["url"] != "http://localhost/download/librepatch-agent.msi" {
		t.Fatalf("msi item: %v", first)
	}

	// Anyone on the network can download them, without signing in (an endpoint has no console login).
	anon := &http.Client{Timeout: 10 * time.Second}
	for name, want := range map[string][]byte{"librepatch-agent.msi": msi, "librepatch-agent.exe": exe} {
		resp, err := anon.Get(h.base + "/download/" + name)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !bytes.Equal(body, want) {
			t.Fatalf("%s: HTTP %d, %d bytes", name, resp.StatusCode, len(body))
		}
		if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "librepatch-agent_"+ver+"_windows_") || resp.Header.Get("ETag") != `"`+shaHex(want)+`"` {
			t.Fatalf("%s headers: %v", name, resp.Header)
		}
	}
	if resp, err := anon.Get(h.base + "/download/something-else.exe"); err != nil || resp.StatusCode != 404 {
		t.Fatalf("an unknown name must be 404: %v %v", resp, err)
	}

	// The new token shows how to install with the MSI and with the exe, each downloading from this server.
	st, b := h.do("POST", "/api/v1/enrollment-tokens", map[string]any{"name": "pcs", "max_uses": 5, "expires_in_hours": 1, "require_approval": false}, nil)
	if st != 201 {
		t.Fatalf("token: %d %v", st, b)
	}
	enc := b["enrollment_string"].(string)
	inst := b["install"].(map[string]any)
	m, e := inst["msi"].(map[string]any), inst["exe"].(map[string]any)
	msiLine, exeLine := m["one_liner"].(string), e["one_liner"].(string)
	// One line each, the same in Command Prompt and in PowerShell: no new line, no "$" or back tick (PowerShell would expand
	// them inside the double quotes), everything inside one "cmd /s /c" argument.
	for name, line := range map[string]string{"msi": msiLine, "exe": exeLine} {
		if strings.ContainsAny(line, "\r\n$`") || !strings.HasPrefix(line, `cmd /s /c "`) || !strings.HasSuffix(line, `"`) || strings.Count(line, `"`) != 2 {
			t.Fatalf("%s one-liner must be one line in one quoted argument: %q", name, line)
		}
	}
	if msiLine != `cmd /s /c "curl.exe -fL -o %SystemRoot%\Temp\librepatch-agent.msi http://localhost/download/librepatch-agent.msi && `+
		`start /wait msiexec /i %SystemRoot%\Temp\librepatch-agent.msi /qn /norestart SERVER=localhost:8443 TOKEN=`+enc+
		` & del /q %SystemRoot%\Temp\librepatch-agent.msi 2>nul"` {
		t.Fatalf("msi one-liner: %s", msiLine)
	}
	if exeLine != `cmd /s /c "curl.exe -fL -o %SystemRoot%\Temp\librepatch-agent.exe http://localhost/download/librepatch-agent.exe && `+
		`%SystemRoot%\Temp\librepatch-agent.exe install --server localhost:8443 --token `+enc+
		` & del /q %SystemRoot%\Temp\librepatch-agent.exe 2>nul"` {
		t.Fatalf("exe one-liner: %s", exeLine)
	}
	// The plain commands (for a file already in the current folder) are still there.
	if m["download"] != "curl.exe -L -o librepatch-agent.msi http://localhost/download/librepatch-agent.msi" ||
		m["command"] != "msiexec /i librepatch-agent.msi /qn /norestart SERVER=localhost:8443 TOKEN="+enc ||
		e["command"] != "librepatch-agent.exe install --server localhost:8443 --token "+enc || b["install_command"] != e["command"] {
		t.Fatalf("plain commands: %v %v", m, e)
	}
}

// On a development build there is no release to take the agent from: no download lines, a clear reason, and 404.
func TestNoAgentDownloadsWithoutARelease(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	_, dl := h.do("GET", "/api/v1/agent-downloads", nil, nil)
	if dl["enabled"] != false || dl["reason"] == "" {
		t.Fatalf("status: %v", dl)
	}
	for _, it := range dl["items"].([]any) {
		if it.(map[string]any)["available"] != false {
			t.Fatalf("nothing should be available: %v", dl)
		}
	}
	resp, err := http.Get(h.base + "/download/librepatch-agent.msi")
	if err != nil || resp.StatusCode != 404 {
		t.Fatalf("download without a release: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	_, b := h.do("POST", "/api/v1/enrollment-tokens", map[string]any{"name": "x", "max_uses": 1, "expires_in_hours": 1, "require_approval": false}, nil)
	m := b["install"].(map[string]any)["msi"].(map[string]any)
	if m["one_liner"] != "" || m["download"] != "" || !strings.HasPrefix(m["command"].(string), "msiexec /i librepatch-agent.msi /qn") {
		t.Fatalf("msi commands: %v", m)
	}
}

// Only people who may read enrollment tokens see the list; the files themselves are public.
func TestAgentDownloadsListNeedsASession(t *testing.T) {
	h := newHarness(t)
	if st, _ := h.do("GET", "/api/v1/agent-downloads", nil, nil); st != 401 {
		t.Fatalf("without a session: HTTP %d", st)
	}
}
