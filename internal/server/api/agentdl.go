package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/auzring1/librepatch/internal/server/agentdl"
)

// Public names of the downloads (the file inside is named after the release, see Content-Disposition).
const (
	downloadMSI = "librepatch-agent.msi"
	downloadEXE = "librepatch-agent.exe"
)

func downloadName(k agentdl.Kind) string {
	if k == agentdl.MSI {
		return downloadMSI
	}
	return downloadEXE
}

// downloadURL is the address an endpoint uses, on the console's own host name.
func (s *server) downloadURL(k agentdl.Kind) string {
	return s.Cfg.Origin() + "/download/" + downloadName(k)
}

// downloadAgent: GET /download/librepatch-agent.msi|exe (no sign-in). Serves the installer the server fetched from the
// release that matches its version (decision D112).
func (s *server) downloadAgent(w http.ResponseWriter, r *http.Request) {
	var kind agentdl.Kind
	switch chi.URLParam(r, "name") {
	case downloadMSI:
		kind = agentdl.MSI
	case downloadEXE:
		kind = agentdl.EXE
	default:
		http.NotFound(w, r)
		return
	}
	it, ok := s.AgentDL.Get(kind)
	if !ok {
		w.Header().Set("Retry-After", "300")
		http.Error(w, "The agent installer is not available on this server yet. See Enrollment in the console.", http.StatusNotFound)
		return
	}
	f, err := it.Open()
	if err != nil {
		s.Log.Error("open agent installer", "err", err)
		http.Error(w, "The agent installer cannot be read.", http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "The agent installer cannot be read.", http.StatusInternalServerError)
		return
	}
	ct := "application/octet-stream"
	if kind == agentdl.MSI {
		ct = "application/x-msi"
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(it.FileName, `"`, "")+`"`)
	h.Set("ETag", `"`+it.SHA256+`"`)
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, it.FileName, st.ModTime(), f)
}

type agentDownloadItem struct {
	Kind      string `json:"kind"`
	FileName  string `json:"file_name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Verified  bool   `json:"verified"`
	URL       string `json:"url"`
	Available bool   `json:"available"`
}

// agentDownloads: GET /agent-downloads. What the console's Enrollment page shows about the installers.
func (s *server) agentDownloads(w http.ResponseWriter, _ *http.Request) {
	st := s.AgentDL.Status()
	items := make([]agentDownloadItem, 0, len(agentdl.Kinds))
	for _, k := range agentdl.Kinds {
		it := agentDownloadItem{Kind: string(k), FileName: agentdl.FileName(k, st.Version), URL: s.downloadURL(k)}
		for _, have := range st.Items {
			if have.Kind == k {
				it.FileName, it.Size, it.SHA256, it.Verified, it.Available = have.FileName, have.Size, have.SHA256, have.Verified, true
			}
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    st.Enabled,
		"version":    st.Version,
		"reason":     st.Reason,
		"error":      st.Error,
		"checked_at": st.CheckedAt,
		"items":      items,
	})
}

// Where the one-liners keep the downloaded installer: a folder that always exists, has no spaces in its name and that an
// elevated prompt may write to. The file is deleted again when the install is done.
const tempDir = `%SystemRoot%\Temp\`

// oneLiner makes ONE line of text that downloads an installer from this server and runs it, and that behaves the same when
// pasted into Command Prompt and into PowerShell (5.1 and 7):
//   - everything is a single argument of "cmd /s /c": PowerShell passes the quoted text on without interpreting it (it
//     has no "&&" before version 7, and "&" means something else there), and Command Prompt hands it to a nested cmd;
//   - "&&" runs the install only if the download worked (curl -f fails on an HTTP error instead of saving the error page);
//   - "start /wait" makes the prompt come back only when the installer has finished (msiexec otherwise returns at once);
//   - the last part removes the downloaded file whatever happened.
//
// None of the characters PowerShell treats specially inside double quotes ($ and the back tick) occur in the text: the
// URL, the host name and the enrollment string only contain letters, digits and . - _ : / ; and %SystemRoot% is expanded
// by cmd, not by PowerShell.
func oneLiner(file, downloadURL, runAfterDownload string) string {
	path := tempDir + file
	return `cmd /s /c "curl.exe -fL -o ` + path + ` ` + downloadURL + ` && ` + strings.ReplaceAll(runAfterDownload, "{file}", path) + ` & del /q ` + path + ` 2>nul"`
}

// installCommands are the commands the console prints for a new token: the MSI (silent) and the exe. "one_liner" downloads
// the installer from this server and installs it in one paste (empty while the installer is not on the server); "command"
// is the plain install command for a file that is already in the current folder, and "download" its curl line.
func (s *server) installCommands(enrollment string) map[string]any {
	server := s.Cfg.GatewayPublicAddr
	msiArgs := "/qn /norestart SERVER=" + server + " TOKEN=" + enrollment
	exeArgs := "install --server " + server + " --token " + enrollment
	msi := map[string]any{
		"download":  "",
		"one_liner": "",
		"command":   "msiexec /i " + downloadMSI + " " + msiArgs,
	}
	exe := map[string]any{
		"download":  "",
		"one_liner": "",
		"command":   "librepatch-agent.exe " + exeArgs,
	}
	if _, ok := s.AgentDL.Get(agentdl.MSI); ok {
		u := s.downloadURL(agentdl.MSI)
		msi["download"] = "curl.exe -L -o " + downloadMSI + " " + u
		msi["one_liner"] = oneLiner(downloadMSI, u, "start /wait msiexec /i {file} "+msiArgs)
	}
	if _, ok := s.AgentDL.Get(agentdl.EXE); ok {
		u := s.downloadURL(agentdl.EXE)
		exe["download"] = "curl.exe -L -o " + downloadEXE + " " + u
		exe["one_liner"] = oneLiner(downloadEXE, u, "{file} "+exeArgs)
	}
	return map[string]any{"msi": msi, "exe": exe}
}
