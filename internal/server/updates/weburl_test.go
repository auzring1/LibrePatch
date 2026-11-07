package updates

import "testing"

func TestWebURLKeepsOnlyWebAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"https://support.microsoft.com/help/5034441": "https://support.microsoft.com/help/5034441",
		"http://go.microsoft.com/fwlink/?LinkId=1":   "http://go.microsoft.com/fwlink/?LinkId=1",
		"":                                    "",
		"javascript:alert(1)":                 "",
		"JaVaScRiPt://x/%0aalert(1)":          "",
		"data:text/html,<script>":             "",
		"file:///c:/windows/system32/cmd.exe": "",
		"//evil.example/x":                    "",
		"https:///no-host":                    "",
	} {
		if got := webURL(in); got != want {
			t.Errorf("webURL(%q) = %q, want %q", in, got, want)
		}
	}
}
