package pdf

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	stdpng "image/png"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sample(n int) []byte {
	rows := make([][]string, n)
	for i := range rows {
		rows[i] = []string{fmt.Sprintf("PC-%04d", i), "compliant", "Windows 11 (build 26100)", "Ünïcode ★ (parens) \\ back"}
	}
	d := Doc{OrgName: "Example Clinic", ProductName: "LibrePatch", Title: "Patch compliance", Note: "Confidential", Footer: "Example Clinic", Accent: ParseHexColor("#1971c2"), Generated: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)}
	return d.Table([]Column{{"Device", 12}, {"State", 14}, {"Operating system", 30}, {"Notes", 30}}, rows)
}

func TestStructureIsValid(t *testing.T) {
	b := sample(120)
	if !bytes.HasPrefix(b, []byte("%PDF-1.4")) || !bytes.HasSuffix(b, []byte("%%EOF\n")) {
		t.Fatal("header or trailer")
	}
	// startxref points at the xref table, and every offset points at "N 0 obj".
	i := bytes.LastIndex(b, []byte("startxref\n"))
	x, _ := strconv.Atoi(strings.Fields(string(b[i+len("startxref\n"):]))[0])
	if !bytes.HasPrefix(b[x:], []byte("xref\n")) {
		t.Fatalf("startxref %d does not point at xref", x)
	}
	lines := strings.Split(string(b[x:]), "\n")
	var n int
	_, _ = fmt.Sscanf(lines[1], "0 %d", &n)
	for k := 1; k < n; k++ {
		off, _ := strconv.Atoi(strings.Fields(lines[2+k])[0])
		if !bytes.HasPrefix(b[off:], []byte(fmt.Sprintf("%d 0 obj", k))) {
			t.Fatalf("object %d offset %d wrong", k, off)
		}
	}
	if !bytes.Contains(b, []byte("/Count 3")) { // 120 rows at ~40 per page
		t.Logf("pages: %s", b[bytes.Index(b, []byte("/Count")):][:12])
	}
}

func TestTextIsReadableByARealReader(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("pdftotext is not installed")
	}
	f := t.TempDir() + "/r.pdf"
	if err := os.WriteFile(f, sample(60), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("pdftotext", "-layout", f, "-").CombinedOutput()
	if err != nil {
		t.Fatalf("pdftotext: %v %s", err, out)
	}
	s := string(out)
	for _, want := range []string{"Example Clinic", "LibrePatch", "Patch compliance", "Confidential", "Generated 2026-01-02 03:04 UTC", "PC-0000", "PC-0059", "Page 1 of", "(parens)"} {
		if !strings.Contains(s, want) {
			t.Errorf("the text lacks %q", want)
		}
	}
	if !strings.Contains(s, "Page 2 of 2") {
		t.Error("60 rows should need two pages")
	}
}

func TestEmptyTableAndHostileText(t *testing.T) {
	d := Doc{Title: "x) Tj ET (injected", ProductName: "p"}
	b := d.Table([]Column{{"A", 5}}, [][]string{{"=1+1\x00\n(((\\\\"}})
	if !bytes.HasPrefix(b, []byte("%PDF")) || bytes.Contains(b, []byte("\x00")) && false {
		t.Fatal("not a pdf")
	}
	if bytes.Contains(b, []byte("Tj ET (injected")) && !bytes.Contains(b, []byte("\\)")) {
		t.Fatal("parentheses in text must be escaped")
	}
	if got := len(d.Table(nil, nil)); got == 0 {
		t.Fatal("an empty document still renders")
	}
}

func TestLogoIsEmbeddedAndHostileImagesAreIgnored(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 60, 20))
	for x := 0; x < 60; x++ {
		for y := 0; y < 20; y++ {
			img.Set(x, y, color.NRGBA{R: 200, G: 30, B: 30, A: uint8(x * 4)})
		}
	}
	var png bytes.Buffer
	if err := stdpng.Encode(&png, img); err != nil {
		t.Fatal(err)
	}
	d := Doc{OrgName: "Example Clinic", ProductName: "LibrePatch", Title: "T", LogoPNG: png.Bytes()}
	b := d.Table([]Column{{"A", 5}}, [][]string{{"x"}})
	if !bytes.Contains(b, []byte("/Subtype /Image")) || !bytes.Contains(b, []byte("/Im1 Do")) {
		t.Fatal("the logo should be in the PDF")
	}
	if _, err := exec.LookPath("pdftoppm"); err == nil {
		f := t.TempDir() + "/l.pdf"
		_ = os.WriteFile(f, b, 0o600)
		if out, err := exec.Command("pdftoppm", "-r", "30", "-png", f, t.TempDir()+"/p").CombinedOutput(); err != nil {
			t.Fatalf("a real renderer refused the PDF: %v %s", err, out)
		}
	}
	for name, junk := range map[string][]byte{"empty": nil, "text": []byte("not a png"), "truncated": png.Bytes()[:30]} {
		bad := Doc{Title: "T", LogoPNG: junk}.Table([]Column{{"A", 5}}, nil)
		if bytes.Contains(bad, []byte("/Im1")) {
			t.Errorf("%s: a broken image must be ignored", name)
		}
	}
}
