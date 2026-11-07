package branding

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func testPNG(t testing.TB, w, h int) []byte {
	t.Helper()
	im := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			im.Set(x, y, color.NRGBA{uint8(x * 7), uint8(y * 5), 120, 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, im); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func testJPEG(t testing.TB, w, h int) []byte {
	t.Helper()
	im := image.NewRGBA(image.Rect(0, 0, w, h))
	var b bytes.Buffer
	if err := jpeg.Encode(&b, im, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// chunk builds a PNG chunk with a correct CRC.
func chunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data))) // #nosec G115 -- test data
	b.WriteString(typ)
	b.Write(data)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), data...)))
	return b.Bytes()
}

func wantImageError(t *testing.T, name, kind string, data []byte, contains string) {
	t.Helper()
	_, err := Process(kind, data)
	ie, ok := err.(*ImageError)
	if !ok {
		t.Errorf("%s: want an ImageError, got %v", name, err)
		return
	}
	if !strings.Contains(ie.Msg, contains) {
		t.Errorf("%s: message %q does not mention %q", name, ie.Msg, contains)
	}
}

func TestProcessAcceptsPNGAndJPEG(t *testing.T) {
	for name, data := range map[string][]byte{"png": testPNG(t, 200, 60), "jpeg": testJPEG(t, 200, 60)} {
		p, err := Process(KindLogoLight, data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Width != 200 || p.Height != 60 || !bytes.HasPrefix(p.PNG, pngMagic) {
			t.Fatalf("%s: %dx%d, png=%v", name, p.Width, p.Height, bytes.HasPrefix(p.PNG, pngMagic))
		}
		if _, err := png.Decode(bytes.NewReader(p.PNG)); err != nil {
			t.Fatalf("%s: stored image does not decode: %v", name, err)
		}
	}
}

func TestProcessRejects(t *testing.T) {
	wantImageError(t, "svg", KindLogoLight, []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), "SVG")
	wantImageError(t, "svg with xml prolog", KindLogoLight, []byte(`<?xml version="1.0"?><svg onload="alert(1)"/>`), "SVG")
	wantImageError(t, "html", KindLogoLight, []byte(`<html><script>alert(1)</script></html>`), "PNG and JPEG")
	wantImageError(t, "gif", KindLogoLight, []byte("GIF89a\x01\x00\x01\x00"), "PNG and JPEG")
	wantImageError(t, "empty", KindLogoLight, nil, "empty")
	wantImageError(t, "too many bytes", KindLogoLight, append(append([]byte{}, pngMagic...), make([]byte, MaxUploadBytes)...), "larger than")
	wantImageError(t, "truncated png", KindLogoLight, testPNG(t, 100, 40)[:60], "valid image")
	wantImageError(t, "unknown slot", "wallpaper", testPNG(t, 100, 40), "slot")
	wantImageError(t, "logo too wide", KindLogoLight, testPNG(t, 1201, 40), "too large")
	wantImageError(t, "logo too tall", KindLogoLight, testPNG(t, 300, 401), "too large")
	wantImageError(t, "logo too small", KindLogoLight, testPNG(t, 8, 8), "too small")
	wantImageError(t, "icon not square", KindIcon, testPNG(t, 128, 96), "square")
	wantImageError(t, "icon too small", KindIcon, testPNG(t, 32, 32), "too small")
	wantImageError(t, "favicon too large", KindFavicon, testPNG(t, 300, 300), "too large")
	// A text file renamed to .png is still just text.
	wantImageError(t, "text", KindLogoLight, []byte(strings.Repeat("hello ", 50)), "PNG and JPEG")
}

// TestProcessDecompressionBomb: a header that claims huge dimensions is refused before any pixel is allocated.
func TestProcessDecompressionBomb(t *testing.T) {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 60000)
	binary.BigEndian.PutUint32(ihdr[4:], 60000)
	ihdr[8], ihdr[9] = 8, 6
	var b bytes.Buffer
	b.Write(pngMagic)
	b.Write(chunk("IHDR", ihdr))
	b.Write(chunk("IEND", nil))
	wantImageError(t, "60000x60000", KindLogoLight, b.Bytes(), "too large")
}

// TestProcessStripsEverythingButPixels: metadata chunks, text and trailing bytes (a polyglot payload) do not survive.
func TestProcessStripsEverythingButPixels(t *testing.T) {
	plain := testPNG(t, 100, 40)
	idat := bytes.Index(plain, []byte("IDAT")) - 4
	secret := []byte("SECRET-GPS-AND-SCRIPT")
	var dirty bytes.Buffer
	dirty.Write(plain[:idat])
	dirty.Write(chunk("tEXt", append([]byte("Comment\x00"), secret...)))
	dirty.Write(chunk("eXIf", secret))
	dirty.Write(plain[idat:])
	dirty.WriteString("<script>alert(1)</script>") // appended after IEND
	dirty.Write(secret)

	p, err := Process(KindLogoLight, dirty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range [][]byte{secret, []byte("<script"), []byte("tEXt"), []byte("eXIf")} {
		if bytes.Contains(p.PNG, needle) {
			t.Errorf("the stored image still contains %q", needle)
		}
	}
	// Anything past IEND is gone: the output ends exactly at the end of its IEND chunk.
	if !bytes.HasSuffix(p.PNG, chunk("IEND", nil)) {
		t.Error("the stored image has bytes after IEND")
	}
	// The pixels are the same.
	a, _ := png.Decode(bytes.NewReader(plain))
	c, _ := png.Decode(bytes.NewReader(p.PNG))
	if a.At(10, 10) != c.At(10, 10) || a.At(99, 39) != c.At(99, 39) {
		t.Error("the re-encoded image differs in pixels")
	}
}

func TestProcessIgnoresClaimedType(t *testing.T) {
	// JPEG bytes are recognised as JPEG whatever the caller says, and come out as PNG.
	p, err := Process(KindReportLogo, testJPEG(t, 120, 50))
	if err != nil || !bytes.HasPrefix(p.PNG, pngMagic) {
		t.Fatalf("%v", err)
	}
}

func FuzzProcess(f *testing.F) {
	f.Add(testPNG(f, 64, 32))
	f.Add(testJPEG(f, 64, 32))
	f.Add([]byte("<svg onload=alert(1)>"))
	f.Add(append([]byte{}, pngMagic...))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Process(KindLogoLight, data)
		if err != nil {
			if _, ok := err.(*ImageError); !ok {
				t.Fatalf("an unexpected internal error for hostile input: %v", err)
			}
			return
		}
		if !bytes.HasPrefix(p.PNG, pngMagic) || len(p.PNG) > MaxStoredBytes || p.Width > 1200 || p.Height > 400 {
			t.Fatalf("accepted an image outside the limits: %dx%d, %d bytes", p.Width, p.Height, len(p.PNG))
		}
	})
}
