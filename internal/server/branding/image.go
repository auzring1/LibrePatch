package branding

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"image/png"
)

// Asset kinds. Every image is stored as a PNG that this server produced itself.
const (
	KindLogoLight  = "logo_light"  // logo for light backgrounds
	KindLogoDark   = "logo_dark"   // logo for dark backgrounds
	KindIcon       = "icon"        // square icon
	KindFavicon    = "favicon"     // browser tab icon
	KindReportLogo = "report_logo" // logo on exported reports and emails
)

// Kinds lists the valid asset kinds in display order.
var Kinds = []string{KindLogoLight, KindLogoDark, KindIcon, KindFavicon, KindReportLogo}

// ValidKind reports whether kind names an image slot.
func ValidKind(kind string) bool {
	for _, k := range Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Upload limits. The raw upload and the stored (re-encoded) image are both capped; the decoded dimensions are
// checked from the header before any pixel is decoded, so a small file cannot make the server allocate much.
const (
	MaxUploadBytes = 512 << 10
	MaxStoredBytes = 512 << 10
)

type bounds struct {
	minW, minH, maxW, maxH int
	square                 bool
}

func limits(kind string) bounds {
	switch kind {
	case KindIcon:
		return bounds{64, 64, 512, 512, true}
	case KindFavicon:
		return bounds{16, 16, 256, 256, true}
	default: // logos
		return bounds{16, 16, 1200, 400, false}
	}
}

// ImageError is a rejected upload; the message is safe to show to the administrator.
type ImageError struct{ Msg string }

func (e *ImageError) Error() string { return e.Msg }

func reject(format string, a ...any) error { return &ImageError{Msg: fmt.Sprintf(format, a...)} }

// Processed is a validated image, re-encoded as PNG.
type Processed struct {
	PNG           []byte
	Width, Height int
	SHA256        [32]byte
}

var (
	pngMagic  = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	jpegMagic = []byte{0xff, 0xd8, 0xff}
)

// Process validates an uploaded image for a slot and returns it re-encoded as PNG. Only PNG and JPEG are
// accepted, recognised by their content and not by the name or the declared type. SVG (and anything else that can
// carry script) is refused. Decoding and re-encoding drops every ancillary chunk, EXIF block, comment and any bytes
// appended after the image, so what is stored and served is pixels only.
func Process(kind string, data []byte) (Processed, error) {
	if !ValidKind(kind) {
		return Processed{}, reject("Unknown image slot %q.", kind)
	}
	if len(data) == 0 {
		return Processed{}, reject("The image is empty.")
	}
	if len(data) > MaxUploadBytes {
		return Processed{}, reject("The image is larger than %d KiB.", MaxUploadBytes>>10)
	}
	var cfg image.Config
	var err error
	var isJPEG bool
	switch {
	case bytes.HasPrefix(data, pngMagic):
		cfg, err = png.DecodeConfig(bytes.NewReader(data))
	case bytes.HasPrefix(data, jpegMagic):
		isJPEG = true
		cfg, err = jpeg.DecodeConfig(bytes.NewReader(data))
	default:
		head := bytes.ToLower(bytes.TrimSpace(data[:min(len(data), 512)]))
		if bytes.Contains(head, []byte("<svg")) || bytes.HasPrefix(head, []byte("<?xml")) || bytes.HasPrefix(head, []byte("<!doctype")) {
			return Processed{}, reject("SVG images are not accepted (they can carry scripts). Use a PNG or JPEG.")
		}
		return Processed{}, reject("Only PNG and JPEG images are accepted.")
	}
	if err != nil {
		return Processed{}, reject("The image could not be read as a valid image.")
	}
	b := limits(kind)
	switch {
	case cfg.Width < b.minW || cfg.Height < b.minH:
		return Processed{}, reject("The image is too small: at least %d × %d pixels.", b.minW, b.minH)
	case cfg.Width > b.maxW || cfg.Height > b.maxH:
		return Processed{}, reject("The image is too large: at most %d × %d pixels for this slot (it is %d × %d).", b.maxW, b.maxH, cfg.Width, cfg.Height)
	case b.square && cfg.Width != cfg.Height:
		return Processed{}, reject("This slot needs a square image (it is %d × %d).", cfg.Width, cfg.Height)
	}
	var src image.Image
	if isJPEG {
		src, err = jpeg.Decode(bytes.NewReader(data))
	} else {
		src, err = png.Decode(bytes.NewReader(data))
	}
	if err != nil {
		return Processed{}, reject("The image could not be read as a valid image.")
	}
	rgba := image.NewNRGBA(image.Rect(0, 0, cfg.Width, cfg.Height))
	draw.Draw(rgba, rgba.Bounds(), src, src.Bounds().Min, draw.Src)
	var out bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&out, rgba); err != nil {
		return Processed{}, errors.New("branding: re-encode: " + err.Error())
	}
	if out.Len() > MaxStoredBytes {
		return Processed{}, reject("The image is too complex: it is larger than %d KiB once cleaned. Use a simpler or smaller image.", MaxStoredBytes>>10)
	}
	p := Processed{PNG: out.Bytes(), Width: cfg.Width, Height: cfg.Height}
	p.SHA256 = sha256.Sum256(p.PNG)
	return p, nil
}
