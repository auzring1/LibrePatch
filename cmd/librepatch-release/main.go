// Command librepatch-release is the vendor-side tool that creates and checks signed agent releases.
//
//	librepatch-release keygen --out release.key            create an Ed25519 release key pair (writes release.key and release.pub)
//	librepatch-release sign --key release.key --exe agent.exe --version 1.2.3 [--os windows --arch amd64]
//	                     [--min-version V] [--rollback-from V,...] [--authenticode-subject CN] [--notes TEXT] --out agent-1.2.3.lprel
//	librepatch-release manifest --exe agent.exe --version 1.2.3 ... --out manifest.json     (for an HSM/KMS signer)
//	librepatch-release attach --manifest manifest.json --signature sig.bin (--pub HEX|FILE | --key-id ID) --out agent-1.2.3.lprel
//	librepatch-release tosign --manifest manifest.json --out tosign.bin     (the exact bytes a KMS must sign: domain prefix + manifest)
//	librepatch-release sign-bytes --key release.key --in tosign.bin --out sig.bin   (stand-in for the KMS, throw-away keys only)
//	librepatch-release verify --bundle agent-1.2.3.lprel --exe agent.exe --pub release.pub
//	librepatch-release overlay-sign --key overlay.key --in overlay.json --out clinic.lpov     sign a catalog overlay (docs/RUNBOOK.md, catalog overlays)
//	librepatch-release overlay-verify --bundle clinic.lpov --pub overlay.pub                  check one and print what it contains
//
// The private key never leaves the signer: with a cloud KMS use `manifest`, sign the bytes
// with "librepatch/release/v1\x00" prepended, then `attach`. This tool is not part of the shipped
// product; it runs in the vendor's release pipeline (docs/RUNBOOK.md, release signing).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/auzring1/librepatch/internal/shared/overlay"
	"github.com/auzring1/librepatch/internal/shared/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "manifest":
		err = manifestCmd(os.Args[2:])
	case "attach":
		err = attach(os.Args[2:])
	case "tosign":
		err = toSign(os.Args[2:])
	case "sign-bytes":
		err = signBytes(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "overlay-sign":
		err = overlaySign(os.Args[2:])
	case "overlay-verify":
		err = overlayVerify(os.Args[2:])
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, "usage: librepatch-release keygen|sign|manifest|attach|tosign|sign-bytes|verify|overlay-sign|overlay-verify (see the package comment)\n")
}

func keygen(args []string) error {
	fl := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fl.String("out", "release.key", "private key file (the public key is written next to it as .pub)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeNew(*out, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	pubPath := strings.TrimSuffix(*out, ".key") + ".pub"
	if err := writeNew(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil { // #nosec G306 -- public key
		return err
	}
	fmt.Printf("private key: %s (keep it offline or in a KMS)\npublic key:  %s\nkey id:      %s\npublic key hex (for -ldflags): %s\n", *out, pubPath, release.KeyID(pub), hex.EncodeToString(pub))
	return nil
}

// writeNew creates a file and refuses to overwrite an existing one (a key must never be replaced silently).
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode) // #nosec G304 -- operator-chosen output path
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

type common struct {
	exe, version, goos, goarch, minV, rollback, subject, notes string
	releasedAt                                                 int64
}

func (c *common) flags(fl *flag.FlagSet) {
	fl.StringVar(&c.exe, "exe", "", "the agent binary")
	fl.StringVar(&c.version, "version", "", "its version (must equal the -X Version the binary was built with)")
	fl.StringVar(&c.goos, "os", "windows", "operating system")
	fl.StringVar(&c.goarch, "arch", "amd64", "architecture")
	fl.StringVar(&c.minV, "min-version", "", "oldest agent version allowed to update directly")
	fl.StringVar(&c.rollback, "rollback-from", "", "comma-separated versions from which this older release may be installed")
	fl.StringVar(&c.subject, "authenticode-subject", "", "certificate subject the binary must be Authenticode-signed with")
	fl.StringVar(&c.notes, "notes", "", "release notes (short)")
	fl.Int64Var(&c.releasedAt, "released-at", 0, "release time, unix seconds (default: now; pipelines pass SOURCE_DATE_EPOCH so the manifest is reproducible)")
}

func (c *common) manifest() ([]byte, error) {
	if c.exe == "" || c.version == "" {
		return nil, errors.New("--exe and --version are required")
	}
	f, err := os.Open(c.exe) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	at := c.releasedAt
	if at == 0 {
		at = time.Now().Unix()
	}
	m := &release.Manifest{Format: 1, Product: release.Product, Version: c.version, OS: c.goos, Arch: c.goarch,
		SHA256: hex.EncodeToString(h.Sum(nil)), Size: uint64(n), ReleasedAt: at, // #nosec G115 -- non-negative
		MinVersion: c.minV, AuthenticodeSubject: c.subject, Notes: c.notes}
	for _, v := range strings.Split(c.rollback, ",") {
		if v = strings.TrimSpace(v); v != "" {
			m.RollbackFrom = append(m.RollbackFrom, v)
		}
	}
	return release.Marshal(m)
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-chosen path
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the key file must hold a 32-byte Ed25519 seed in hex")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func sign(args []string) error {
	fl := flag.NewFlagSet("sign", flag.ContinueOnError)
	var c common
	c.flags(fl)
	keyPath := fl.String("key", "", "private key file")
	out := fl.String("out", "", "bundle to write (.lprel)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *out == "" {
		return errors.New("--key and --out are required")
	}
	priv, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	mb, err := c.manifest()
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return writeBundle(*out, mb, release.Sign(priv, mb), release.KeyID(pub))
}

func manifestCmd(args []string) error {
	fl := flag.NewFlagSet("manifest", flag.ContinueOnError)
	var c common
	c.flags(fl)
	out := fl.String("out", "manifest.json", "manifest file to write")
	if err := fl.Parse(args); err != nil {
		return err
	}
	mb, err := c.manifest()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, mb, 0o644); err != nil { // #nosec G306 -- not secret
		return err
	}
	fmt.Printf("wrote %s; sign the bytes of this file after prepending %q, then run `attach`\n", *out, release.Domain)
	return nil
}

func attach(args []string) error {
	fl := flag.NewFlagSet("attach", flag.ContinueOnError)
	mf := fl.String("manifest", "", "manifest file")
	sf := fl.String("signature", "", "raw 64-byte Ed25519 signature file")
	keyID := fl.String("key-id", "", "key id (hex) of the signing key")
	pub := fl.String("pub", "", "the signing key's public key (hex, or a file holding it): the key id is derived from it and the signature is verified before the bundle is written")
	out := fl.String("out", "", "bundle to write (.lprel)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	mb, err := os.ReadFile(*mf) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(*sf) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	if *pub != "" {
		hexKey := *pub
		if b, err := os.ReadFile(*pub); err == nil { // #nosec G304 -- operator-chosen path
			hexKey = string(b)
		}
		keys, err := release.ParseKeys(strings.TrimSpace(hexKey))
		if err != nil || len(keys) != 1 {
			return errors.New("--pub must hold exactly one Ed25519 public key in hex")
		}
		if _, err := release.Verify(keys, mb, sig, ""); err != nil {
			return fmt.Errorf("the signature does not verify under --pub: %w", err)
		}
		*keyID = release.KeyID(keys[0])
	}
	if *keyID == "" {
		return errors.New("--key-id or --pub is required")
	}
	return writeBundle(*out, mb, sig, *keyID)
}

// toSign writes the exact byte string the release key signs: the domain prefix and the manifest.
// A KMS/HSM signs this file as-is (pure Ed25519, no pre-hash); `attach` then packs the signature.
func toSign(args []string) error {
	fl := flag.NewFlagSet("tosign", flag.ContinueOnError)
	mf := fl.String("manifest", "", "manifest file made by `manifest`")
	out := fl.String("out", "tosign.bin", "file to write")
	if err := fl.Parse(args); err != nil {
		return err
	}
	mb, err := os.ReadFile(*mf) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	if _, err := release.ParseUnverified(mb); err != nil { // refuse to sign a manifest agents would reject
		return err
	}
	sb := release.SignedBytes(mb)
	if err := os.WriteFile(*out, sb, 0o644); err != nil { // #nosec G306 G703 -- not secret; operator-chosen path
		return err
	}
	fmt.Printf("wrote %s (%d bytes); sign it with Ed25519 as-is, then run `attach`\n", *out, len(sb))
	return nil
}

// signBytes signs a tosign file with a key file. It exists so the pipeline's KMS step can be rehearsed
// with a throw-away key (scripts/release-dryrun.sh); production signatures come from the KMS/HSM.
func signBytes(args []string) error {
	fl := flag.NewFlagSet("sign-bytes", flag.ContinueOnError)
	keyPath := fl.String("key", "", "private key file")
	in := fl.String("in", "", "tosign file")
	out := fl.String("out", "", "raw 64-byte signature to write")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" || *out == "" {
		return errors.New("--key, --in and --out are required")
	}
	priv, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(data), release.Domain) {
		return errors.New("the input does not start with the release domain prefix; make it with `tosign`")
	}
	return os.WriteFile(*out, ed25519.Sign(priv, data), 0o644) // #nosec G306 G703 -- a signature is public; operator-chosen path
}

func writeBundle(path string, manifest, sig []byte, keyID string) error {
	b, err := release.EncodeBundle(&release.Bundle{Manifest: manifest, Signature: sig, KeyID: keyID})
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil { // #nosec G306 -- not secret
		return err
	}
	fmt.Println("wrote", path)
	return nil
}

func verify(args []string) error {
	fl := flag.NewFlagSet("verify", flag.ContinueOnError)
	bp := fl.String("bundle", "", "bundle (.lprel)")
	exe := fl.String("exe", "", "binary to check against the manifest (optional)")
	pubf := fl.String("pub", "", "public key file (hex)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	data, err := os.ReadFile(*bp) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	b, err := release.DecodeBundle(data)
	if err != nil {
		return err
	}
	pb, err := os.ReadFile(*pubf) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	keys, err := release.ParseKeys(string(pb))
	if err != nil {
		return err
	}
	m, err := release.Verify(keys, b.Manifest, b.Signature, b.KeyID)
	if err != nil {
		return err
	}
	if *exe != "" {
		f, err := os.Open(*exe) // #nosec G304 -- operator-chosen path
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != m.SHA256 || uint64(n) != m.Size { // #nosec G115 -- non-negative
			return errors.New("the binary does not match the manifest")
		}
	}
	fmt.Printf("OK: %s %s %s/%s sha256 %s\n", release.Product, m.Version, m.OS, m.Arch, m.SHA256)
	return nil
}

// overlaySign signs a catalog overlay document. The key is any Ed25519 key made with keygen; use a separate one for
// overlays, never the agent release key.
func overlaySign(args []string) error {
	fl := flag.NewFlagSet("overlay-sign", flag.ContinueOnError)
	keyPath := fl.String("key", "", "private key file (from keygen)")
	in := fl.String("in", "", "the overlay document (JSON)")
	out := fl.String("out", "", "the signed file to write (.lpov)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" || *out == "" {
		return errors.New("--key, --in and --out are required")
	}
	priv, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	doc, err := os.ReadFile(*in) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	b, err := overlay.Sign(priv, doc)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil { // #nosec G306 -- a signed public document
		return err
	}
	fmt.Printf("signed %s\nkey id: %s\npublic key hex (enter this in the console): %s\n", *out, b.KeyID, hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return nil
}

func overlayVerify(args []string) error {
	fl := flag.NewFlagSet("overlay-verify", flag.ContinueOnError)
	bundle := fl.String("bundle", "", "the signed overlay file (.lpov)")
	pubArg := fl.String("pub", "", "the public key, as a file or as hex")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *bundle == "" || *pubArg == "" {
		return errors.New("--bundle and --pub are required")
	}
	pubText := *pubArg
	if b, err := os.ReadFile(*pubArg); err == nil { // #nosec G304 -- operator-chosen path
		pubText = string(b)
	}
	pub, err := overlay.ParsePublicKey(pubText)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*bundle) // #nosec G304 -- operator-chosen path
	if err != nil {
		return err
	}
	doc, _, err := overlay.Verify(raw, pub)
	if err != nil {
		return err
	}
	verified := 0
	for _, p := range doc.Packages {
		if p.Verified {
			verified++
		}
	}
	fmt.Printf("OK: %q version %d, %d packages (%d marked verified), key id %s\n", doc.Name, doc.Version, len(doc.Packages), verified, overlay.KeyID(pub))
	return nil
}
