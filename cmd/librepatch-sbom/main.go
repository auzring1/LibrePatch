// Command librepatch-sbom writes and checks CycloneDX 1.5 JSON SBOMs for release artifacts. It is a
// build-pipeline tool, not part of the shipped product.
//
//	librepatch-sbom go  --binary librepatch-agent.exe --version v1.2.3 --epoch 1700000000 --out agent.cdx.json [--name librepatch-agent]
//	librepatch-sbom npm --lock web/package-lock.json --version v1.2.3 --epoch 1700000000 --out web.cdx.json
//	librepatch-sbom check file.cdx.json [...]
//
// The timestamp is the --epoch value (the release commit time, SOURCE_DATE_EPOCH), never the wall clock,
// so a reproducible build gives a byte-identical SBOM.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/auzring1/librepatch/internal/sbom"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "go":
		err = goCmd(os.Args[2:])
	case "npm":
		err = npmCmd(os.Args[2:])
	case "check":
		err = checkCmd(os.Args[2:])
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
	fmt.Fprint(os.Stderr, "usage: librepatch-sbom go|npm|check (see the package comment)\n")
}

// epochFlag defaults to SOURCE_DATE_EPOCH.
func epochFlag(fl *flag.FlagSet) *int64 {
	def := int64(0)
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			def = v
		}
	}
	return fl.Int64("epoch", def, "document timestamp, unix seconds (default: $SOURCE_DATE_EPOCH)")
}

func goCmd(args []string) error {
	fl := flag.NewFlagSet("go", flag.ContinueOnError)
	bin := fl.String("binary", "", "Go binary to describe (any GOOS/GOARCH)")
	version := fl.String("version", "", "release version of the product")
	name := fl.String("name", "", "component name (default: the binary's file name)")
	out := fl.String("out", "", "SBOM file to write")
	epoch := epochFlag(fl)
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *bin == "" || *out == "" || *version == "" {
		return fmt.Errorf("--binary, --version and --out are required")
	}
	if *epoch <= 0 {
		return fmt.Errorf("--epoch (or SOURCE_DATE_EPOCH) is required: the SBOM must not depend on the wall clock")
	}
	doc, err := sbom.FromGoBinary(*bin, sbom.GoOptions{Version: *version, Name: *name, Epoch: *epoch})
	if err != nil {
		return err
	}
	return write(*out, doc)
}

func npmCmd(args []string) error {
	fl := flag.NewFlagSet("npm", flag.ContinueOnError)
	lock := fl.String("lock", "web/package-lock.json", "package-lock.json (lockfile v2 or v3)")
	version := fl.String("version", "", "release version of the bundle")
	out := fl.String("out", "", "SBOM file to write")
	epoch := epochFlag(fl)
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *out == "" || *version == "" {
		return fmt.Errorf("--version and --out are required")
	}
	if *epoch <= 0 {
		return fmt.Errorf("--epoch (or SOURCE_DATE_EPOCH) is required: the SBOM must not depend on the wall clock")
	}
	doc, err := sbom.FromNPMLock(*lock, sbom.NPMOptions{Version: *version, Epoch: *epoch})
	if err != nil {
		return err
	}
	return write(*out, doc)
}

func checkCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("check needs at least one file")
	}
	for _, p := range args {
		doc, err := os.ReadFile(p) // #nosec G304 G703 -- operator-chosen path
		if err != nil {
			return err
		}
		if err := sbom.Check(doc); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		fmt.Printf("OK: %s is a well-formed CycloneDX %s document\n", p, sbom.SpecVersion)
	}
	return nil
}

func write(path string, doc []byte) error {
	if err := sbom.Check(doc); err != nil { // never write a document our own checker rejects
		return fmt.Errorf("internal error, generated SBOM is malformed: %w", err)
	}
	if err := os.WriteFile(path, append(doc, '\n'), 0o644); err != nil { // #nosec G306 -- not secret
		return err
	}
	fmt.Println("wrote", path)
	return nil
}
