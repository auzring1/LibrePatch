package catalog

import (
	"encoding/json"
	"errors"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/installer"
)

// BuildInput selects what to build an install body from.
type BuildInput struct {
	Pkg      dbq.CatalogPackage
	Ver      dbq.CatalogVersion
	Inst     dbq.CatalogInstaller
	Override *dbq.PackageOverride
	Scope    string // machine | user (the scope of this job)
	Update   bool
}

var typeEnum = map[string]agentv1.InstallerType{
	"msi": agentv1.InstallerType_INSTALLER_TYPE_MSI, "msix": agentv1.InstallerType_INSTALLER_TYPE_MSIX,
	"inno": agentv1.InstallerType_INSTALLER_TYPE_INNO, "nsis": agentv1.InstallerType_INSTALLER_TYPE_NSIS,
	"burn": agentv1.InstallerType_INSTALLER_TYPE_BURN, "exe": agentv1.InstallerType_INSTALLER_TYPE_EXE,
	"portable": agentv1.InstallerType_INSTALLER_TYPE_PORTABLE, "zip": agentv1.InstallerType_INSTALLER_TYPE_ZIP,
}

var kindEnum = map[string]agentv1.DetectionKind{
	"msi": agentv1.DetectionKind_DETECTION_KIND_MSI_PRODUCT, "registry": agentv1.DetectionKind_DETECTION_KIND_REGISTRY,
	"file": agentv1.DetectionKind_DETECTION_KIND_FILE, "appx": agentv1.DetectionKind_DETECTION_KIND_APPX,
}

// DetectionProto converts stored rules.
func DetectionProto(ds []Detection) []*agentv1.Detection {
	out := make([]*agentv1.Detection, 0, len(ds))
	for _, d := range ds {
		cmp := agentv1.VersionCmp_VERSION_CMP_UNSPECIFIED
		switch d.Cmp {
		case "eq":
			cmp = agentv1.VersionCmp_VERSION_CMP_EQ
		case "ge":
			cmp = agentv1.VersionCmp_VERSION_CMP_GE
		}
		out = append(out, &agentv1.Detection{Kind: kindEnum[d.Kind], Key: d.Key, ValueName: d.ValueName, Version: d.Version, Cmp: cmp})
	}
	return out
}

// BuildInstallBody assembles the signed-job body for one installer. Arguments:
// an override's silent_args replace the manifest's switches; for generic EXE
// installers the manifest's silent switches are the base, for the other types
// the agent supplies the silent switches and only extras are listed here.
func BuildInstallBody(in BuildInput) (*agentv1.InstallBody, error) {
	i := in.Inst
	if i.Unsupported != "" {
		return nil, errors.New("installer is not deployable: " + i.Unsupported)
	}
	var sw struct {
		Silent []string `json:"silent"`
		Custom []string `json:"custom"`
	}
	_ = json.Unmarshal(i.Switches, &sw)
	args := append(append([]string{}, sw.Silent...), sw.Custom...)
	if in.Override != nil && len(in.Override.SilentArgs) > 0 {
		args = append([]string{}, in.Override.SilentArgs...)
	}
	if err := installer.ValidateArgs(args); err != nil {
		return nil, err
	}
	t := typeEnum[i.InstallerType]
	// The agent accepts only a GUID here. Manifests of Inno, NSIS and similar installers give the name of their uninstall
	// key instead (for example "Folge" or "{GUID}_is1"); that name is what the detection rule checks, so it is not sent.
	productCode := ""
	if guidRe.MatchString(i.ProductCode) {
		productCode = i.ProductCode
	}
	inst := &agentv1.Installer{Type: t, NestedType: typeEnum[i.NestedType], NestedPath: i.NestedPath, Sha256: i.Sha256,
		Size: uint64(i.Size), FileName: i.FileName, Args: args, ProductCode: productCode, // #nosec G115 -- size is non-negative
		CodeMap: map[int32]agentv1.JobOutcome{}}
	if i.SignerSubject != "" {
		inst.SignerPin = &agentv1.SignerPin{Subject: i.SignerSubject}
	}
	if i.UsesContentBlob {
		inst.Sources = []*agentv1.ContentSource{{Kind: agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_SERVER}}
	} else {
		inst.Sources = []*agentv1.ContentSource{{Kind: agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_VENDOR, Url: i.Url}}
	}
	inst.SuccessCodes = append(inst.SuccessCodes, i.SuccessCodes...)
	for _, c := range i.ExpectedCodes { // "already installed" style codes count as success
		inst.CodeMap[c] = agentv1.JobOutcome_JOB_OUTCOME_SUCCESS
	}
	var det []Detection
	_ = json.Unmarshal(i.Detection, &det)
	if in.Override != nil {
		var extra []Detection
		_ = json.Unmarshal(in.Override.ExtraDetection, &extra)
		det = append(det, extra...)
	}
	sc := agentv1.InstallScope_INSTALL_SCOPE_MACHINE
	if in.Scope == "user" {
		sc = agentv1.InstallScope_INSTALL_SCOPE_USER
	}
	body := &agentv1.InstallBody{PackageId: in.Pkg.Identifier, Name: in.Pkg.Name, Version: in.Ver.Version, Scope: sc, Installer: inst,
		Detection: DetectionProto(det), TimeoutS: 3600, MaxRetries: 1, RetryBackoffS: 120, Reboot: agentv1.RebootAllow_REBOOT_ALLOW_NEVER, Update: in.Update}
	if i.InstallerType == "msi" || i.NestedType == "msi" {
		body.MaxRetries, body.RetryBackoffS = 3, 120 // 1618: another installation is in progress
	}
	return body, nil
}
