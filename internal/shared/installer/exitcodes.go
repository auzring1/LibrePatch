package installer

// Resolve maps an installer exit code to an Outcome. Precedence (ARCHITECTURE
// §7.3): explicit code map, success codes, then per-type defaults.
func Resolve(t Type, code int, success []int, codeMap map[int]Outcome) Outcome {
	if o, ok := codeMap[code]; ok && o >= Success && o <= Failed {
		return o
	}
	for _, c := range success {
		if c == code {
			return Success
		}
	}
	switch code {
	case 0:
		return Success
	case 3010, 1641: // reboot required / initiated (MSI, WiX Burn, most EXE)
		return RebootRequired
	case 1618: // ERROR_INSTALL_ALREADY_RUNNING
		if t == MSI {
			return Retryable
		}
	case 1638: // ERROR_PRODUCT_VERSION: another version installed; not a failure of the target state for MSI
		if t == MSI {
			return Failed
		}
	}
	return Failed
}

// MSIUninstallCommand returns the msiexec vector that removes a product.
func MSIUninstallCommand(productCode, logPath string) (string, []string) {
	args := []string{"/x", productCode, "/qn", "/norestart"}
	if logPath != "" {
		args = append(args, "/l*v", logPath)
	}
	return "msiexec.exe", args
}
