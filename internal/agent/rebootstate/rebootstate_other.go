//go:build !windows

package rebootstate

// Check reports nothing off Windows (the Linux test build has its own marker in the hardware collector).
func Check() State { return State{} }
