package keychain

import (
	"os"
	"os/exec"
	"runtime"
)

const (
	StatusAvailable   = "available"
	StatusUnavailable = "unavailable"
)

// Detector contains injectable platform probes so doctor output can be tested
// without requiring a real desktop keychain session.
type Detector struct {
	GOOS     string
	Getenv   func(string) string
	LookPath func(string) (string, error)
}

// Result describes whether an OS keychain backend appears usable.
type Result struct {
	Status  string
	Backend string
	Detail  string
}

// Detect reports best-effort keychain availability without reading or writing
// token key material.
func Detect(detector Detector) Result {
	if detector.GOOS == "" {
		detector.GOOS = runtime.GOOS
	}
	if detector.Getenv == nil {
		detector.Getenv = os.Getenv
	}
	if detector.LookPath == nil {
		detector.LookPath = exec.LookPath
	}

	switch detector.GOOS {
	case "darwin":
		if _, err := detector.LookPath("security"); err != nil {
			return Result{Status: StatusUnavailable, Backend: "macOS Keychain", Detail: "security tool not found"}
		}
		return Result{Status: StatusAvailable, Backend: "macOS Keychain", Detail: "security tool found"}
	case "linux":
		if detector.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
			return Result{Status: StatusUnavailable, Backend: "Secret Service", Detail: "DBus session not found"}
		}
		return Result{Status: StatusAvailable, Backend: "Secret Service", Detail: "DBus session found"}
	default:
		return Result{Status: StatusUnavailable, Backend: "OS keychain", Detail: detector.GOOS + " backend not implemented"}
	}
}
