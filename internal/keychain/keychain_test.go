package keychain

import (
	"errors"
	"testing"
)

func TestDetectDarwinAvailable(t *testing.T) {
	result := Detect(Detector{
		GOOS: "darwin",
		LookPath: func(string) (string, error) {
			return "/usr/bin/security", nil
		},
	})

	if result.Status != StatusAvailable || result.Backend != "macOS Keychain" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectDarwinUnavailableWithoutSecurityTool(t *testing.T) {
	result := Detect(Detector{
		GOOS: "darwin",
		LookPath: func(string) (string, error) {
			return "", errors.New("not found")
		},
	})

	if result.Status != StatusUnavailable || result.Detail != "security tool not found" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectLinuxAvailableWithDBusSession(t *testing.T) {
	result := Detect(Detector{
		GOOS: "linux",
		Getenv: func(name string) string {
			if name == "DBUS_SESSION_BUS_ADDRESS" {
				return "unix:path=/run/user/1000/bus"
			}
			return ""
		},
	})

	if result.Status != StatusAvailable || result.Backend != "Secret Service" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectLinuxUnavailableWithoutDBusSession(t *testing.T) {
	result := Detect(Detector{
		GOOS: "linux",
		Getenv: func(string) string {
			return ""
		},
	})

	if result.Status != StatusUnavailable || result.Detail != "DBus session not found" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDetectUnsupportedPlatform(t *testing.T) {
	result := Detect(Detector{GOOS: "plan9"})

	if result.Status != StatusUnavailable || result.Backend != "OS keychain" {
		t.Fatalf("result = %+v", result)
	}
}
