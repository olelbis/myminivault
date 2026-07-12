package main

import (
	"strings"
	"testing"
)

func TestFormatDisplayValuePrintsLongRecoveryKeyOnSingleLine(t *testing.T) {
	value := "4BIPE-YZFZA-3MWHX-2A6JN-TJJ64-OMH6M-V5YMX-EXRL5-HQNAX-ZROVT-PQ"

	output := formatDisplayValue(value)
	if output != "  "+value+"\n" {
		t.Fatalf("output = %q, want single-line value", output)
	}
}

func TestFormatDisplayValuePrintsLongTokenOnSingleLine(t *testing.T) {
	value := strings.Repeat("A", terminalBoxContentWidth+8)

	output := formatDisplayValue(value)
	if output != "  "+value+"\n" {
		t.Fatalf("output = %q, want single-line value", output)
	}
}

func TestFormatDisplayValueKeepsBoxForShortValues(t *testing.T) {
	output := formatDisplayValue("SHORT")
	if !strings.Contains(output, "│ SHORT") {
		t.Fatalf("short value should stay boxed:\n%s", output)
	}
	if !strings.Contains(output, "┌") || !strings.Contains(output, "└") {
		t.Fatalf("short value box missing borders:\n%s", output)
	}
}
