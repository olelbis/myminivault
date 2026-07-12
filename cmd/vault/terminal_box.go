// Code split from myminivault.go; behavior intentionally unchanged.
package main

import (
	"fmt"
	"strings"
)

const terminalBoxContentWidth = 43

func printBoxedValue(value string) {
	fmt.Print(formatDisplayValue(value))
}

func formatDisplayValue(value string) string {
	if len(value) > terminalBoxContentWidth {
		return fmt.Sprintf("  %s\n", value)
	}
	return formatBoxedValue(value)
}

func formatBoxedValue(value string) string {
	var builder strings.Builder
	border := strings.Repeat("─", terminalBoxContentWidth+2)
	builder.WriteString("┌")
	builder.WriteString(border)
	builder.WriteString("┐\n")
	builder.WriteString("│ ")
	builder.WriteString(value)
	builder.WriteString(strings.Repeat(" ", terminalBoxContentWidth-len(value)))
	builder.WriteString(" │\n")
	builder.WriteString("└")
	builder.WriteString(border)
	builder.WriteString("┘\n")
	return builder.String()
}
