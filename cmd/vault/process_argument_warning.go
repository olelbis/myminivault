package main

import (
	"fmt"
	"os"
)

func warnProcessArgumentSecret(form, saferAlternative string) {
	fmt.Fprintf(os.Stderr, "⚠️  %s places secret material in process arguments; prefer %s for real secrets.\n", form, saferAlternative)
}
