package main

func shouldLogAccessForCommand(command string) bool {
	switch command {
	case "get", "list", "export", "search", "stats":
		return false
	default:
		return true
	}
}

func shouldMirrorMainVaultToShared(command string) bool {
	switch command {
	case "set", "delete", "clear", "import":
		return true
	default:
		return false
	}
}
