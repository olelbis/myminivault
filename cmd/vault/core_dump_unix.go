//go:build darwin || linux || freebsd || openbsd || netbsd

package main

import "syscall"

func disableCoreDumps() {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &limit); err != nil {
		return
	}
	limit.Cur = 0
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &limit)
}
