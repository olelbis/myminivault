//go:build !(darwin || linux || freebsd || openbsd || netbsd)

package main

func disableCoreDumps() {}
