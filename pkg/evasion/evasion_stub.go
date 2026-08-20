//go:build !(windows && amd64)

// Package evasion is a no-op on platforms without the indirect syscall
// machinery; the inject build tag is only meaningful on windows/amd64.
package evasion
