//go:build !(windows && amd64)

package securityctl

type funcPatch struct {
	addr  uintptr
	orig  []byte
	patch []byte
}
