//go:build !windows || !amd64

package reflective

import "errors"

var errUnsupported = errors.New("reflective: not supported on this platform")

func Load(payload []byte, opts Options) (*Module, error) {
	return nil, errUnsupported
}

func Call(mod *Module, name string) (uintptr, error) {
	return 0, errUnsupported
}

func LoadAndRun(payload []byte, fn string, opts Options) (uintptr, *Module, error) {
	return 0, nil, errUnsupported
}

func TestPayload(kind string) ([]byte, error) {
	return nil, errUnsupported
}
