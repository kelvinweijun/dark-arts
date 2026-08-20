//go:build !(windows && amd64) && inject

package inject

import "errors"

var ErrUnsupported = errors.New("inject: shellcode injection not supported on this platform")

func SelfRun(sc []byte) (*Result, error) {
	return nil, ErrUnsupported
}

func RemoteRun(sc []byte, pid uint32) (*Result, error) {
	return nil, ErrUnsupported
}
