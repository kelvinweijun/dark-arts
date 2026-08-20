//go:build windows

package beacon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"syscall"
	"unsafe"
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutex = kernel32.NewProc("CreateMutexW")
)

func acquireInstanceLock(sid string) (func(), error) {
	sum := sha256.Sum256([]byte(sid))
	name, err := syscall.UTF16PtrFromString(`Local\DarkArts-` + hex.EncodeToString(sum[:8]))
	if err != nil {
		return nil, err
	}
	h, _, callErr := procCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(name)))
	handle := syscall.Handle(h)
	if handle == 0 {
		return nil, errors.New("beacon: create mutex failed")
	}
	if callErr == syscall.Errno(183) {
		syscall.CloseHandle(handle)
		return nil, errors.New("beacon: another instance is already running for this session")
	}
	return func() { syscall.CloseHandle(handle) }, nil
}
