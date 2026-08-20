package beacon

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func TestDbgVerifyProbe(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)

	broker, err := bindElevated("BDB57FF2-79B9-4205-9447-F5FE85F37312", "9AEA8A59-E0C9-40F1-87DD-757061D56177")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	brokerI := (*ieaAdminBrokerIface)(broker)
	defer comRelease(broker)

	var uuidBstr uintptr
	r1, _, _ := syscall.Syscall9(brokerI.lpVtbl.InitializeAdminInstaller, 4, uintptr(broker), 0, 0, uintptr(unsafe.Pointer(&uuidBstr)), 0, 0, 0, 0, 0)
	if r1 != 0 {
		t.Fatalf("init 0x%08x", uint32(r1))
	}
	defer procSysFreeString.Call(uuidBstr)

	iidInst2, _ := guidFromString("BC0EC710-A3ED-4F99-B14F-5FD59FDACEA3")
	var inst unsafe.Pointer
	r1, _, _ = syscall.Syscall(brokerI.lpVtbl.QueryInterface, 3, uintptr(broker), uintptr(unsafe.Pointer(&iidInst2)), uintptr(unsafe.Pointer(&inst)))
	if r1 != 0 {
		t.Fatalf("QI 0x%08x", uint32(r1))
	}
	instI := (*ieaInstallBrokerIface)(inst)
	defer comRelease(inst)

	iidUnk, _ := guidFromString("00000000-0000-0000-C000-000000000046")

	verify := func(label, file string) {
		fb := sysAllocStringPtr(mustUTF16(file))
		defer procSysFreeString.Call(fb)
		var cacheBstr uintptr
		var certLen uint32
		var certPtr unsafe.Pointer
		r1, _, _ = syscall.Syscall12(instI.lpVtbl.VerifyFile, 12,
			uintptr(inst), uuidBstr, 0xFFFFFFFFFFFFFFFF, fb, fb, 0,
			1, 0x10, uintptr(unsafe.Pointer(&iidUnk)), uintptr(unsafe.Pointer(&cacheBstr)),
			uintptr(unsafe.Pointer(&certLen)), uintptr(unsafe.Pointer(&certPtr)))
		var path string
		if cacheBstr != 0 {
			path = bstrToString(cacheBstr)
			procSysFreeString.Call(cacheBstr)
		}
		t.Logf("VerifyFile[%s] -> 0x%08x cache=%s", label, uint32(r1), path)
	}

	verify("cmd", `C:\Windows\System32\cmd.exe`)
	verify("msiexec", `C:\Windows\System32\msiexec.exe`)
	verify("netsh", `C:\Windows\System32\netsh.exe`)
	verify("findstr", `C:\Windows\System32\findstr.exe`)
	verify("expand", `C:\Windows\System32\expand.exe`)
	verify("certutil", `C:\Windows\System32\certutil.exe`)
	verify("rundll32", `C:\Windows\System32\rundll32.exe`)
	fmt.Println("done")
}
