package beacon

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

var probeCLSIDs = []struct {
	name  string
	clsid string
}{
	{"easinvoker", "18FBD4BC-16EA-47f2-8AD0-868C1269C79A"},
	{"sdchange", "E1BA41AD-4A1D-418F-AABA-3D1196B423D3"},
	{"cttunesvr", "32BA16FD-2602-41f0-8133-A366925E0289"},
	{"lpksetup", "1C749B87-568C-4865-8E73-6413F8372CE6"},
	{"CertEnrollCtrl", "884e2050-217a-11da-b2a4-000e7bbb2b09"},
	{"TpmVscMgrSvr", "16A18E86-2876-4acd-8AA7-18D5247353DD"},
	{"EasPolicyMgr", "EAF9FB9A-1F26-426E-AE2F-EA8C1E74D75A"},
	{"ImmersiveTpmVscMgr", "19833350-2A9A-4BE3-9BAB-53755D28FA96"},
	{"IEInstal", "BDB57FF2-79B9-4205-9447-F5FE85F37312"},
}

func TestDbgProbeAutoApproved(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)

	for _, c := range probeCLSIDs {
		p, err := bindElevatedOpts(c.clsid, "00000000-0000-0000-C000-000000000046", 0)
		if err != nil {
			t.Logf("%-18s bind: %v", c.name, err)
			continue
		}
		t.Logf("%-18s BIND OK", c.name)
		iface := (*probeIface)(p)
		vtbl := iface.lpVtbl
		t.Logf("  vtbl=%p slots: QI=0x%x AddR=0x%x Rel=0x%x s3=0x%x s4=0x%x s5=0x%x s6=0x%x s7=0x%x s8=0x%x", vtbl, vtbl.QueryInterface, vtbl.AddRef, vtbl.Release, vtbl.Slot3, vtbl.Slot4, vtbl.Slot5, vtbl.Slot6, vtbl.Slot7, vtbl.Slot8)
		comRelease(p)
	}
	fmt.Println("done")
}

func TestDbgProbeEasInvoker(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)

	p, err := bindElevatedOpts("18FBD4BC-16EA-47f2-8AD0-868C1269C79A", "00000000-0000-0000-C000-000000000046", 0)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Logf("bound IUnknown")
	defer comRelease(p)

	iface := (*probeIface)(p)
	vtbl := iface.lpVtbl
	t.Logf("IUnknown vtable: QI=0x%x AddR=0x%x Rel=0x%x", vtbl.QueryInterface, vtbl.AddRef, vtbl.Release)

	iidEas, _ := guidFromString("A1DAF094-B06F-4841-8C63-9820C68B65A1")
	var qp unsafe.Pointer
	r1, _, _ := syscall.Syscall9(vtbl.QueryInterface, 3,
		uintptr(p), uintptr(unsafe.Pointer(&iidEas)), uintptr(unsafe.Pointer(&qp)), 0, 0, 0, 0, 0, 0)
	t.Logf("QI IEasInvoker -> 0x%08x p=%v", uint32(r1), qp != nil)
	if r1 != 0 {
		t.Fatalf("QI failed")
	}
	defer comRelease(qp)

	eiface := (*probeIface)(qp)
	ev := eiface.lpVtbl
	t.Logf("IEasInvoker vtable=%p", ev)
	t.Logf("  s3=0x%x s4=0x%x s5=0x%x s6=0x%x", ev.Slot3, ev.Slot4, ev.Slot5, ev.Slot6)
	t.Logf("  s7=0x%x s8=0x%x s9=0x%x s10=0x%x", ev.Slot7, ev.Slot8, ev.Slot9, ev.Slot10)
	t.Logf("  s11=0x%x s12=0x%x s13=0x%x s14=0x%x", ev.Slot11, ev.Slot12, ev.Slot13, ev.Slot14)
	fmt.Println("done")
}

type probeIface struct {
	lpVtbl *probeVtbl
}
type probeVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	Slot3          uintptr
	Slot4          uintptr
	Slot5          uintptr
	Slot6          uintptr
	Slot7          uintptr
	Slot8          uintptr
	Slot9          uintptr
	Slot10         uintptr
	Slot11         uintptr
	Slot12         uintptr
	Slot13         uintptr
	Slot14         uintptr
}
