package beacon

import (
	"fmt"
	"runtime"
	"testing"
)

func TestDbgFOPMatrix(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)

	for _, mask := range []bool{false, true} {
		for _, iid := range []string{"00000000-0000-0000-C000-000000000046", "9AC9FBE1-E0A2-4AD6-B4EE-E212013EA917"} {
			for _, ctx := range []uint32{0, 0x4} {
				if mask {
					restore, err := masqueradeExplorer()
					if err != nil {
						t.Fatalf("mask: %v", err)
					}
					restore()
				}
				p, err := bindElevatedOpts("3AD05575-8857-4850-9277-11B85BDB8E09", iid, ctx)
				label := "IUnknown"
				if iid == "9AC9FBE1-E0A2-4AD6-B4EE-E212013EA917" {
					label = "IFileOp"
				}
				t.Logf("FOP mask=%-5v %-7s ctx=0x%-2x -> p=%v err=%v", mask, label, ctx, p != nil, err)
				if p != nil {
					comRelease(p)
				}
			}
		}
	}
	fmt.Println("done")
}
