package beacon

import (
	"fmt"
	"runtime"
	"testing"
)

func TestDbgMinBind(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)

	for _, combo := range []struct {
		label string
		clsid string
		iid   string
	}{
		{"IEInstal/IEAxiAdminInstaller", "BDB57FF2-79B9-4205-9447-F5FE85F37312", "9AEA8A59-E0C9-40F1-87DD-757061D56177"},
		{"IEInstal/IUnknown", "BDB57FF2-79B9-4205-9447-F5FE85F37312", "00000000-0000-0000-C000-000000000046"},
	} {
		p, err := bindElevatedOpts(combo.clsid, combo.iid, 0)
		if err != nil {
			t.Logf("%s bind: %v", combo.label, err)
		} else {
			t.Logf("%s BIND OK", combo.label)
			comRelease(p)
		}
	}
	fmt.Println("done")
}
