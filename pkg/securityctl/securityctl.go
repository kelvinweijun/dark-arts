// Package securityctl provides an abstraction layer for security-control
// integration. It defines a SecurityControl interface for managing
// security-related process modifications in a lifecycle-safe, idempotent,
// and concurrency-safe manner.
//
// Phase 5B implements only the interface, configuration plumbing, and
// test scaffolding. No operational security-control bypass code is included.
// The resulting implementation is non-operational with respect to bypassing
// Windows security controls.
package securityctl

import (
	"errors"
	"sync"
)

var (
	// ErrUnsupported is returned when the control is not supported on the
	// current platform or configuration.
	ErrUnsupported = errors.New("securityctl: unsupported platform or configuration")

	// ErrNotInitialized is returned when Enable() or Disable() is called
	// before Initialize().
	ErrNotInitialized = errors.New("securityctl: not initialized")

	// ErrInitializeFailed is returned when Initialize() has previously failed.
	ErrInitializeFailed = errors.New("securityctl: initialization previously failed")
)

// ControlStatus represents the current state of a security control.
type ControlStatus int

const (
	// StatusUnknown indicates the control has not been initialized.
	StatusUnknown ControlStatus = iota

	// StatusInitialized indicates dependencies are resolved but the
	// control has not been enabled.
	StatusInitialized

	// StatusEnabled indicates the abstraction's logical state is "enabled".
	// In Phase 5B this is a no-op; no real security-control modification occurs.
	// Phase 5C will apply the actual modification when this state is entered.
	StatusEnabled

	// StatusDisabled indicates the abstraction's logical state is "disabled".
	// The control was previously enabled (logically) but has been reverted.
	// In Phase 5B this is a no-op; no real security-control restoration occurs.
	StatusDisabled

	// StatusUnsupported indicates the platform, OS, or configuration does
	// not support this control.
	StatusUnsupported
)

// String returns a human-readable representation of the status.
func (s ControlStatus) String() string {
	switch s {
	case StatusUnknown:
		return "unknown"
	case StatusInitialized:
		return "initialized"
	case StatusEnabled:
		return "enabled"
	case StatusDisabled:
		return "disabled"
	case StatusUnsupported:
		return "unsupported"
	default:
		return "invalid"
	}
}

// SecurityControl abstracts a security-control modification. Implementations
// manage the lifecycle of a specific security-control integration.
//
// All methods are safe for concurrent use. The lifecycle is:
//
//	Initialize → Enable → Disable → Restore
//
// Initialize must be called before Enable or Disable. Enable and Disable
// are idempotent. Restore is always safe to call.
//
// Phase 5B: all implementations are no-op stubs. Enable/Disable/Restore
// transition the abstraction's logical state but perform no modification
// of real Windows security controls (AMSI, ETW, or otherwise).
type SecurityControl interface {
	// Name returns the control name (e.g., "amsi", "etw").
	Name() string

	// Initialize resolves dependencies (target DLL base, export address).
	// Must be called after pkg/evasion initialization completes.
	// Returns error if the target is not present or unresolvable.
	// Idempotent: calling multiple times returns the same result.
	Initialize() error

	// Enable transitions the abstraction to the "enabled" logical state.
	// Phase 5B: no-op stub returning nil. No real security-control
	// modification occurs.
	// Requires Initialize() to have succeeded.
	// Idempotent: calling multiple times is safe.
	Enable() error

	// Disable transitions the abstraction to the "disabled" logical state.
	// Phase 5B: no-op stub returning nil. No real security-control
	// restoration occurs.
	// Idempotent: calling multiple times is safe.
	// Returns nil if not currently enabled.
	Disable() error

	// Status reports whether the control is currently active.
	Status() ControlStatus

	// Restore performs cleanup on process exit or kill.
	// Phase 5B: no-op.
	// Must be safe to call even if Initialize() or Enable() failed.
	Restore()
}

// baseControl provides shared lifecycle state management for
// SecurityControl implementations. Embed this in concrete types.
type baseControl struct {
	mu      sync.Mutex
	status  ControlStatus
	initErr error
	name    string
}

// newBaseControl creates a baseControl with StatusUnknown.
func newBaseControl(name string) baseControl {
	return baseControl{name: name, status: StatusUnknown}
}

// Status returns the current control status in a thread-safe manner.
func (b *baseControl) Status() ControlStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status
}

// Name returns the control name.
func (b *baseControl) Name() string {
	return b.name
}

// setStatus transitions the control to a new status. Must be called
// while b.mu is held by the caller.
func (b *baseControl) setStatus(s ControlStatus) {
	b.status = s
}

// markInitialized transitions to StatusInitialized. Returns the
// initErr if initialization previously failed.
func (b *baseControl) markInitialized(err error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.status == StatusInitialized || b.status == StatusEnabled || b.status == StatusDisabled {
		return b.initErr
	}
	b.initErr = err
	if err != nil {
		b.status = StatusUnsupported
		return err
	}
	b.status = StatusInitialized
	return nil
}

// markEnabled transitions to StatusEnabled. Returns ErrNotInitialized
// if Initialize() was not called, or ErrInitializeFailed if it failed.
func (b *baseControl) markEnabled() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.status == StatusUnknown {
		return ErrNotInitialized
	}
	if b.status == StatusUnsupported {
		return ErrInitializeFailed
	}
	b.status = StatusEnabled
	return nil
}

// markDisabled transitions to StatusDisabled. Returns nil if not enabled.
func (b *baseControl) markDisabled() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.status == StatusEnabled {
		b.status = StatusDisabled
	}
}
