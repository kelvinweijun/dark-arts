//go:build windows && amd64

package securityctl

// ETWControl implements SecurityControl for ETW integration.
// Phase 5B: no-op stub. All methods return safe defaults.
// Phase 5C: will implement actual ETW security-control integration.
type ETWControl struct {
	baseControl
}

// NewETWControl creates a new ETW security-control instance.
func NewETWControl() *ETWControl {
	return &ETWControl{baseControl: newBaseControl("etw")}
}

// Initialize resolves ETW dependencies. Phase 5B: no-op, returns nil.
func (e *ETWControl) Initialize() error {
	return e.markInitialized(nil)
}

// Enable applies the ETW modification. Phase 5B: no-op, returns nil.
func (e *ETWControl) Enable() error {
	return e.markEnabled()
}

// Disable reverts the ETW modification. Phase 5B: no-op, returns nil.
func (e *ETWControl) Disable() error {
	e.markDisabled()
	return nil
}

// Restore cleans up on process exit. Phase 5B: no-op.
func (e *ETWControl) Restore() {}
