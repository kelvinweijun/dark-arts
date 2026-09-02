//go:build !(windows && amd64)

package securityctl

// ETWControl implements SecurityControl for ETW integration.
// Non-Windows/AMD64: always returns StatusUnsupported.
type ETWControl struct {
	baseControl
}

// NewETWControl creates a new ETW security-control instance.
func NewETWControl() *ETWControl {
	return &ETWControl{baseControl: newBaseControl("etw")}
}

// Initialize marks the control as unsupported on this platform.
func (e *ETWControl) Initialize() error {
	return e.markInitialized(ErrUnsupported)
}

// Enable returns ErrUnsupported on this platform.
func (e *ETWControl) Enable() error {
	return ErrUnsupported
}

// Disable returns nil (no-op on unsupported platform).
func (e *ETWControl) Disable() error {
	return nil
}

// Restore is a no-op on unsupported platforms.
func (e *ETWControl) Restore() {}
