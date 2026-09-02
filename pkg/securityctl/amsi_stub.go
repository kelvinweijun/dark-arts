//go:build !(windows && amd64)

package securityctl

// AMSIControl implements SecurityControl for AMSI integration.
// Non-Windows/AMD64: always returns StatusUnsupported.
type AMSIControl struct {
	baseControl
}

// NewAMSIControl creates a new AMSI security-control instance.
func NewAMSIControl() *AMSIControl {
	return &AMSIControl{baseControl: newBaseControl("amsi")}
}

// Initialize marks the control as unsupported on this platform.
func (a *AMSIControl) Initialize() error {
	return a.markInitialized(ErrUnsupported)
}

// Enable returns ErrUnsupported on this platform.
func (a *AMSIControl) Enable() error {
	return ErrUnsupported
}

// Disable returns nil (no-op on unsupported platform).
func (a *AMSIControl) Disable() error {
	return nil
}

// Restore is a no-op on unsupported platforms.
func (a *AMSIControl) Restore() {}
