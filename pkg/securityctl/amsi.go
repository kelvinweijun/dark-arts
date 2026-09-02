//go:build windows && amd64

package securityctl

// AMSIControl implements SecurityControl for AMSI integration.
// Phase 5B: no-op stub. All methods return safe defaults.
// Phase 5C: will implement actual AMSI security-control integration.
type AMSIControl struct {
	baseControl
}

// NewAMSIControl creates a new AMSI security-control instance.
func NewAMSIControl() *AMSIControl {
	return &AMSIControl{baseControl: newBaseControl("amsi")}
}

// Initialize resolves AMSI dependencies. Phase 5B: no-op, returns nil.
func (a *AMSIControl) Initialize() error {
	return a.markInitialized(nil)
}

// Enable applies the AMSI modification. Phase 5B: no-op, returns nil.
func (a *AMSIControl) Enable() error {
	return a.markEnabled()
}

// Disable reverts the AMSI modification. Phase 5B: no-op, returns nil.
func (a *AMSIControl) Disable() error {
	a.markDisabled()
	return nil
}

// Restore cleans up on process exit. Phase 5B: no-op.
func (a *AMSIControl) Restore() {}
