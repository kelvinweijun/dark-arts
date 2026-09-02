package securityctl

import (
	"sync"
	"testing"
)

// MockControl implements SecurityControl for testing.
// It records all method calls and allows configurable behavior.
type MockControl struct {
	baseControl

	mu           sync.Mutex
	initCalls    int
	enableCalls  int
	disableCalls int
	restoreCalls int

	initErr    error
	enableErr  error
	disableErr error

	calls []string
}

func newMockControl(name string) *MockControl {
	return &MockControl{
		baseControl: newBaseControl(name),
	}
}

func (m *MockControl) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initCalls++
	m.calls = append(m.calls, "Initialize")
	return m.markInitialized(m.initErr)
}

func (m *MockControl) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enableCalls++
	m.calls = append(m.calls, "Enable")
	return m.markEnabled()
}

func (m *MockControl) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disableCalls++
	m.calls = append(m.calls, "Disable")
	m.markDisabled()
	return m.disableErr
}

func (m *MockControl) Restore() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restoreCalls++
	m.calls = append(m.calls, "Restore")
}

func (m *MockControl) getInitCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.initCalls
}

func (m *MockControl) getEnableCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enableCalls
}

func (m *MockControl) getDisableCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disableCalls
}

func (m *MockControl) getRestoreCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreCalls
}

func (m *MockControl) getCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

// --- ControlStatus tests ---

func TestControlStatusString(t *testing.T) {
	tests := []struct {
		status ControlStatus
		want   string
	}{
		{StatusUnknown, "unknown"},
		{StatusInitialized, "initialized"},
		{StatusEnabled, "enabled"},
		{StatusDisabled, "disabled"},
		{StatusUnsupported, "unsupported"},
		{ControlStatus(99), "invalid"},
	}
	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("ControlStatus(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

// --- Default state tests ---

func TestNewMockControl_DefaultStatus(t *testing.T) {
	m := newMockControl("test")
	if s := m.Status(); s != StatusUnknown {
		t.Errorf("new MockControl status = %v, want StatusUnknown", s)
	}
	if n := m.Name(); n != "test" {
		t.Errorf("Name() = %q, want %q", n, "test")
	}
}

func TestNewAMSIControl_DefaultStatus(t *testing.T) {
	a := NewAMSIControl()
	if s := a.Status(); s != StatusUnknown {
		t.Errorf("new AMSIControl status = %v, want StatusUnknown", s)
	}
	if n := a.Name(); n != "amsi" {
		t.Errorf("Name() = %q, want %q", n, "amsi")
	}
}

func TestNewETWControl_DefaultStatus(t *testing.T) {
	e := NewETWControl()
	if s := e.Status(); s != StatusUnknown {
		t.Errorf("new ETWControl status = %v, want StatusUnknown", s)
	}
	if n := e.Name(); n != "etw" {
		t.Errorf("Name() = %q, want %q", n, "etw")
	}
}

// --- Default configuration test ---

func TestDefaultConfiguration_NoAction(t *testing.T) {
	a := NewAMSIControl()
	e := NewETWControl()

	// Default: StatusUnknown. No security-control action taken.
	if a.Status() != StatusUnknown {
		t.Errorf("AMSI default status = %v, want StatusUnknown", a.Status())
	}
	if e.Status() != StatusUnknown {
		t.Errorf("ETW default status = %v, want StatusUnknown", e.Status())
	}

	// Enable without Initialize should fail
	if err := a.Enable(); err != ErrNotInitialized {
		t.Errorf("AMSI Enable() without Initialize: got %v, want ErrNotInitialized", err)
	}
	if err := e.Enable(); err != ErrNotInitialized {
		t.Errorf("ETW Enable() without Initialize: got %v, want ErrNotInitialized", err)
	}

	// Status should still be Unknown after failed Enable
	if a.Status() != StatusUnknown {
		t.Errorf("AMSI status after failed Enable = %v, want StatusUnknown", a.Status())
	}
}

// --- Lifecycle tests ---

func TestMockControl_FullLifecycle(t *testing.T) {
	m := newMockControl("test")

	// Initialize
	if err := m.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if s := m.Status(); s != StatusInitialized {
		t.Errorf("after Initialize: status = %v, want StatusInitialized", s)
	}

	// Enable
	if err := m.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if s := m.Status(); s != StatusEnabled {
		t.Errorf("after Enable: status = %v, want StatusEnabled", s)
	}

	// Disable
	if err := m.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	if s := m.Status(); s != StatusDisabled {
		t.Errorf("after Disable: status = %v, want StatusDisabled", s)
	}

	// Restore
	m.Restore()
	if s := m.Status(); s != StatusDisabled {
		t.Errorf("after Restore: status = %v, want StatusDisabled (restore does not change status)", s)
	}
}

func TestAMSIControl_FullLifecycle(t *testing.T) {
	a := NewAMSIControl()

	if err := a.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if s := a.Status(); s != StatusInitialized {
		t.Errorf("after Initialize: status = %v, want StatusInitialized", s)
	}

	if err := a.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if s := a.Status(); s != StatusEnabled {
		t.Errorf("after Enable: status = %v, want StatusEnabled", s)
	}

	if err := a.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	if s := a.Status(); s != StatusDisabled {
		t.Errorf("after Disable: status = %v, want StatusDisabled", s)
	}

	a.Restore()
}

func TestETWControl_FullLifecycle(t *testing.T) {
	e := NewETWControl()

	if err := e.Initialize(); err != nil {
		t.Fatalf("Initialize() = %v", err)
	}
	if err := e.Enable(); err != nil {
		t.Fatalf("Enable() = %v", err)
	}
	if s := e.Status(); s != StatusEnabled {
		t.Errorf("after Enable: status = %v, want StatusEnabled", s)
	}

	if err := e.Disable(); err != nil {
		t.Fatalf("Disable() = %v", err)
	}
	if s := e.Status(); s != StatusDisabled {
		t.Errorf("after Disable: status = %v, want StatusDisabled", s)
	}

	e.Restore()
}

// --- Idempotency tests ---

func TestMockControl_IdempotentInitialize(t *testing.T) {
	m := newMockControl("test")

	if err := m.Initialize(); err != nil {
		t.Fatalf("first Initialize() = %v", err)
	}
	if err := m.Initialize(); err != nil {
		t.Fatalf("second Initialize() = %v", err)
	}
	if n := m.getInitCalls(); n != 2 {
		t.Errorf("Initialize called %d times, want 2", n)
	}
	if s := m.Status(); s != StatusInitialized {
		t.Errorf("status after double Initialize = %v, want StatusInitialized", s)
	}
}

func TestMockControl_IdempotentEnable(t *testing.T) {
	m := newMockControl("test")
	m.Initialize()

	if err := m.Enable(); err != nil {
		t.Fatalf("first Enable() = %v", err)
	}
	if err := m.Enable(); err != nil {
		t.Fatalf("second Enable() = %v", err)
	}
	if n := m.getEnableCalls(); n != 2 {
		t.Errorf("Enable called %d times, want 2", n)
	}
	if s := m.Status(); s != StatusEnabled {
		t.Errorf("status after double Enable = %v, want StatusEnabled", s)
	}
}

func TestMockControl_IdempotentDisable(t *testing.T) {
	m := newMockControl("test")
	m.Initialize()
	m.Enable()

	if err := m.Disable(); err != nil {
		t.Fatalf("first Disable() = %v", err)
	}
	if err := m.Disable(); err != nil {
		t.Fatalf("second Disable() = %v", err)
	}
	if s := m.Status(); s != StatusDisabled {
		t.Errorf("status after double Disable = %v, want StatusDisabled", s)
	}
}

func TestMockControl_DisableWithoutEnable(t *testing.T) {
	m := newMockControl("test")
	m.Initialize()

	// Disable without prior Enable should be safe
	if err := m.Disable(); err != nil {
		t.Fatalf("Disable() without Enable = %v", err)
	}
	if s := m.Status(); s != StatusInitialized {
		t.Errorf("status after Disable without Enable = %v, want StatusInitialized", s)
	}
}

// --- Failure handling tests ---

func TestMockControl_InitializeFailure(t *testing.T) {
	m := newMockControl("test")
	m.initErr = ErrUnsupported

	if err := m.Initialize(); err != ErrUnsupported {
		t.Errorf("Initialize() = %v, want ErrUnsupported", err)
	}
	if s := m.Status(); s != StatusUnsupported {
		t.Errorf("status after failed Initialize = %v, want StatusUnsupported", s)
	}

	// Enable after failed Initialize should fail
	if err := m.Enable(); err != ErrInitializeFailed {
		t.Errorf("Enable() after failed Initialize = %v, want ErrInitializeFailed", err)
	}
}

func TestMockControl_EnableBeforeInitialize(t *testing.T) {
	m := newMockControl("test")

	if err := m.Enable(); err != ErrNotInitialized {
		t.Errorf("Enable() before Initialize = %v, want ErrNotInitialized", err)
	}
}

func TestMockControl_RestoreAfterFailedInit(t *testing.T) {
	m := newMockControl("test")
	m.initErr = ErrUnsupported
	m.Initialize()

	// Restore should be safe even after failed init
	m.Restore()
	if n := m.getRestoreCalls(); n != 1 {
		t.Errorf("Restore called %d times, want 1", n)
	}
}

func TestMockControl_RestoreWithoutInit(t *testing.T) {
	m := newMockControl("test")

	// Restore should be safe without any prior calls
	m.Restore()
	if n := m.getRestoreCalls(); n != 1 {
		t.Errorf("Restore called %d times, want 1", n)
	}
}

// --- Cleanup safety tests ---

func TestMockControl_CleanupAfterPartialInit(t *testing.T) {
	m := newMockControl("test")
	m.initErr = ErrUnsupported

	// Partial init (failed)
	m.Initialize()

	// Cleanup should be safe
	m.Disable()
	m.Restore()

	if s := m.Status(); s != StatusUnsupported {
		t.Errorf("status after partial init cleanup = %v, want StatusUnsupported", s)
	}
}

func TestMockControl_CleanupAfterEnable(t *testing.T) {
	m := newMockControl("test")
	m.Initialize()
	m.Enable()

	// Cleanup: Disable + Restore should be safe
	m.Disable()
	m.Restore()

	if s := m.Status(); s != StatusDisabled {
		t.Errorf("status after cleanup = %v, want StatusDisabled", s)
	}
}

// --- Concurrency tests ---

func TestMockControl_ConcurrentLifecycle(t *testing.T) {
	m := newMockControl("test")
	const goroutines = 100

	// Concurrent Initialize
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = m.Initialize()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Initialize() = %v", i, err)
		}
	}
	if s := m.Status(); s != StatusInitialized {
		t.Errorf("concurrent Initialize: status = %v, want StatusInitialized", s)
	}

	// Concurrent Enable
	wg.Add(goroutines)
	errs2 := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			errs2[idx] = m.Enable()
		}(i)
	}
	wg.Wait()

	for i, err := range errs2 {
		if err != nil {
			t.Errorf("goroutine %d: Enable() = %v", i, err)
		}
	}
	if s := m.Status(); s != StatusEnabled {
		t.Errorf("concurrent Enable: status = %v, want StatusEnabled", s)
	}

	// Concurrent Disable
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = m.Disable()
		}()
	}
	wg.Wait()

	if s := m.Status(); s != StatusDisabled {
		t.Errorf("concurrent Disable: status = %v, want StatusDisabled", s)
	}

	// Concurrent Restore
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			m.Restore()
		}()
	}
	wg.Wait()
}

func TestMockControl_ConcurrentStatusReads(t *testing.T) {
	m := newMockControl("test")
	m.Initialize()
	m.Enable()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = m.Status()
		}()
	}
	wg.Wait()
}

func TestMockControl_ConcurrentMixedOps(t *testing.T) {
	m := newMockControl("test")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 4)
	for i := 0; i < goroutines; i++ {
		go func() { defer wg.Done(); _ = m.Initialize() }()
		go func() { defer wg.Done(); _ = m.Enable() }()
		go func() { defer wg.Done(); _ = m.Disable() }()
		go func() { defer wg.Done(); _ = m.Status() }()
	}
	wg.Wait()

	// Should be in a consistent state (one of the valid states)
	s := m.Status()
	switch s {
	case StatusUnknown, StatusInitialized, StatusEnabled, StatusDisabled, StatusUnsupported:
		// valid
	default:
		t.Errorf("invalid state after concurrent ops: %v", s)
	}
}

// --- Interface compliance test ---

func TestInterfaceCompliance(t *testing.T) {
	var _ SecurityControl = (*AMSIControl)(nil)
	var _ SecurityControl = (*ETWControl)(nil)
	var _ SecurityControl = (*MockControl)(nil)
}
