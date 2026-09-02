//go:build !(windows && amd64)

package securityctl

import "testing"

func TestAMSIControl_UnsupportedPlatform(t *testing.T) {
	a := NewAMSIControl()
	if s := a.Status(); s != StatusUnknown {
		t.Errorf("new AMSIControl status = %v, want StatusUnknown", s)
	}
	if err := a.Initialize(); err != ErrUnsupported {
		t.Errorf("Initialize() = %v, want ErrUnsupported", err)
	}
	if s := a.Status(); s != StatusUnsupported {
		t.Errorf("after Initialize: status = %v, want StatusUnsupported", s)
	}
	if err := a.Enable(); err != ErrUnsupported {
		t.Errorf("Enable() = %v, want ErrUnsupported", err)
	}
	if err := a.Disable(); err != nil {
		t.Errorf("Disable() = %v, want nil", err)
	}
	a.Restore()
}

func TestETWControl_UnsupportedPlatform(t *testing.T) {
	e := NewETWControl()
	if s := e.Status(); s != StatusUnknown {
		t.Errorf("new ETWControl status = %v, want StatusUnknown", s)
	}
	if err := e.Initialize(); err != ErrUnsupported {
		t.Errorf("Initialize() = %v, want ErrUnsupported", err)
	}
	if s := e.Status(); s != StatusUnsupported {
		t.Errorf("after Initialize: status = %v, want StatusUnsupported", s)
	}
	if err := e.Enable(); err != ErrUnsupported {
		t.Errorf("Enable() = %v, want ErrUnsupported", err)
	}
	if err := e.Disable(); err != nil {
		t.Errorf("Disable() = %v, want nil", err)
	}
	e.Restore()
}
