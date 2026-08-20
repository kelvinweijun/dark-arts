//go:build !windows || !amd64

package sleepmask

// Masker is a no-op on non-windows/amd64 platforms.
type Masker struct{}

func New() (*Masker, error) { return &Masker{}, nil }
func (m *Masker) Register(buf []byte) {
}
func (m *Masker) RegisterRegion(ptr, size uintptr, prot uint32) {
}
func (m *Masker) Mask() error   { return nil }
func (m *Masker) Unmask() error { return nil }
func MaskSelfRegion(ptr, size uintptr, prot uint32) {
}
