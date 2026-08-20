package deaddrop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

type State uint8

const (
	StatePublished State = iota
	StateQuarantined
	StateRetired
)

var (
	ErrNotFound    = errors.New("deaddrop: not found")
	ErrUnavailable = errors.New("deaddrop: resolver unavailable")
)

type Drop struct {
	Kind    string `json:"kind"`
	Ref     string `json:"ref"`
	Payload []byte `json:"payload"`
}

type Resolver interface {
	Publish(ctx context.Context, ref string, payload []byte) error
	Resolve(ctx context.Context, ref string) ([]byte, error)
	Retire(ctx context.Context, ref string) error
}

func KeyOf(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:16])
}

type Manager struct {
	rs     []Resolver
	states map[string]State
}

func NewManager(resolvers ...Resolver) *Manager {
	return &Manager{rs: resolvers, states: make(map[string]State)}
}

func (m *Manager) Publish(ctx context.Context, payload []byte) (string, error) {
	ref := KeyOf(payload)
	var last error
	for _, r := range m.rs {
		if err := r.Publish(ctx, ref, payload); err != nil {
			last = err
			continue
		}
		m.states[ref] = StatePublished
		return ref, nil
	}
	if last == nil {
		last = ErrUnavailable
	}
	return "", fmt.Errorf("deaddrop: publish: %w", last)
}

func (m *Manager) Quarantine(ref string) {
	if st, ok := m.states[ref]; ok && st != StateRetired {
		m.states[ref] = StateQuarantined
	}
}

func (m *Manager) Retire(ctx context.Context, ref string) error {
	var last error
	for _, r := range m.rs {
		if err := r.Retire(ctx, ref); err != nil && !errors.Is(err, ErrNotFound) {
			last = err
		}
	}
	m.states[ref] = StateRetired
	return last
}

func (m *Manager) Resolve(ctx context.Context, ref string) ([]byte, error) {
	if m.states[ref] == StateRetired {
		return nil, ErrNotFound
	}
	var last error
	sawNotFound := false
	for _, r := range m.rs {
		b, err := r.Resolve(ctx, ref)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				sawNotFound = true
			}
			last = err
			continue
		}
		return b, nil
	}
	if last == nil {
		last = ErrUnavailable
	}
	if sawNotFound {
		return nil, ErrNotFound
	}
	return nil, last
}
