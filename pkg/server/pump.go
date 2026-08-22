package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"dark-arts/pkg/crypto"
)

type Pump struct {
	e          *Engine
	edgeURL    string
	client     *http.Client
	log        *slog.Logger
	lastResult map[string]uint64
	pushed     map[string]bool
}

func NewPump(e *Engine, edgeURL string, log *slog.Logger) *Pump {
	return NewPumpWithClient(e, edgeURL, log, &http.Client{Timeout: 30 * time.Second})
}

func NewPumpWithClient(e *Engine, edgeURL string, log *slog.Logger, client *http.Client) *Pump {
	if log == nil {
		log = slog.Default()
	}
	return &Pump{
		e: e, edgeURL: edgeURL, client: client,
		log: log, lastResult: make(map[string]uint64), pushed: make(map[string]bool),
	}
}

func (p *Pump) Pass(ctx context.Context) error {
	for _, s := range p.e.Sessions() {
		sid := s.ID
		if err := p.pullResults(ctx, sid); err != nil {
			p.log.Warn("pump: pull results failed", "sid", sid, "err", err)
		}
		if err := p.pushTasks(ctx, sid); err != nil {
			p.log.Warn("pump: push tasks failed", "sid", sid, "err", err)
		}
	}
	return nil
}

func (p *Pump) Loop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	p.Pass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Pass(ctx)
		}
	}
}

func (p *Pump) pullResults(ctx context.Context, sid string) error {
	u := fmt.Sprintf("%s/tasks/%s?f=beacon&since=%d", p.edgeURL, url.PathEscape(sid), p.lastResult[sid])
	resp, err := p.client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("edge status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var envs []json.RawMessage
	if err := json.Unmarshal(body, &envs); err != nil {
		return err
	}
	for _, raw := range envs {
		if err := p.e.IngestEnvelope(sid, raw); err != nil {
			p.log.Warn("pump: result rejected", "sid", sid, "err", err)
			continue
		}
		c, ok := envelopeCounter(raw)
		if !ok {
			continue
		}
		if err := p.deleteBlob(ctx, sid, c); err != nil {
			p.log.Warn("pump: result blob delete failed", "sid", sid, "counter", c, "err", err)
		}
		if p.lastResult[sid] < c+1 {
			p.lastResult[sid] = c + 1
		}
	}
	return nil
}

func (p *Pump) deleteBlob(ctx context.Context, sid string, counter uint64) error {
	u := fmt.Sprintf("%s/tasks/%s/%020d?f=beacon", p.edgeURL, url.PathEscape(sid), counter)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("edge delete status %d", resp.StatusCode)
	}
	return nil
}

func (p *Pump) pushTasks(ctx context.Context, sid string) error {
	for _, t := range p.e.Queue().Pending(sid) {
		if p.pushed[t.ID] {
			continue
		}
		envBytes, err := p.e.Encrypt(sid, t)
		if err != nil {
			p.log.Warn("pump: encrypt task failed", "sid", sid, "task", t.ID, "err", err)
			continue
		}
		u := fmt.Sprintf("%s/ingest?f=server", p.edgeURL)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(envBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := p.client.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			return fmt.Errorf("edge ingest status %d", resp.StatusCode)
		}
		p.e.Queue().Ack(t.ID)
		p.pushed[t.ID] = true
		p.log.Info("pump: task pushed", "sid", sid, "task", t.ID, "type", t.Type)
	}
	return nil
}

func envelopeCounter(raw json.RawMessage) (uint64, bool) {
	env, err := crypto.UnmarshalEnvelope(raw)
	if err != nil {
		return 0, false
	}
	if len(env.Nonce) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(env.Nonce[:8]), true
}
