package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"dark-arts/internal/version"
	"dark-arts/pkg/crypto"
	"dark-arts/pkg/logging"
	"dark-arts/pkg/server"
)

func main() {
	log := logging.New(os.Getenv("DARK_ARTS_LOG_LEVEL"))

	ident, err := serverIdentity()
	if err != nil {
		log.Error("identity init failed", "err", err)
		os.Exit(1)
	}

	engine := server.NewEngineWithState(ident, filepath.Join(envOr("DARK_ARTS_STATE_DIR", "./data/server"), "state.json"))
	apiKey := os.Getenv("DARK_ARTS_API_KEY")
	addr := envOr("DARK_ARTS_LISTEN", ":9000")

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           server.NewHandler(engine, apiKey, log),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("dark-arts server starting", "version", version.Version, "addr", addr, "api_key_set", apiKey != "")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if edgeURL := os.Getenv("DARK_ARTS_EDGE"); edgeURL != "" {
		client := &http.Client{Timeout: 30 * time.Second}
		if os.Getenv("DARK_ARTS_INSECURE") == "true" {
			client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}
		pump := server.NewPumpWithClient(engine, edgeURL, log, client)
		interval := envInt("DARK_ARTS_PUMP_INTERVAL", 5)
		go pump.Loop(ctx, time.Duration(interval)*time.Second)
		log.Info("server pump running", "edge", edgeURL, "interval", interval)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
	}()

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func serverIdentity() (*crypto.Identity, error) {
	seedHex := os.Getenv("DARK_ARTS_SERVER_SEED")
	if seedHex == "" {
		return crypto.NewIdentity()
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	return crypto.IdentityFromSeed(seed)
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
