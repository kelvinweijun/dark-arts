package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dark-arts/internal/version"
	"dark-arts/pkg/logging"
	"dark-arts/pkg/relay"
	"dark-arts/pkg/store"
)

func main() {
	log := logging.New(os.Getenv("DARK_ARTS_LOG_LEVEL"))
	addr := envOr("DARK_ARTS_RELAY_LISTEN", ":7443")
	upstreams := splitList(os.Getenv("DARK_ARTS_UPSTREAM"))
	if len(upstreams) == 0 {
		log.Error("DARK_ARTS_UPSTREAM required (comma separated edge/relay urls)")
		os.Exit(2)
	}
	st := store.NewFile(envOr("DARK_ARTS_STORE_DIR", "./data/relay"))

	opts := relay.Options{Logger: log}
	if os.Getenv("DARK_ARTS_INSECURE") == "true" {
		opts.Client = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}
	}
	r := relay.New(st, upstreams, opts)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("dark-arts relay starting", "version", version.Version, "addr", addr, "upstreams", upstreams)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go r.ForwardPendingLoop(ctx, time.Duration(envInt("DARK_ARTS_RETRY", 30))*time.Second)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
	}()

	cert, key := os.Getenv("DARK_ARTS_TLS_CERT"), os.Getenv("DARK_ARTS_TLS_KEY")
	var serveErr error
	if cert != "" && key != "" {
		log.Info("relay serving TLS")
		serveErr = httpSrv.ListenAndServeTLS(cert, key)
	} else {
		serveErr = httpSrv.ListenAndServe()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Error("relay exited", "err", serveErr)
		os.Exit(1)
	}
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
