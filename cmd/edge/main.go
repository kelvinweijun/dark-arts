package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"darkarts/internal/version"
	"darkarts/pkg/edge"
	"darkarts/pkg/logging"
	"darkarts/pkg/store"
)

func main() {
	log := logging.New(os.Getenv("DARKARTS_LOG_LEVEL"))
	addr := envOr("DARKARTS_LISTEN", ":8443")

	st, err := newStore(log)
	if err != nil {
		log.Error("store init failed", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           edge.New(st, edge.Options{Logger: log, CoverHTML: os.Getenv("DARKARTS_COVER_HTML")}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("dark-arts edge starting", "version", version.Version, "addr", addr)
	cert, key := os.Getenv("DARKARTS_TLS_CERT"), os.Getenv("DARKARTS_TLS_KEY")
	var serveErr error
	if cert != "" && key != "" {
		log.Info("edge serving TLS")
		serveErr = httpSrv.ListenAndServeTLS(cert, key)
	} else {
		serveErr = httpSrv.ListenAndServe()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Error("edge exited", "err", serveErr)
		os.Exit(1)
	}
}

func newStore(log *slog.Logger) (store.Store, error) {
	switch os.Getenv("DARKARTS_STORE") {
	case "minio":
		m, err := store.NewMinIO(
			envOr("DARKARTS_S3_ENDPOINT", "minio:9000"),
			envOr("DARKARTS_S3_ACCESS_KEY", "darkarts"),
			envOr("DARKARTS_S3_SECRET_KEY", "darkarts-lab"),
			envOr("DARKARTS_S3_BUCKET", "darkarts"),
			os.Getenv("DARKARTS_S3_SECURE") == "true",
		)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.EnsureBucket(ctx); err != nil {
			return nil, err
		}
		log.Info("edge using minio store", "bucket", m.Bucket())
		return m, nil
	default:
		dir := envOr("DARKARTS_STORE_DIR", "./data/edge")
		log.Info("edge using file store", "dir", dir)
		return store.NewFile(dir), nil
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
