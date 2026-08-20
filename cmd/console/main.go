package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"darkarts/internal/version"
	"darkarts/pkg/console"
	"darkarts/pkg/logging"
)

func main() {
	log := logging.New(os.Getenv("DARKARTS_LOG_LEVEL"))
	serverURL := envOr("DARKARTS_SERVER_URL", "http://127.0.0.1:9000")
	apiKey := os.Getenv("DARKARTS_API_KEY")
	opID := envOr("DARKARTS_OP_ID", "op-console")

	client := console.New(serverURL, apiKey)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("dark-arts console", "version", version.Version, "server", serverURL)
	if err := console.NewREPL(client, opID, os.Stdout).Run(ctx, os.Stdin); err != nil && ctx.Err() == nil {
		log.Error("console exited", "err", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
