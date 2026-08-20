package logging

import (
	"context"
	"log/slog"
	"testing"
)

func TestNewReturnsLogger(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "DEBUG", "garbage", ""} {
		if New(level) == nil {
			t.Fatalf("New(%q) returned nil", level)
		}
	}
}

func TestLevelFiltering(t *testing.T) {
	ctx := context.Background()
	if !New("debug").Enabled(ctx, slog.LevelDebug) {
		t.Fatal("debug must be enabled at debug level")
	}
	if New("info").Enabled(ctx, slog.LevelDebug) {
		t.Fatal("debug must be filtered at info level")
	}
	if !New("error").Enabled(ctx, slog.LevelError) {
		t.Fatal("error must be enabled at error level")
	}
	if New("error").Enabled(ctx, slog.LevelInfo) {
		t.Fatal("info must be filtered at error level")
	}
}
