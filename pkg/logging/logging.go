package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

func New(level string) *slog.Logger {
	return NewWith(os.Stderr, level)
}

func NewWith(w io.Writer, level string) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: levelFrom(level)}))
}

func levelFrom(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
