package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

var Global *slog.Logger

func init() {
	// Initialize the global logger
	Global = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Config defines the logger configuration
type Config struct {
	Level      string `toml:"level"`       // debug, info, warn, error
	Format     string `toml:"format"`      // text, json
	OutputPath string `toml:"output_path"` // log file path
	MaxSize    int    `toml:"max_size"`    // maximum size in megabytes
	MaxAge     int    `toml:"max_age"`     // maximum age in days
	MaxBackups int    `toml:"max_backups"` // maximum number of old log files
	Compress   bool   `toml:"compress"`    // compress old files
}

// InitLogger Initialize the logger according to the configuration
func InitLogger(cfg *Config) error {
	// Create log directory
	if err := os.MkdirAll(filepath.Dir(cfg.OutputPath), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Configure log rotation
	writer := &lumberjack.Logger{
		Filename:   cfg.OutputPath,
		MaxSize:    cfg.MaxSize,    // MB
		MaxAge:     cfg.MaxAge,     // days
		MaxBackups: cfg.MaxBackups, // files
		Compress:   cfg.Compress,   // compress old files
	}

	// Output to both file and console
	multiWriter := io.MultiWriter(os.Stdout, writer)

	// Set log level
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create handler
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}

	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(multiWriter, opts)
	default:
		handler = slog.NewTextHandler(multiWriter, opts)
	}

	// Update the global logger
	Global = slog.New(handler)

	Global.Info("Logger initialized",
		"level", cfg.Level,
		"format", cfg.Format,
		"path", cfg.OutputPath)

	return nil
}

// SetupLogFile creates log directory and returns file path
func SetupLogFile(logDir string) (string, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create log directory: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02-15-04-05")
	return filepath.Join(logDir, fmt.Sprintf("mxtrack-%s.log", timestamp)), nil
}
