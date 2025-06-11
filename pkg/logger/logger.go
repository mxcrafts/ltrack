package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	EnvLogLevel  = "LTRACK_LOG_LEVEL"
	EnvLogFormat = "LTRACK_LOG_FORMAT"
)

var Global *slog.Logger

// Add custom log level constants
const (
	LevelTrace = slog.Level(-8)
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

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

// getLogLevelFromEnv get log level from environment variable
func getLogLevelFromEnv() slog.Level {
	levelStr := strings.ToLower(os.Getenv(EnvLogLevel))
	switch levelStr {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// InitLogger initialize the logger according to the configuration
func InitLogger(cfg *Config) error {
	// Prioritize the logging level in the environment variable
	level := getLogLevelFromEnv()

	// If the environment variable is not set, use the configuration file level
	if os.Getenv(EnvLogLevel) == "" {
		switch strings.ToLower(cfg.Level) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}

	format := os.Getenv(EnvLogFormat)
	if format == "" {
		format = cfg.Format
	}

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

	// Update the global logger with enhanced logging options
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Add timestamp in a more readable format
			if a.Key == slog.TimeKey {
				return slog.Attr{
					Key:   slog.TimeKey,
					Value: slog.StringValue(a.Value.Time().Format("2006-01-02 15:04:05.000")),
				}
			}
			return a
		},
	}

	// Create handler based on format
	var handler slog.Handler
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(multiWriter, opts)
	default:
		handler = slog.NewTextHandler(multiWriter, opts)
	}

	Global = slog.New(handler)

	// Log initialization with all relevant details
	Global.Info("Logger initialized",
		"level", level,
		"format", format,
		"path", cfg.OutputPath,
		"env_level", os.Getenv(EnvLogLevel),
		"env_format", os.Getenv(EnvLogFormat))

	return nil
}

// SetupLogFile create log directory and return file path
func SetupLogFile(logDir string) (string, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create log directory: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02-15-04-05")
	return filepath.Join(logDir, fmt.Sprintf("ltrack-%s.log", timestamp)), nil
}
