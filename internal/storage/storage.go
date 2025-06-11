package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/types"
	"github.com/mxcrafts/ltrack/pkg/logger"
)

// Config alias, use the config type from the types package
type Config = types.StorageConfig

// Storage defines the storage interface
type Storage interface {
	// Store stores a single event
	Store(event collector.Event) error
	// StoreMany stores multiple events in batch
	StoreMany(events []collector.Event) error
	// ProcessEvents continuously processes events from the channel
	ProcessEvents(ctx context.Context, events <-chan collector.Event) error
	// Close closes the storage and releases resources
	Close() error
}

// BaseStorage provides a basic storage implementation
type BaseStorage struct {
	config Config
	writer io.Writer
	closer io.Closer
}

// NewStorage creates a new storage instance
func NewStorage(cfg Config) (Storage, error) {
	storage := &BaseStorage{
		config: cfg,
	}

	// Initialize the specific storage implementation according to the config type
	switch cfg.Type {
	case types.OutputFile:
		// Ensure the log directory exists
		if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Use lumberjack for log rotation
		fileWriter := &lumberjack.Logger{
			Filename:   cfg.FilePath,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		}
		storage.writer = fileWriter
		storage.closer = fileWriter
	case types.OutputStdout:
		storage.writer = os.Stdout
		storage.closer = nil
	case types.OutputSocket:
		// Network connection can be implemented here
		return nil, fmt.Errorf("socket output not implemented yet")
	case types.OutputSyslog:
		// Syslog output can be implemented here
		return nil, fmt.Errorf("syslog output not implemented yet")
	default:
		return nil, fmt.Errorf("unknown output type: %s", cfg.Type)
	}

	// Ensure writer is properly initialized
	if storage.writer == nil {
		logger.Global.Warn("Storage writer not initialized, using standard output as fallback")
		storage.writer = os.Stdout
	}

	return storage, nil
}

// Store implements single event storage
func (s *BaseStorage) Store(event collector.Event) error {
	// Safety check: ensure event and writer are not nil
	if event == nil {
		return fmt.Errorf("event is nil, cannot store")
	}

	if s.writer == nil {
		logger.Global.Error("Storage writer not initialized")
		return fmt.Errorf("storage writer not initialized")
	}

	// Convert the event to the appropriate log format according to the config format
	var data []byte
	var err error

	switch s.config.Format {
	case types.FormatJSON, types.FormatNDJSON:
		// Build a standardized log structure
		logEntry := s.buildLogEntry(event)
		data, err = json.Marshal(logEntry)
		if err != nil {
			return fmt.Errorf("json serialization failed: %w", err)
		}
		// NDJSON requires a newline
		data = append(data, '\n')
	case types.FormatText:
		// Simple text format
		typeStr := event.GetType()
		timestamp := event.GetTimestamp().Format(time.RFC3339)
		data = []byte(fmt.Sprintf("[%s] %s: %s\n", timestamp, typeStr, s.formatEventAsText(event)))
	default:
		return fmt.Errorf("unknown log format: %s", s.config.Format)
	}

	// Write to storage
	_, err = s.writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write log: %w", err)
	}

	return nil
}

// StoreMany stores multiple events in batch
func (s *BaseStorage) StoreMany(events []collector.Event) error {
	for _, event := range events {
		if err := s.Store(event); err != nil {
			return err
		}
	}
	return nil
}

// ProcessEvents processes the event channel
func (s *BaseStorage) ProcessEvents(ctx context.Context, events <-chan collector.Event) error {
	// Safety check
	if s.writer == nil {
		return fmt.Errorf("storage writer not initialized, cannot process events")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				// Channel closed
				return nil
			}

			if event == nil {
				logger.Global.Warn("Received nil event, skipped")
				continue
			}

			if err := s.Store(event); err != nil {
				logger.Global.Error("Failed to store event", "error", err)
			}
		}
	}
}

// Close closes the storage
func (s *BaseStorage) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

// buildLogEntry builds a standardized log entry
func (s *BaseStorage) buildLogEntry(event collector.Event) map[string]interface{} {
	// Basic log structure
	logEntry := map[string]interface{}{
		"@timestamp": event.GetTimestamp().Format(time.RFC3339),
		"type":       event.GetType(),
	}

	// Add event-specific data
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		eventData := dataProvider.GetData()
		if eventData != nil {
			for k, v := range eventData {
				// Avoid overwriting core fields
				if k != "@timestamp" && k != "type" {
					logEntry[k] = v
				}
			}
		}
	}

	// Add extra fields from config
	if s.config.ExtraFields != nil {
		for k, v := range s.config.ExtraFields {
			// Avoid overwriting event data
			if _, exists := logEntry[k]; !exists {
				logEntry[k] = v
			}
		}
	}

	return logEntry
}

// formatEventAsText formats the event as text
func (s *BaseStorage) formatEventAsText(event collector.Event) string {
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		eventData := dataProvider.GetData()
		if eventData == nil {
			return "<nil data>"
		}
		// Simple formatting as key-value pairs
		var result string
		for k, v := range eventData {
			result += fmt.Sprintf("%s=%v ", k, v)
		}
		return result
	}
	return fmt.Sprintf("%v", event)
}
