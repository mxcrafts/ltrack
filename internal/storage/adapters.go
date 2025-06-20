package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/types"
	"github.com/mxcrafts/ltrack/pkg/logger"
	"gopkg.in/natefinch/lumberjack.v2"
)

// This file provides adapters for different log collection systems

// LogAdapter defines the log adapter interface
type LogAdapter interface {
	// Convert event to the format required by the log system
	// Connect to the log system (if needed)
	// Close the connection
	// Send log to the target system
	Format(event collector.Event) ([]byte, error)
	Connect() error
	Close() error
	Send(data []byte) error
}

// BaseAdapter provides basic adapter functionality
type BaseAdapter struct {
	config    Config
	conn      net.Conn
	connected bool
}

// Connect to remote server (if needed)
func (a *BaseAdapter) Connect() error {
	if a.config.Type != types.OutputSocket || a.connected {
		return nil
	}

	address := net.JoinHostPort(a.config.RemoteAddr, fmt.Sprintf("%d", a.config.RemotePort))
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to log server: %w", err)
	}

	a.conn = conn
	a.connected = true
	return nil
}

// Close the connection
func (a *BaseAdapter) Close() error {
	if a.connected && a.conn != nil {
		a.connected = false
		return a.conn.Close()
	}
	return nil
}

// Send data to the target system
func (a *BaseAdapter) Send(data []byte) error {
	if !a.connected {
		if err := a.Connect(); err != nil {
			return err
		}
	}

	if a.config.Type == types.OutputSocket && a.conn != nil {
		_, err := a.conn.Write(data)
		return err
	}

	return nil
}

// ElasticsearchAdapter provides formatting for Elasticsearch
type ElasticsearchAdapter struct {
	BaseAdapter
	indexName string
}

// NewElasticsearchAdapter creates a new Elasticsearch adapter
func NewElasticsearchAdapter(cfg Config, indexName string) *ElasticsearchAdapter {
	return &ElasticsearchAdapter{
		BaseAdapter: BaseAdapter{
			config: cfg,
		},
		indexName: indexName,
	}
}

// Format formats the event to be compatible with Elasticsearch
func (a *ElasticsearchAdapter) Format(event collector.Event) ([]byte, error) {
	// Build the basic log entry
	logEntry := map[string]interface{}{
		"@timestamp": event.GetTimestamp().Format(time.RFC3339),
		"event_type": event.GetType(),
	}

	// Add event data
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		eventData := dataProvider.GetData()
		for k, v := range eventData {
			if k != "@timestamp" {
				logEntry[k] = v
			}
		}
	}

	// Add Elasticsearch-specific metadata
	for k, v := range a.config.ExtraFields {
		logEntry[k] = v
	}

	// Format as JSON
	data, err := json.Marshal(logEntry)
	if err != nil {
		return nil, fmt.Errorf("json serialization failed: %w", err)
	}

	// Add newline
	return append(data, '\n'), nil
}

// LogstashAdapter provides formatting for Logstash
type LogstashAdapter struct {
	BaseAdapter
	fields []string
}

// NewLogstashAdapter creates a new Logstash adapter
func NewLogstashAdapter(cfg Config, fields []string) *LogstashAdapter {
	return &LogstashAdapter{
		BaseAdapter: BaseAdapter{
			config: cfg,
		},
		fields: fields,
	}
}

// Format formats the event to be compatible with Logstash
func (a *LogstashAdapter) Format(event collector.Event) ([]byte, error) {
	// Build the basic log entry
	logEntry := map[string]interface{}{
		"@timestamp": event.GetTimestamp().Format(time.RFC3339),
		"@version":   "1", // Logstash standard field
		"type":       event.GetType(),
		"tags":       a.fields,
	}

	// Add event data
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		eventData := dataProvider.GetData()
		for k, v := range eventData {
			if k != "@timestamp" && k != "@version" && k != "type" && k != "tags" {
				logEntry[k] = v
			}
		}
	}

	// Add extra fields from config
	for k, v := range a.config.ExtraFields {
		if k != "@timestamp" && k != "@version" && k != "type" && k != "tags" {
			logEntry[k] = v
		}
	}

	// Format as JSON
	data, err := json.Marshal(logEntry)
	if err != nil {
		return nil, fmt.Errorf("json serialization failed: %w", err)
	}

	return append(data, '\n'), nil
}

// FluentdAdapter provides formatting for Fluentd
type FluentdAdapter struct {
	BaseAdapter
	tag string
}

// NewFluentdAdapter creates a new Fluentd adapter
func NewFluentdAdapter(cfg Config, tag string) *FluentdAdapter {
	return &FluentdAdapter{
		BaseAdapter: BaseAdapter{
			config: cfg,
		},
		tag: tag,
	}
}

// Format formats the event to be compatible with Fluentd
func (a *FluentdAdapter) Format(event collector.Event) ([]byte, error) {
	// Determine tag
	tag := a.tag
	if tag == "" {
		tag = "ltrack"
		if v, ok := a.config.ExtraFields["tag"]; ok {
			tag = v
		}
	}

	// In Fluentd, the tag is usually in the message header
	// But for file output, we add it as a field

	// Build the basic log entry
	logEntry := map[string]interface{}{
		"time":  event.GetTimestamp().Unix(),
		"tag":   tag,
		"type":  event.GetType(),
		"event": event.GetType(),
	}

	// Add event data
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		logEntry["record"] = dataProvider.GetData()
	}

	// Add extra fields from config as part of the record
	if record, ok := logEntry["record"].(map[string]interface{}); ok {
		for k, v := range a.config.ExtraFields {
			if k != "tag" {
				record[k] = v
			}
		}
	}

	// Format as JSON
	data, err := json.Marshal(logEntry)
	if err != nil {
		return nil, fmt.Errorf("json serialization failed: %w", err)
	}

	return append(data, '\n'), nil
}

// GraylogAdapter provides formatting for Graylog
type GraylogAdapter struct {
	BaseAdapter
	facility string
}

// NewGraylogAdapter creates a new Graylog adapter
func NewGraylogAdapter(cfg Config, facility string) *GraylogAdapter {
	if facility == "" {
		facility = "ltrack"
	}

	return &GraylogAdapter{
		BaseAdapter: BaseAdapter{
			config: cfg,
		},
		facility: facility,
	}
}

// Format formats the event to GELF (Graylog Extended Log Format)
func (a *GraylogAdapter) Format(event collector.Event) ([]byte, error) {
	// Graylog uses GELF format, which requires specific fields
	// Reference: https://docs.graylog.org/docs/gelf

	// Build the basic GELF entry
	gelfEntry := map[string]interface{}{
		"version":       "1.1",       // GELF version
		"host":          "localhost", // Default hostname
		"short_message": fmt.Sprintf("Event: %s", event.GetType()),
		"timestamp":     float64(event.GetTimestamp().UnixNano()) / 1e9, // Unix timestamp (seconds)
		"level":         5,                                              // Default level: Notice
		"facility":      a.facility,                                     // Facility name
	}

	// Set hostname
	if host, ok := a.config.ExtraFields["host"]; ok {
		gelfEntry["host"] = host
	}

	// Add event data as additional fields (with prefix "_")
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		eventData := dataProvider.GetData()

		// If there is a detailed message, use it
		if msg, ok := eventData["message"]; ok {
			if msgStr, isStr := msg.(string); isStr {
				gelfEntry["full_message"] = msgStr
			}
		}

		// Add other fields as additional fields
		for k, v := range eventData {
			if k != "message" {
				gelfEntry["_"+k] = v
			}
		}
	}

	// Add extra fields from config as additional fields
	for k, v := range a.config.ExtraFields {
		if k != "host" && k != "version" && k != "short_message" &&
			k != "full_message" && k != "timestamp" && k != "level" &&
			k != "facility" {
			gelfEntry["_"+k] = v
		}
	}

	// Add event type as an additional field
	gelfEntry["_event_type"] = event.GetType()

	// Format as JSON
	data, err := json.Marshal(gelfEntry)
	if err != nil {
		return nil, fmt.Errorf("json serialization failed: %w", err)
	}

	return append(data, '\n'), nil
}

// AdapterStorage implements storage using an adapter
type AdapterStorage struct {
	BaseStorage
	adapter LogAdapter
}

// NewAdapterStorage creates a storage using the specified adapter
func NewAdapterStorage(cfg Config, adapter LogAdapter) (Storage, error) {
	storage := &AdapterStorage{
		BaseStorage: BaseStorage{
			config: cfg,
		},
		adapter: adapter,
	}

	// Initialize writer according to config type
	switch cfg.Type {
	case types.OutputFile:
		// Ensure log directory exists
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
		storage.BaseStorage.writer = fileWriter
		storage.BaseStorage.closer = fileWriter
	case types.OutputStdout:
		storage.BaseStorage.writer = os.Stdout
		storage.BaseStorage.closer = nil
	case types.OutputSocket:
		// For Socket type, writer can be nil because we use the adapter's Send method
		// But to prevent ProcessEvents from reporting errors, use os.Stdout as default
		storage.BaseStorage.writer = os.Stdout
		storage.BaseStorage.closer = nil
	default:
		return nil, fmt.Errorf("unsupported output type: %s", cfg.Type)
	}

	// Ensure writer is properly initialized
	if storage.BaseStorage.writer == nil {
		logger.Global.Warn("Storage writer not initialized, using standard output as fallback")
		storage.BaseStorage.writer = os.Stdout
	}

	// Connect to remote server (if needed)
	if err := adapter.Connect(); err != nil {
		return nil, err
	}

	return storage, nil
}

// Store stores the event using the adapter
func (s *AdapterStorage) Store(event collector.Event) error {
	// Format the event using the adapter
	data, err := s.adapter.Format(event)
	if err != nil {
		return fmt.Errorf("failed to format event: %w", err)
	}

	// Store according to config type
	switch s.config.Type {
	case types.OutputFile:
		// Ensure writer is initialized
		if s.writer == nil {
			return fmt.Errorf("file writer not initialized")
		}
		_, err = s.writer.Write(data)
	case types.OutputStdout:
		// Output to standard output
		fmt.Print(string(data))
	case types.OutputSocket:
		// Use the adapter to send data
		err = s.adapter.Send(data)
	default:
		err = fmt.Errorf("unsupported output type: %s", s.config.Type)
	}

	return err
}

// Close closes the storage and adapter
func (s *AdapterStorage) Close() error {
	// First close the base storage
	if err := s.BaseStorage.Close(); err != nil {
		logger.Global.Error("Failed to close base storage", "error", err)
	}

	// Then close the adapter
	return s.adapter.Close()
}

// GetAdapterByName gets the adapter by name
func GetAdapterByName(name string, cfg Config) (LogAdapter, error) {
	name = strings.ToLower(name)

	switch name {
	case "elasticsearch":
		indexName := "ltrack-events"
		if v, ok := cfg.ExtraFields["index_name"]; ok {
			indexName = v
		}
		return NewElasticsearchAdapter(cfg, indexName), nil

	case "logstash":
		fields := []string{"ltrack"}
		if v, ok := cfg.ExtraFields["fields"]; ok {
			fields = []string{v}
		}
		return NewLogstashAdapter(cfg, fields), nil

	case "fluentd":
		tag := "ltrack"
		if v, ok := cfg.ExtraFields["tag"]; ok {
			tag = v
		}
		return NewFluentdAdapter(cfg, tag), nil

	case "graylog":
		facility := "ltrack"
		if v, ok := cfg.ExtraFields["facility"]; ok {
			facility = v
		}
		return NewGraylogAdapter(cfg, facility), nil

	default:
		return nil, fmt.Errorf("unknown adapter type: %s", name)
	}
}
