package storage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/config"
	"github.com/mxcrafts/ltrack/internal/types"
	"github.com/mxcrafts/ltrack/pkg/logger"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
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
	case types.OutputKafka:
		// For Kafka type, we don't need a writer since we use the adapter's Send method
		// Set writer to nil to avoid duplicate output
		storage.BaseStorage.writer = nil
		storage.BaseStorage.closer = nil
	default:
		return nil, fmt.Errorf("unsupported output type: %s", cfg.Type)
	}

	// Ensure writer is properly initialized (except for Kafka which doesn't need a writer)
	if storage.BaseStorage.writer == nil && cfg.Type != types.OutputKafka {
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
	case types.OutputKafka:
		// Use the adapter to send data to Kafka
		err = s.adapter.Send(data)
	default:
		err = fmt.Errorf("unsupported output type: %s", s.config.Type)
	}

	return err
}

// ProcessEvents processes the event channel for adapter storage
func (s *AdapterStorage) ProcessEvents(ctx context.Context, events <-chan collector.Event) error {
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

	case "kafka":
		// Kafka适配器需要额外的配置信息，这里需要从全局配置中获取
		// 注意：这里需要传入完整的Kafka配置
		return nil, fmt.Errorf("kafka adapter requires additional configuration, use NewKafkaAdapter directly")

	default:
		return nil, fmt.Errorf("unknown adapter type: %s", name)
	}
}

// KafkaAdapter Kafka适配器
type KafkaAdapter struct {
	BaseAdapter
	writer *kafka.Writer
	config config.KafkaConfig
}

// NewKafkaAdapter 创建新的Kafka适配器
func NewKafkaAdapter(cfg Config, kafkaConfig config.KafkaConfig) (*KafkaAdapter, error) {
	adapter := &KafkaAdapter{
		BaseAdapter: BaseAdapter{
			config: cfg,
		},
		config: kafkaConfig,
	}

	// 创建Kafka Writer
	writer := &kafka.Writer{
		Addr:         kafka.TCP(kafkaConfig.Brokers...),
		Topic:        kafkaConfig.Topic,
		BatchSize:    kafkaConfig.BatchSize,
		BatchBytes:   int64(kafkaConfig.BatchBytes),
		BatchTimeout: time.Duration(kafkaConfig.BatchTimeout) * time.Millisecond,
		WriteTimeout: time.Duration(kafkaConfig.WriteTimeout) * time.Second,
		ReadTimeout:  time.Duration(kafkaConfig.ReadTimeout) * time.Second,
		RequiredAcks: kafka.RequireOne, // 等待leader确认
		Async:        false,             // 同步写入
	}

	// 设置压缩算法
	switch kafkaConfig.Compression {
	case "gzip":
		writer.Compression = kafka.Gzip
	case "snappy":
		writer.Compression = kafka.Snappy
	case "lz4":
		writer.Compression = kafka.Lz4
	case "zstd":
		writer.Compression = kafka.Zstd
	case "none":
		// 不设置压缩
	default:
		writer.Compression = kafka.Gzip // 默认使用gzip
	}

	// 配置TLS和SASL
	dialer := &kafka.Dialer{
		Timeout:   10 * time.Second,
		DualStack: true,
	}

	// 配置TLS
	if kafkaConfig.TLS.Enabled {
		tlsConfig, err := createTLSConfig(kafkaConfig.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		dialer.TLS = tlsConfig
	}

	// 配置SASL认证
	if kafkaConfig.SASL.Enabled {
		mechanism, err := createSASLMechanism(kafkaConfig.SASL)
		if err != nil {
			return nil, fmt.Errorf("failed to create SASL mechanism: %w", err)
		}
		dialer.SASLMechanism = mechanism
	}

	// 如果配置了TLS或SASL，设置自定义dialer
	if kafkaConfig.TLS.Enabled || kafkaConfig.SASL.Enabled {
		writer.Transport = &kafka.Transport{
			Dial: dialer.DialFunc,
		}
	}

	// 设置Writer到适配器
	adapter.writer = writer

	return adapter, nil
}

// Format 格式化事件为Kafka消息
func (a *KafkaAdapter) Format(event collector.Event) ([]byte, error) {
	// 构建基本日志条目
	logEntry := map[string]interface{}{
		"@timestamp": event.GetTimestamp().Format(time.RFC3339),
		"event_type": event.GetType(),
		"source":     "ltrack",
	}

	// 添加事件数据
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		eventData := dataProvider.GetData()
		for k, v := range eventData {
			if k != "@timestamp" && k != "event_type" && k != "source" {
				logEntry[k] = v
			}
		}
	}

	// 添加配置中的额外字段
	for k, v := range a.BaseAdapter.config.ExtraFields {
		if _, exists := logEntry[k]; !exists {
			logEntry[k] = v
		}
	}

	// 序列化为JSON
	data, err := json.Marshal(logEntry)
	if err != nil {
		return nil, fmt.Errorf("json serialization failed: %w", err)
	}

	return data, nil
}

// Connect 连接到Kafka集群
func (a *KafkaAdapter) Connect() error {
	// kafka-go的Writer会自动处理连接，这里可以做一些连接测试
	// 创建一个临时的连接来测试连通性
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 尝试获取topic的元数据来验证连接
	conn, err := kafka.DialContext(ctx, "tcp", a.config.Brokers[0])
	if err != nil {
		return fmt.Errorf("failed to connect to kafka broker: %w", err)
	}
	defer conn.Close()

	// 检查topic是否存在
	partitions, err := conn.ReadPartitions(a.config.Topic)
	if err != nil {
		logger.Global.Warn("Failed to read topic partitions, topic may not exist",
			"topic", a.config.Topic, "error", err)
		// 不返回错误，因为topic可能会自动创建
	} else {
		logger.Global.Info("Successfully connected to Kafka",
			"topic", a.config.Topic, "partitions", len(partitions))
	}

	return nil
}

// Send 发送数据到Kafka
func (a *KafkaAdapter) Send(data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(a.config.WriteTimeout)*time.Second)
	defer cancel()

	// 创建Kafka消息
	message := kafka.Message{
		Key:   []byte(fmt.Sprintf("ltrack-%d", time.Now().UnixNano())), // 使用时间戳作为key
		Value: data,
		Time:  time.Now(),
	}

	// 发送消息
	logger.Global.Debug("Attempting to send message to Kafka",
		"topic", a.config.Topic,
		"message_size", len(data))

	err := a.writer.WriteMessages(ctx, message)
	if err != nil {
		logger.Global.Error("Failed to send message to Kafka",
			"topic", a.config.Topic,
			"error", err,
			"message_size", len(data))
		return fmt.Errorf("failed to write message to kafka: %w", err)
	}

	logger.Global.Debug("Successfully sent message to Kafka",
		"topic", a.config.Topic,
		"message_size", len(data))
	return nil
}

// Close 关闭Kafka连接
func (a *KafkaAdapter) Close() error {
	if a.writer != nil {
		err := a.writer.Close()
		if err != nil {
			return fmt.Errorf("failed to close kafka writer: %w", err)
		}
	}
	return a.BaseAdapter.Close()
}

// createTLSConfig 创建TLS配置
func createTLSConfig(tlsConfig config.TLSConfig) (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
	}

	// 加载客户端证书
	if tlsConfig.CertFile != "" && tlsConfig.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsConfig.CertFile, tlsConfig.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	// 加载CA证书
	if tlsConfig.CAFile != "" {
		caCert, err := ioutil.ReadFile(tlsConfig.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		cfg.RootCAs = caCertPool
	}

	return cfg, nil
}

// createSASLMechanism 创建SASL认证机制
func createSASLMechanism(saslConfig config.SASLConfig) (sasl.Mechanism, error) {
	switch saslConfig.Mechanism {
	case "PLAIN":
		return plain.Mechanism{
			Username: saslConfig.Username,
			Password: saslConfig.Password,
		}, nil
	case "SCRAM-SHA-256":
		mechanism, err := scram.Mechanism(scram.SHA256, saslConfig.Username, saslConfig.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to create SCRAM-SHA-256 mechanism: %w", err)
		}
		return mechanism, nil
	case "SCRAM-SHA-512":
		mechanism, err := scram.Mechanism(scram.SHA512, saslConfig.Username, saslConfig.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to create SCRAM-SHA-512 mechanism: %w", err)
		}
		return mechanism, nil
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism: %s", saslConfig.Mechanism)
	}
}
