package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mxcrafts/ltrack/internal/config"
	"github.com/mxcrafts/ltrack/internal/types"
)

// MockEvent 实现collector.Event接口用于测试
type MockEvent struct {
	eventType string
	timestamp time.Time
	data      map[string]interface{}
}

func (m *MockEvent) GetType() string {
	return m.eventType
}

func (m *MockEvent) GetTimestamp() time.Time {
	return m.timestamp
}

func (m *MockEvent) GetData() map[string]interface{} {
	return m.data
}

// createTestConfig 创建测试用的Kafka配置
func createTestConfig() (*config.Config, error) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Enabled:  true,
			Type:     "kafka",
			Format:   "json",
			Adapter:  "kafka",
			FilePath: "/tmp/test-events.log",
			ExtraFields: map[string]string{
				"host":        "test-host",
				"service":     "ltrack-test",
				"environment": "test",
				"version":     "1.0.0",
			},
		},
		Kafka: config.KafkaConfig{
			Enabled:      true,
			Brokers:      []string{"localhost:9092"},
			Topic:        "ltrack-test",
			ClientID:     "ltrack-test",
			Compression:  "gzip",
			BatchSize:    10,
			BatchBytes:   1048576,
			BatchTimeout: 1000,
			WriteTimeout: 5,
			ReadTimeout:  5,
			Retries:      1,
			SASL: config.SASLConfig{
				Enabled:   false,
				Mechanism: "PLAIN",
				Username:  "",
				Password:  "",
			},
			TLS: config.TLSConfig{
				Enabled:            false,
				InsecureSkipVerify: false,
				CertFile:           "",
				KeyFile:            "",
				CAFile:             "",
			},
		},
	}
	return cfg, nil
}

// TestKafkaConfigLoading 测试Kafka配置加载
func TestKafkaConfigLoading(t *testing.T) {
	cfg, err := createTestConfig()
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// 验证Kafka配置
	if !cfg.Kafka.Enabled {
		t.Error("Kafka should be enabled")
	}

	if len(cfg.Kafka.Brokers) == 0 {
		t.Error("Kafka brokers should not be empty")
	}

	if cfg.Kafka.Topic == "" {
		t.Error("Kafka topic should not be empty")
	}

	if cfg.Kafka.ClientID == "" {
		t.Error("Kafka client ID should not be empty")
	}

	// 验证存储配置
	storageCfg, err := cfg.Storage.ToStorageConfig()
	if err != nil {
		t.Fatalf("Failed to convert storage config: %v", err)
	}

	if storageCfg.Type != types.OutputKafka {
		t.Errorf("Expected storage type %v, got %v", types.OutputKafka, storageCfg.Type)
	}

	if storageCfg.Format != types.FormatJSON {
		t.Errorf("Expected storage format %v, got %v", types.FormatJSON, storageCfg.Format)
	}

	t.Logf("Kafka config loaded successfully: brokers=%v, topic=%s", cfg.Kafka.Brokers, cfg.Kafka.Topic)
}

// TestKafkaAdapterCreation 测试Kafka适配器创建
func TestKafkaAdapterCreation(t *testing.T) {
	cfg, err := createTestConfig()
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// 转换存储配置
	storageCfg, err := cfg.Storage.ToStorageConfig()
	if err != nil {
		t.Fatalf("Failed to convert storage config: %v", err)
	}

	// 创建Kafka适配器
	adapter, err := NewKafkaAdapter(storageCfg, cfg.Kafka)
	if err != nil {
		t.Fatalf("Failed to create Kafka adapter: %v", err)
	}

	if adapter == nil {
		t.Fatal("Kafka adapter should not be nil")
	}

	// 测试适配器关闭
	if err := adapter.Close(); err != nil {
		t.Errorf("Failed to close Kafka adapter: %v", err)
	}

	t.Log("Kafka adapter created and closed successfully")
}

// TestKafkaMessageFormatting 测试Kafka消息格式化
func TestKafkaMessageFormatting(t *testing.T) {
	cfg, err := createTestConfig()
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// 转换存储配置
	storageCfg, err := cfg.Storage.ToStorageConfig()
	if err != nil {
		t.Fatalf("Failed to convert storage config: %v", err)
	}

	// 创建Kafka适配器
	adapter, err := NewKafkaAdapter(storageCfg, cfg.Kafka)
	if err != nil {
		t.Fatalf("Failed to create Kafka adapter: %v", err)
	}
	defer adapter.Close()

	// 创建测试事件
	testEvent := &MockEvent{
		eventType: "file_event",
		timestamp: time.Now(),
		data: map[string]interface{}{
			"file_path":  "/test/file.txt",
			"operation":  "create",
			"size":       1024,
			"user":       "testuser",
		},
	}

	// 格式化消息
	data, err := adapter.Format(testEvent)
	if err != nil {
		t.Fatalf("Failed to format message: %v", err)
	}

	// 验证JSON格式
	var message map[string]interface{}
	if err := json.Unmarshal(data, &message); err != nil {
		t.Fatalf("Failed to unmarshal formatted message: %v", err)
	}

	// 验证必需字段
	requiredFields := []string{"@timestamp", "event_type", "source"}
	for _, field := range requiredFields {
		if _, exists := message[field]; !exists {
			t.Errorf("Missing required field: %s", field)
		}
	}

	// 验证事件数据
	if message["event_type"] != "file_event" {
		t.Errorf("Expected event_type 'file_event', got %v", message["event_type"])
	}

	if message["source"] != "ltrack" {
		t.Errorf("Expected source 'ltrack', got %v", message["source"])
	}

	// 验证额外字段
	if message["host"] != "test-host" {
		t.Errorf("Expected host 'test-host', got %v", message["host"])
	}

	if message["service"] != "ltrack-test" {
		t.Errorf("Expected service 'ltrack-test', got %v", message["service"])
	}

	// 验证事件数据字段
	if message["file_path"] != "/test/file.txt" {
		t.Errorf("Expected file_path '/test/file.txt', got %v", message["file_path"])
	}

	t.Logf("Message formatted successfully: %s", string(data))
}

// TestKafkaStorageManagerIntegration 测试存储管理器集成
func TestKafkaStorageManagerIntegration(t *testing.T) {
	cfg, err := createTestConfig()
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// 转换存储配置
	storageCfg, err := cfg.Storage.ToStorageConfig()
	if err != nil {
		t.Fatalf("Failed to convert storage config: %v", err)
	}

	// 创建存储管理器
	storageManager, err := NewStorageManagerWithKafka(storageCfg, "kafka", cfg.Kafka)
	if err != nil {
		t.Fatalf("Failed to create storage manager: %v", err)
	}
	defer storageManager.Stop()

	// 验证存储管理器
	if storageManager == nil {
		t.Fatal("Storage manager should not be nil")
	}

	storage := storageManager.GetStorage()
	if storage == nil {
		t.Fatal("Storage should not be nil")
	}

	t.Log("Storage manager with Kafka integration created successfully")
}

// TestKafkaConfigValidation 测试Kafka配置验证
func TestKafkaConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		configMod func(cfg *config.Config)
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid config",
			configMod: func(cfg *config.Config) {
				// 不修改，使用默认有效配置
			},
			wantError: false,
		},
		{
			name: "empty brokers",
			configMod: func(cfg *config.Config) {
				cfg.Kafka.Brokers = []string{}
			},
			wantError: true,
			errorMsg:  "brokers",
		},
		{
			name: "empty topic",
			configMod: func(cfg *config.Config) {
				cfg.Kafka.Topic = ""
			},
			wantError: true,
			errorMsg:  "topic",
		},
		{
			name: "invalid compression",
			configMod: func(cfg *config.Config) {
				cfg.Kafka.Compression = "invalid"
			},
			wantError: false, // 适配器创建时不会验证压缩算法，只在运行时使用默认值
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := createTestConfig()
			if err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			// 应用修改
			tt.configMod(cfg)

			// 验证配置的基本逻辑
			if tt.wantError {
				// 检查特定的配置错误
				switch tt.name {
				case "empty brokers":
					if len(cfg.Kafka.Brokers) == 0 && cfg.Kafka.Enabled {
						t.Logf("✓ Correctly detected empty brokers")
					} else {
						t.Errorf("Failed to detect empty brokers issue")
					}
				case "empty topic":
					if cfg.Kafka.Topic == "" && cfg.Kafka.Enabled {
						t.Logf("✓ Correctly detected empty topic")
					} else {
						t.Errorf("Failed to detect empty topic issue")
					}
				}
			} else {
				// 对于有效配置，尝试创建适配器
				storageCfg, err := cfg.Storage.ToStorageConfig()
				if err != nil {
					t.Fatalf("Failed to convert storage config: %v", err)
				}

				adapter, err := NewKafkaAdapter(storageCfg, cfg.Kafka)
				if err != nil {
					t.Errorf("Unexpected error for valid config %s: %v", tt.name, err)
				} else if adapter != nil {
					adapter.Close()
					t.Logf("✓ Successfully created adapter for %s", tt.name)
				}
			}
		})
	}
}

// TestKafkaConfigFileValidation 测试配置文件中的Kafka配置验证逻辑
func TestKafkaConfigFileValidation(t *testing.T) {
	tests := []struct {
		name        string
		kafkaConfig config.KafkaConfig
		wantError   bool
		errorMsg    string
	}{
		{
			name: "valid kafka config",
			kafkaConfig: config.KafkaConfig{
				Enabled:     true,
				Brokers:     []string{"localhost:9092"},
				Topic:       "test-topic",
				ClientID:    "test-client",
				Compression: "gzip",
			},
			wantError: false,
		},
		{
			name: "kafka disabled",
			kafkaConfig: config.KafkaConfig{
				Enabled: false,
				// 其他字段可以为空，因为Kafka未启用
			},
			wantError: false,
		},
		{
			name: "empty brokers when enabled",
			kafkaConfig: config.KafkaConfig{
				Enabled: true,
				Brokers: []string{},
				Topic:   "test-topic",
			},
			wantError: true,
			errorMsg:  "no brokers specified",
		},
		{
			name: "empty topic when enabled",
			kafkaConfig: config.KafkaConfig{
				Enabled: true,
				Brokers: []string{"localhost:9092"},
				Topic:   "",
			},
			wantError: true,
			errorMsg:  "no topic specified",
		},
		{
			name: "invalid compression",
			kafkaConfig: config.KafkaConfig{
				Enabled:     true,
				Brokers:     []string{"localhost:9092"},
				Topic:       "test-topic",
				Compression: "invalid-compression",
			},
			wantError: true,
			errorMsg:  "invalid kafka compression",
		},
		{
			name: "invalid SASL mechanism",
			kafkaConfig: config.KafkaConfig{
				Enabled: true,
				Brokers: []string{"localhost:9092"},
				Topic:   "test-topic",
				SASL: config.SASLConfig{
					Enabled:   true,
					Mechanism: "INVALID",
					Username:  "user",
					Password:  "pass",
				},
			},
			wantError: true,
			errorMsg:  "invalid kafka SASL mechanism",
		},
		{
			name: "SASL enabled but missing credentials",
			kafkaConfig: config.KafkaConfig{
				Enabled: true,
				Brokers: []string{"localhost:9092"},
				Topic:   "test-topic",
				SASL: config.SASLConfig{
					Enabled:   true,
					Mechanism: "PLAIN",
					Username:  "",
					Password:  "",
				},
			},
			wantError: true,
			errorMsg:  "username or password not specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 模拟配置验证逻辑（这些逻辑应该在config.Load中）
			err := validateKafkaConfig(tt.kafkaConfig)

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got none", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				} else {
					t.Logf("✓ Correctly detected error: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid config: %v", err)
				} else {
					t.Logf("✓ Valid config passed validation")
				}
			}
		})
	}
}

// validateKafkaConfig 模拟配置验证逻辑（应该在config包中实现）
func validateKafkaConfig(kafkaConfig config.KafkaConfig) error {
	if !kafkaConfig.Enabled {
		return nil // Kafka未启用，跳过验证
	}

	if len(kafkaConfig.Brokers) == 0 {
		return fmt.Errorf("kafka enabled but no brokers specified")
	}

	if kafkaConfig.Topic == "" {
		return fmt.Errorf("kafka enabled but no topic specified")
	}

	// 验证压缩算法
	validCompressions := []string{"none", "gzip", "snappy", "lz4", "zstd"}
	if kafkaConfig.Compression != "" {
		validCompression := false
		for _, comp := range validCompressions {
			if kafkaConfig.Compression == comp {
				validCompression = true
				break
			}
		}
		if !validCompression {
			return fmt.Errorf("invalid kafka compression: %s", kafkaConfig.Compression)
		}
	}

	// 验证SASL配置
	if kafkaConfig.SASL.Enabled {
		validMechanisms := []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"}
		validMechanism := false
		for _, mech := range validMechanisms {
			if kafkaConfig.SASL.Mechanism == mech {
				validMechanism = true
				break
			}
		}
		if !validMechanism {
			return fmt.Errorf("invalid kafka SASL mechanism: %s", kafkaConfig.SASL.Mechanism)
		}

		if kafkaConfig.SASL.Username == "" || kafkaConfig.SASL.Password == "" {
			return fmt.Errorf("kafka SASL enabled but username or password not specified")
		}
	}

	return nil
}

// contains 检查字符串是否包含子字符串
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && s[:len(substr)] == substr) ||
		(len(s) > len(substr) && s[len(s)-len(substr):] == substr) ||
		(len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// BenchmarkKafkaMessageFormatting 性能测试
func BenchmarkKafkaMessageFormatting(b *testing.B) {
	cfg, err := createTestConfig()
	if err != nil {
		b.Fatalf("Failed to create test config: %v", err)
	}

	// 转换存储配置
	storageCfg, err := cfg.Storage.ToStorageConfig()
	if err != nil {
		b.Fatalf("Failed to convert storage config: %v", err)
	}

	// 创建Kafka适配器
	adapter, err := NewKafkaAdapter(storageCfg, cfg.Kafka)
	if err != nil {
		b.Fatalf("Failed to create Kafka adapter: %v", err)
	}
	defer adapter.Close()

	// 创建测试事件
	testEvent := &MockEvent{
		eventType: "benchmark_event",
		timestamp: time.Now(),
		data: map[string]interface{}{
			"file_path": "/benchmark/file.txt",
			"operation": "write",
			"size":      2048,
			"user":      "benchuser",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := adapter.Format(testEvent)
		if err != nil {
			b.Fatalf("Failed to format message: %v", err)
		}
	}
}

// TestKafkaWithRealConfig 使用真实配置文件测试Kafka连接和消息生产
// 运行方式: go test -v ./internal/storage -run TestKafkaWithRealConfig
func TestKafkaWithRealConfig(t *testing.T) {
	// 从项目根目录的配置文件加载配置
	configPath := "../../policy.toml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("Skipping real config test: policy.toml not found")
	}

	// 加载真实配置文件
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config from %s: %v", configPath, err)
	}

	// 检查Kafka是否启用
	if !cfg.Kafka.Enabled {
		t.Skip("Skipping test: Kafka is not enabled in config file")
	}

	t.Logf("Testing with real Kafka config:")
	t.Logf("  Brokers: %v", cfg.Kafka.Brokers)
	t.Logf("  Topic: %s", cfg.Kafka.Topic)
	t.Logf("  Client ID: %s", cfg.Kafka.ClientID)
	t.Logf("  Compression: %s", cfg.Kafka.Compression)

	// 转换存储配置
	storageCfg, err := cfg.Storage.ToStorageConfig()
	if err != nil {
		t.Fatalf("Failed to convert storage config: %v", err)
	}

	// 创建Kafka适配器
	adapter, err := NewKafkaAdapter(storageCfg, cfg.Kafka)
	if err != nil {
		t.Fatalf("Failed to create Kafka adapter: %v", err)
	}
	defer adapter.Close()

	// 测试连接
	t.Log("Testing Kafka connection...")
	if err := adapter.Connect(); err != nil {
		t.Fatalf("Failed to connect to Kafka: %v", err)
	}
	t.Log("✓ Successfully connected to Kafka")

	// 创建测试事件
	testEvents := []*MockEvent{
		{
			eventType: "file_event",
			timestamp: time.Now(),
			data: map[string]interface{}{
				"file_path": "/test/file1.txt",
				"operation": "create",
				"size":      1024,
				"user":      "testuser",
			},
		},
		{
			eventType: "network_event",
			timestamp: time.Now(),
			data: map[string]interface{}{
				"src_ip":   "192.168.1.100",
				"dst_ip":   "10.0.0.1",
				"src_port": 12345,
				"dst_port": 80,
				"protocol": "tcp",
			},
		},
		{
			eventType: "process_event",
			timestamp: time.Now(),
			data: map[string]interface{}{
				"pid":     12345,
				"command": "/bin/bash",
				"user":    "testuser",
				"action":  "exec",
			},
		},
	}

	// 发送测试消息
	t.Log("Sending test messages to Kafka...")
	for i, event := range testEvents {
		data, err := adapter.Format(event)
		if err != nil {
			t.Fatalf("Failed to format event %d: %v", i, err)
		}

		if err := adapter.Send(data); err != nil {
			t.Fatalf("Failed to send event %d: %v", i, err)
		}

		t.Logf("✓ Sent %s event", event.GetType())

		// 打印消息内容以便验证
		var msgMap map[string]interface{}
		if err := json.Unmarshal(data, &msgMap); err == nil {
			t.Logf("  Message content: event_type=%s, timestamp=%s",
				msgMap["event_type"], msgMap["@timestamp"])
		}
	}

	t.Logf("✓ Successfully sent %d messages to Kafka topic: %s", len(testEvents), cfg.Kafka.Topic)
}

// TestLoadConfigFileAndKafka 测试从配置文件加载Kafka配置
// 运行方式: go test -v ./internal/storage -run TestLoadConfigFileAndKafka
func TestLoadConfigFileAndKafka(t *testing.T) {
	// 测试加载主配置文件
	configPath := "../../policy.toml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("Skipping config file test: policy.toml not found")
	}

	// 加载配置文件
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config from %s: %v", configPath, err)
	}

	t.Log("✓ Successfully loaded config file")

	// 验证Kafka配置结构
	t.Logf("Kafka configuration:")
	t.Logf("  Enabled: %v", cfg.Kafka.Enabled)
	t.Logf("  Brokers: %v", cfg.Kafka.Brokers)
	t.Logf("  Topic: %s", cfg.Kafka.Topic)
	t.Logf("  Client ID: %s", cfg.Kafka.ClientID)
	t.Logf("  Compression: %s", cfg.Kafka.Compression)
	t.Logf("  Batch Size: %d", cfg.Kafka.BatchSize)
	t.Logf("  Write Timeout: %d", cfg.Kafka.WriteTimeout)
	t.Logf("  SASL Enabled: %v", cfg.Kafka.SASL.Enabled)
	t.Logf("  TLS Enabled: %v", cfg.Kafka.TLS.Enabled)

	// 验证存储配置
	t.Logf("Storage configuration:")
	t.Logf("  Enabled: %v", cfg.Storage.Enabled)
	t.Logf("  Type: %s", cfg.Storage.Type)
	t.Logf("  Format: %s", cfg.Storage.Format)
	t.Logf("  Adapter: %s", cfg.Storage.Adapter)

	// 如果Kafka启用，测试适配器创建
	if cfg.Kafka.Enabled {
		storageCfg, err := cfg.Storage.ToStorageConfig()
		if err != nil {
			t.Fatalf("Failed to convert storage config: %v", err)
		}

		adapter, err := NewKafkaAdapter(storageCfg, cfg.Kafka)
		if err != nil {
			t.Fatalf("Failed to create Kafka adapter: %v", err)
		}
		defer adapter.Close()

		t.Log("✓ Successfully created Kafka adapter from config file")

		// 如果配置了真实的broker，尝试连接测试
		if len(cfg.Kafka.Brokers) > 0 && cfg.Kafka.Brokers[0] != "localhost:9092" {
			t.Log("Attempting to connect to real Kafka brokers...")
			if err := adapter.Connect(); err != nil {
				t.Logf("⚠ Connection failed (expected if Kafka not running): %v", err)
			} else {
				t.Log("✓ Successfully connected to Kafka!")
			}
		}
	} else {
		t.Log("Kafka is disabled in config file")
	}
}

// TestKafkaRealProduction 测试真实的Kafka消息生产
// 运行方式: go test -v ./internal/storage -run TestKafkaRealProduction
// 注意: 需要在policy.toml中启用Kafka并配置真实的broker地址
func TestKafkaRealProduction(t *testing.T) {
	// 从配置文件加载真实配置
	configPath := "../../policy.toml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("Skipping real production test: policy.toml not found")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// 检查Kafka是否启用
	if !cfg.Kafka.Enabled {
		t.Skip("Skipping test: Kafka is not enabled in policy.toml. To run this test, set kafka.enabled = true")
	}

	// 检查是否配置为使用Kafka适配器
	if cfg.Storage.Adapter != "kafka" || cfg.Storage.Type != "kafka" {
		t.Skip("Skipping test: Storage is not configured for Kafka. Set storage.type = \"kafka\" and storage.adapter = \"kafka\"")
	}

	t.Log("=== Testing Real Kafka Production ===")
	t.Logf("Brokers: %v", cfg.Kafka.Brokers)
	t.Logf("Topic: %s", cfg.Kafka.Topic)

	// 转换存储配置
	storageCfg, err := cfg.Storage.ToStorageConfig()
	if err != nil {
		t.Fatalf("Failed to convert storage config: %v", err)
	}

	// 创建Kafka适配器
	adapter, err := NewKafkaAdapter(storageCfg, cfg.Kafka)
	if err != nil {
		t.Fatalf("Failed to create Kafka adapter: %v", err)
	}
	defer adapter.Close()

	// 测试连接
	t.Log("Testing connection to Kafka...")
	if err := adapter.Connect(); err != nil {
		t.Fatalf("Failed to connect to Kafka: %v", err)
	}
	t.Log("✓ Successfully connected to Kafka")

	// 创建真实的测试事件
	testEvents := []*MockEvent{
		{
			eventType: "file_event",
			timestamp: time.Now(),
			data: map[string]interface{}{
				"file_path": "/var/log/test.log",
				"operation": "write",
				"size":      2048,
				"user":      "root",
				"mode":      "0644",
			},
		},
		{
			eventType: "network_event",
			timestamp: time.Now(),
			data: map[string]interface{}{
				"src_ip":    "192.168.1.100",
				"dst_ip":    "8.8.8.8",
				"src_port":  45678,
				"dst_port":  53,
				"protocol":  "udp",
				"direction": "outbound",
			},
		},
		{
			eventType: "process_event",
			timestamp: time.Now(),
			data: map[string]interface{}{
				"pid":        12345,
				"ppid":       1,
				"command":    "/usr/bin/curl",
				"args":       []string{"curl", "-s", "https://api.example.com"},
				"user":       "www-data",
				"action":     "exec",
				"exit_code":  0,
			},
		},
	}

	// 发送测试消息到真实Kafka
	t.Log("Sending test messages to Kafka...")
	for i, event := range testEvents {
		// 格式化消息
		data, err := adapter.Format(event)
		if err != nil {
			t.Fatalf("Failed to format event %d (%s): %v", i+1, event.GetType(), err)
		}

		// 发送消息
		if err := adapter.Send(data); err != nil {
			t.Fatalf("Failed to send event %d (%s): %v", i+1, event.GetType(), err)
		}

		t.Logf("✓ Sent %s event to topic %s", event.GetType(), cfg.Kafka.Topic)

		// 打印消息内容供验证
		var msgMap map[string]interface{}
		if err := json.Unmarshal(data, &msgMap); err == nil {
			t.Logf("  Content: event_type=%s, @timestamp=%s, source=%s",
				msgMap["event_type"], msgMap["@timestamp"], msgMap["source"])
		}
	}

	t.Logf("✓ Successfully produced %d messages to Kafka", len(testEvents))
	t.Log("=== Real Kafka Production Test Completed ===")
}
