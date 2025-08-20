package config

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/mxcrafts/ltrack/internal/types"
	"github.com/mxcrafts/ltrack/pkg/logger"
)

// ConfigMonitor Define configuration monitor
type ConfigMonitor struct {
	configPath string
}

func NewConfigMonitor(path string) *ConfigMonitor {
	return &ConfigMonitor{
		configPath: path,
	}
}

type Config struct {
	FileMonitor struct {
		Enabled     bool     `toml:"enabled"`
		Directories []string `toml:"directories"`
		MaxEvents   int      `toml:"max_events"`
	} `toml:"file_monitor"`

	ExecMonitor struct {
		Enabled       bool     `toml:"enabled"`
		WatchCommands []string `toml:"watch_commands"`
	} `toml:"exec_monitor"`

	NetworkMonitor struct {
		Enabled   bool     `toml:"enabled"`
		Ports     []int    `toml:"ports"`
		Protocols []string `toml:"protocols"`
	} `toml:"network_monitor"`

	System struct {
		Enabled bool `toml:"enabled"`
	} `toml:"system_monitor"`

	// HTTP服务配置
	HttpServer struct {
		Enabled bool   `toml:"enabled"`
		Port    int    `toml:"port"`
		Host    string `toml:"host"`
	} `toml:"http_server"`

	Log logger.Config `toml:"log"`

	Storage StorageConfig `toml:"storage"`

	Kafka KafkaConfig `toml:"kafka"`
}

// StorageConfig Define storage related configuration
type StorageConfig struct {
	Enabled     bool              `toml:"enabled"`
	Type        string            `toml:"type"`
	Format      string            `toml:"format"`
	Adapter     string            `toml:"adapter"`
	FilePath    string            `toml:"file_path"`
	MaxSize     int               `toml:"max_size"`
	MaxAge      int               `toml:"max_age"`
	MaxBackups  int               `toml:"max_backups"`
	Compress    bool              `toml:"compress"`
	RemoteAddr  string            `toml:"remote_addr"`
	RemotePort  int               `toml:"remote_port"`
	ExtraFields map[string]string `toml:"extra_fields"`
}

// KafkaConfig Kafka生产者配置
type KafkaConfig struct {
	Enabled     bool     `toml:"enabled"`
	Brokers     []string `toml:"brokers"`
	Topic       string   `toml:"topic"`
	ClientID    string   `toml:"client_id"`
	Compression string   `toml:"compression"` // none, gzip, snappy, lz4, zstd
	BatchSize   int      `toml:"batch_size"`
	BatchBytes  int      `toml:"batch_bytes"`  // 批次字节大小
	BatchTimeout int     `toml:"batch_timeout"` // 批次超时时间(毫秒)
	WriteTimeout int     `toml:"write_timeout"` // 写入超时时间(秒)
	ReadTimeout  int     `toml:"read_timeout"`  // 读取超时时间(秒)
	Retries      int     `toml:"retries"`
	// SASL认证配置
	SASL SASLConfig `toml:"sasl"`
	// TLS配置
	TLS TLSConfig `toml:"tls"`
}

// SASLConfig SASL认证配置
type SASLConfig struct {
	Enabled   bool   `toml:"enabled"`
	Mechanism string `toml:"mechanism"` // PLAIN, SCRAM-SHA-256, SCRAM-SHA-512
	Username  string `toml:"username"`
	Password  string `toml:"password"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	Enabled            bool   `toml:"enabled"`
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`
	CertFile           string `toml:"cert_file"`
	KeyFile            string `toml:"key_file"`
	CAFile             string `toml:"ca_file"`
}

// ToStorageConfig Convert configuration to storage module usable configuration structure
func (sc *StorageConfig) ToStorageConfig() (types.StorageConfig, error) {
	cfg := types.StorageConfig{
		FilePath:    sc.FilePath,
		MaxSize:     sc.MaxSize,
		MaxAge:      sc.MaxAge,
		MaxBackups:  sc.MaxBackups,
		Compress:    sc.Compress,
		RemoteAddr:  sc.RemoteAddr,
		RemotePort:  sc.RemotePort,
		ExtraFields: sc.ExtraFields,
	}

	// Set output type
	switch sc.Type {
	case "file":
		cfg.Type = types.OutputFile
	case "stdout":
		cfg.Type = types.OutputStdout
	case "socket":
		cfg.Type = types.OutputSocket
	case "syslog":
		cfg.Type = types.OutputSyslog
	case "kafka":
		cfg.Type = types.OutputKafka
	default:
		return cfg, fmt.Errorf("unknown storage type: %s", sc.Type)
	}

	// Set output format
	switch sc.Format {
	case "json":
		cfg.Format = types.FormatJSON
	case "text":
		cfg.Format = types.FormatText
	case "ndjson":
		cfg.Format = types.FormatNDJSON
	default:
		return cfg, fmt.Errorf("unknown storage format: %s", sc.Format)
	}

	return cfg, nil
}

func Load(path string) (*Config, error) {
	var config Config

	// Read and parse TOML configuration file
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	// Set default values
	if config.FileMonitor.MaxEvents == 0 {
		config.FileMonitor.MaxEvents = 1000
	}

	// Set default values for storage
	if config.Storage.MaxSize == 0 {
		config.Storage.MaxSize = 100
	}
	if config.Storage.MaxAge == 0 {
		config.Storage.MaxAge = 7
	}
	if config.Storage.MaxBackups == 0 {
		config.Storage.MaxBackups = 5
	}
	if config.Storage.FilePath == "" {
		config.Storage.FilePath = "/var/log/ltrack/events.log"
	}

	// 设置HTTP服务器默认值
	if config.HttpServer.Enabled && config.HttpServer.Port == 0 {
		config.HttpServer.Port = 8080
	}
	if config.HttpServer.Host == "" {
		config.HttpServer.Host = "0.0.0.0"
	}

	// 设置Kafka默认值
	if config.Kafka.Enabled {
		if config.Kafka.ClientID == "" {
			config.Kafka.ClientID = "ltrack-producer"
		}
		if config.Kafka.Compression == "" {
			config.Kafka.Compression = "gzip"
		}
		if config.Kafka.BatchSize == 0 {
			config.Kafka.BatchSize = 100
		}
		if config.Kafka.BatchBytes == 0 {
			config.Kafka.BatchBytes = 1048576 // 1MB
		}
		if config.Kafka.BatchTimeout == 0 {
			config.Kafka.BatchTimeout = 1000 // 1秒
		}
		if config.Kafka.WriteTimeout == 0 {
			config.Kafka.WriteTimeout = 10 // 10秒
		}
		if config.Kafka.ReadTimeout == 0 {
			config.Kafka.ReadTimeout = 10 // 10秒
		}
		if config.Kafka.Retries == 0 {
			config.Kafka.Retries = 3
		}
	}

	// Validate configuration
	if config.FileMonitor.Enabled && len(config.FileMonitor.Directories) == 0 {
		return nil, fmt.Errorf("file monitor enabled but no directories specified")
	}

	if config.NetworkMonitor.Enabled && len(config.NetworkMonitor.Ports) == 0 {
		return nil, fmt.Errorf("network monitor enabled but no ports specified")
	}

	// Validate storage configuration
	if config.Storage.Enabled {
		if config.Storage.Type == "" {
			config.Storage.Type = "file"
		}
		if config.Storage.Format == "" {
			config.Storage.Format = "json"
		}
		if config.Storage.Type == "socket" && config.Storage.RemoteAddr == "" {
			return nil, fmt.Errorf("storage type is socket but remote_addr not specified")
		}
	}

	// 验证Kafka配置
	if config.Kafka.Enabled {
		if len(config.Kafka.Brokers) == 0 {
			return nil, fmt.Errorf("kafka enabled but no brokers specified")
		}
		if config.Kafka.Topic == "" {
			return nil, fmt.Errorf("kafka enabled but no topic specified")
		}
		// 验证压缩算法
		validCompressions := []string{"none", "gzip", "snappy", "lz4", "zstd"}
		validCompression := false
		for _, comp := range validCompressions {
			if config.Kafka.Compression == comp {
				validCompression = true
				break
			}
		}
		if !validCompression {
			return nil, fmt.Errorf("invalid kafka compression: %s, valid options: %v",
				config.Kafka.Compression, validCompressions)
		}
		// 验证SASL机制
		if config.Kafka.SASL.Enabled {
			validMechanisms := []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"}
			validMechanism := false
			for _, mech := range validMechanisms {
				if config.Kafka.SASL.Mechanism == mech {
					validMechanism = true
					break
				}
			}
			if !validMechanism {
				return nil, fmt.Errorf("invalid kafka SASL mechanism: %s, valid options: %v",
					config.Kafka.SASL.Mechanism, validMechanisms)
			}
			if config.Kafka.SASL.Username == "" || config.Kafka.SASL.Password == "" {
				return nil, fmt.Errorf("kafka SASL enabled but username or password not specified")
			}
		}
	}

	return &config, nil
}
