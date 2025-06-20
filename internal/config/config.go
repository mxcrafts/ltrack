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

	Log logger.Config `toml:"log"`

	Storage StorageConfig `toml:"storage"`
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

	return &config, nil
}
