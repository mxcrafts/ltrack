package config

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/mxcrafts/mxtrack/pkg/logger"
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

	// Validate configuration
	if config.FileMonitor.Enabled && len(config.FileMonitor.Directories) == 0 {
		return nil, fmt.Errorf("file monitor enabled but no directories specified")
	}

	if config.NetworkMonitor.Enabled && len(config.NetworkMonitor.Ports) == 0 {
		return nil, fmt.Errorf("network monitor enabled but no ports specified")
	}

	return &config, nil
}
