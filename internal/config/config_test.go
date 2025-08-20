package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mxcrafts/ltrack/pkg/utils"
)

func TestAutoHostnameDetection(t *testing.T) {
	// 创建临时配置文件
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.toml")

	tests := []struct {
		name           string
		configContent  string
		expectAutoHost bool
		expectError    bool
	}{
		{
			name: "auto_detect_host enabled with localhost",
			configContent: `
[storage]
enabled = true
type = "file"
format = "json"
auto_detect_host = true

[storage.extra_fields]
host = "localhost"
service = "test"
`,
			expectAutoHost: true,
			expectError:    false,
		},
		{
			name: "auto_detect_host enabled with empty host",
			configContent: `
[storage]
enabled = true
type = "file"
format = "json"
auto_detect_host = true

[storage.extra_fields]
host = ""
service = "test"
`,
			expectAutoHost: true,
			expectError:    false,
		},
		{
			name: "auto_detect_host disabled",
			configContent: `
[storage]
enabled = true
type = "file"
format = "json"
auto_detect_host = false

[storage.extra_fields]
host = "localhost"
service = "test"
`,
			expectAutoHost: false,
			expectError:    false,
		},
		{
			name: "auto_detect_host default (not specified)",
			configContent: `
[storage]
enabled = true
type = "file"
format = "json"

[storage.extra_fields]
host = "localhost"
service = "test"
`,
			expectAutoHost: true,
			expectError:    false,
		},
		{
			name: "custom hostname should not be overridden",
			configContent: `
[storage]
enabled = true
type = "file"
format = "json"
auto_detect_host = true

[storage.extra_fields]
host = "custom-host"
service = "test"
`,
			expectAutoHost: false, // 不应该被覆盖
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 写入配置文件
			err := os.WriteFile(configPath, []byte(tt.configContent), 0644)
			if err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			// 加载配置
			config, err := Load(configPath)
			if (err != nil) != tt.expectError {
				t.Errorf("Load() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if tt.expectError {
				return
			}

			// 验证配置
			if !config.Storage.Enabled {
				t.Error("Storage should be enabled")
			}

			if config.Storage.ExtraFields == nil {
				t.Error("ExtraFields should not be nil")
				return
			}

			hostValue, exists := config.Storage.ExtraFields["host"]
			if !exists {
				t.Error("Host field should exist in extra fields")
				return
			}

			if tt.expectAutoHost {
				// 应该自动检测主机名
				expectedHostname, err := utils.GetHostname()
				if err != nil {
					t.Logf("Warning: Could not get expected hostname: %v", err)
					// 如果获取主机名失败，应该回退到 localhost
					if hostValue != "localhost" {
						t.Errorf("Expected fallback to localhost, got %s", hostValue)
					}
				} else {
					if hostValue != expectedHostname {
						t.Errorf("Expected auto-detected hostname %s, got %s", expectedHostname, hostValue)
					}
				}
			} else {
				// 不应该自动检测，应该保持原值
				if tt.name == "custom hostname should not be overridden" {
					if hostValue != "custom-host" {
						t.Errorf("Expected custom-host, got %s", hostValue)
					}
				} else if tt.name == "auto_detect_host disabled" {
					if hostValue != "localhost" {
						t.Errorf("Expected localhost when auto-detect disabled, got %s", hostValue)
					}
				}
			}

			autoDetectValue := false
			if config.Storage.AutoDetectHost != nil {
				autoDetectValue = *config.Storage.AutoDetectHost
			}
			t.Logf("Test %s: host=%s, auto_detect_host=%v", tt.name, hostValue, autoDetectValue)
		})
	}
}

func TestConfigLoadWithoutExtraFields(t *testing.T) {
	// 测试没有 extra_fields 部分的配置
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.toml")

	configContent := `
[storage]
enabled = true
type = "file"
format = "json"
auto_detect_host = true
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// 验证 ExtraFields 被正确初始化
	if config.Storage.ExtraFields == nil {
		t.Error("ExtraFields should be initialized")
		return
	}

	// 验证主机名被自动设置
	hostValue, exists := config.Storage.ExtraFields["host"]
	if !exists {
		t.Error("Host field should be auto-created")
		return
	}

	expectedHostname, err := utils.GetHostname()
	if err != nil {
		// 如果获取主机名失败，应该设置为 localhost
		if hostValue != "localhost" {
			t.Errorf("Expected localhost as fallback, got %s", hostValue)
		}
	} else {
		if hostValue != expectedHostname {
			t.Errorf("Expected auto-detected hostname %s, got %s", expectedHostname, hostValue)
		}
	}
}

func TestStorageDisabled(t *testing.T) {
	// 测试存储禁用时不进行主机名检测
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test_config.toml")

	configContent := `
[storage]
enabled = false
auto_detect_host = true

[storage.extra_fields]
host = "localhost"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// 存储禁用时，主机名检测逻辑不应该执行
	// 但配置文件中的值应该保持不变
	if config.Storage.ExtraFields != nil {
		if hostValue, exists := config.Storage.ExtraFields["host"]; exists {
			if hostValue != "localhost" {
				t.Errorf("Expected original localhost value when storage disabled, got %s", hostValue)
			}
		}
	}
}
