package types

// StorageType defines the storage type for logs
type StorageType string

const (
	// OutputFile output to file
	OutputFile StorageType = "file"
	// OutputStdout output to standard output
	OutputStdout StorageType = "stdout"
	// OutputSyslog output to Syslog
	OutputSyslog StorageType = "syslog"
	// OutputSocket output to Socket (TCP/UDP)
	OutputSocket StorageType = "socket"
)

// StorageFormat defines the storage format for logs
type StorageFormat string

const (
	// FormatJSON format for log output, suitable for most log collection systems like ELK, Fluentd, etc.
	FormatJSON StorageFormat = "json"
	// FormatText format for log output, easy for human reading
	FormatText StorageFormat = "text"
	// FormatNDJSON format, one complete JSON object per line, suitable for stream processing
	FormatNDJSON StorageFormat = "ndjson"
)

// StorageConfig configuration for the storage module
type StorageConfig struct {
	// Output type
	Type StorageType `toml:"type"`
	// Output format
	Format StorageFormat `toml:"format"`
	// File output path (used when Type is file)
	FilePath string `toml:"file_path"`
	// File rotation settings
	MaxSize    int  `toml:"max_size"`    // Maximum size of a single file (MB)
	MaxAge     int  `toml:"max_age"`     // Maximum number of days to retain
	MaxBackups int  `toml:"max_backups"` // Maximum number of backup files
	Compress   bool `toml:"compress"`    // Whether to compress old files
	// Remote output settings (used when Type is socket)
	RemoteAddr string `toml:"remote_addr"` // Remote address
	RemotePort int    `toml:"remote_port"` // Remote port
	// Custom fields
	ExtraFields map[string]string `toml:"extra_fields"` // Extra fields to add to each log entry
}
