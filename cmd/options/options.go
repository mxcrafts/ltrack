package options

import (
	"flag"
	"fmt"
	"os"
)

const (
	defaultConfigPath = "policy.toml"
)

// Options defines command line options
type Options struct {
	ConfigPath string
}

// NewOptions creates a new Options instance with default values
func NewOptions() *Options {
	return &Options{
		ConfigPath: defaultConfigPath,
	}
}

// AddFlags adds flags to the specified FlagSet
func (o *Options) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.ConfigPath, "config", o.ConfigPath, "Path to configuration file")
}

// Parse parses command line arguments
func Parse() (*Options, error) {
	options := NewOptions()

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	options.AddFlags(fs)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return nil, fmt.Errorf("failed to parse command line arguments: %w", err)
	}

	return options, nil
}

// Validate validates the options
func (o *Options) Validate() error {
	if o.ConfigPath == "" {
		return fmt.Errorf("config path cannot be empty")
	}
	return nil
}
