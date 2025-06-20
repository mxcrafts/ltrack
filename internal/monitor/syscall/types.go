package exec

import (
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/config"
)

// Event represents a syscall event
type Event struct {
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	Comm     [16]byte  // process name
	Filename [256]byte // executable file path
	Argv     [128]byte // command line arguments
	ArgvSize uint32    // argument length
}

// Monitor is a syscall monitor
type Monitor struct {
	config    *config.Config
	objs      execObjects
	link      link.Link
	reader    *ringbuf.Reader
	mu        sync.Mutex
	isRunning bool
	commands  map[string]bool
	eventChan chan collector.Event
}

// ExecEvent implements the collector.Event interface for exec events
type ExecEvent struct {
	Type      string
	Data      map[string]interface{}
	Timestamp time.Time
}

// GetType returns the event type
func (e *ExecEvent) GetType() string {
	return e.Type
}

// GetData returns the event data
func (e *ExecEvent) GetData() map[string]interface{} {
	return e.Data
}

// GetTimestamp returns the event timestamp
func (e *ExecEvent) GetTimestamp() time.Time {
	return e.Timestamp
}
