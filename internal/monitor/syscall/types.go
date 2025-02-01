package exec

import (
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/mxcrafts/mxtrack/internal/config"
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
	objs      *bpfObjects
	link      link.Link
	reader    *ringbuf.Reader
	mu        sync.Mutex
	isRunning bool
	commands  map[string]bool
}
