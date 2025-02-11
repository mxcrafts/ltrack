package network

import (
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/mxcrafts/mxtrack/internal/config"
)

// Event represents a network event
type Event struct {
	SrcAddr  uint32
	DstAddr  uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	DataLen  uint32
}

type Monitor struct {
	config    *config.Config
	objs      networkObjects
	link      link.Link
	reader    *perf.Reader
	ports     map[int]bool
	protocols map[string]bool
	mu        sync.Mutex
	isRunning bool
}
