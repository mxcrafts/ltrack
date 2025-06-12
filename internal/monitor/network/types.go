package network

import (
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/config"
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
	eventChan chan collector.Event
}

// NetworkEvent implements the collector.Event interface for network events
type NetworkEvent struct {
	Type      string
	Data      map[string]interface{}
	Timestamp time.Time
}

// GetType returns the event type
func (e *NetworkEvent) GetType() string {
	return e.Type
}

// GetData returns the event data
func (e *NetworkEvent) GetData() map[string]interface{} {
	return e.Data
}

// GetTimestamp returns the event timestamp
func (e *NetworkEvent) GetTimestamp() time.Time {
	return e.Timestamp
}
