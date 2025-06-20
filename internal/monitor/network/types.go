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

// NetworkEvent implements the collector.Event interface
type NetworkEvent struct {
	Type      string
	Data      map[string]interface{}
	Timestamp time.Time
}

// GetTimestamp returns the timestamp of the event
func (e *NetworkEvent) GetTimestamp() time.Time {
	return e.Timestamp
}

// GetType returns the type of the event
func (e *NetworkEvent) GetType() string {
	return e.Type
}

type Monitor struct {
	config    *config.Config
	objs      networkObjects
	link      link.Link   // 单个链接（向后兼容）
	links     []link.Link // 多个链接的集合
	reader    *perf.Reader
	ports     map[int]bool
	protocols map[string]bool
	mu        sync.Mutex
	isRunning bool
	eventChan chan collector.Event
}
