package file

import (
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/mxcrafts/ltrack/internal/collector"
)

// Event types definition, matching with C code
const (
	EventOpen   uint32 = 1
	EventCreate uint32 = 2
	EventUnlink uint32 = 3
	EventMkdir  uint32 = 4
	EventRmdir  uint32 = 5
)

// Monitor structure definition
type Monitor struct {
	objs      *fileObjects
	links     []link.Link
	reader    *ringbuf.Reader
	dirs      []string
	running   bool
	eventChan chan collector.Event
	// New event cache for deduplication
	eventCache map[string]time.Time
}

// Event represents a file operation event
type Event struct {
	Pid       uint32
	Ppid      uint32
	Uid       uint32
	EventType uint32
	FileName  [256]byte
	Comm      [16]byte
	Pcomm     [16]byte
}

// FileEvent implements the collector.Event interface for file events
type FileEvent struct {
	Type      string
	Data      map[string]interface{}
	Timestamp time.Time
}

// GetType returns the event type
func (e *FileEvent) GetType() string {
	return e.Type
}

// GetData returns the event data
func (e *FileEvent) GetData() map[string]interface{} {
	return e.Data
}

// GetTimestamp returns the event timestamp
func (e *FileEvent) GetTimestamp() time.Time {
	return e.Timestamp
}

// GetEventTypeName converts event type to string
func GetEventTypeName(eventType uint32) string {
	switch eventType {
	case EventOpen:
		return "OPEN"
	case EventCreate:
		return "CREATE"
	case EventUnlink:
		return "UNLINK"
	case EventMkdir:
		return "MKDIR"
	case EventRmdir:
		return "RMDIR"
	default:
		return "UNKNOWN"
	}
}
