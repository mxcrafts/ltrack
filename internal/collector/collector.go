package collector

import (
	"context"
	"time"
)

// Event represents a generic event interface
type Event interface {
	GetTimestamp() time.Time
	GetType() string
}

// Collector defines the interface for data collectors
type Collector interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Collect(ctx context.Context) (<-chan Event, error)
	GetType() string
}

// BaseCollector provides common collector functionality
type BaseCollector struct {
	EventChan chan Event
	Running   bool
}

func NewBaseCollector() *BaseCollector {
	return &BaseCollector{
		EventChan: make(chan Event, 1000),
	}
}
