package core

import (
	"context"
	"log/slog"
	"sync"

	"github.com/mxcrafts/ltrack/internal/collector"
)

// CompositeMonitor implements the Collector interface for multiple monitors
type CompositeMonitor struct {
	collectors []collector.Collector
	eventChan  chan collector.Event
	wg         sync.WaitGroup
	mu         sync.RWMutex
}

// NewCompositeMonitor creates a new composite monitor
func NewCompositeMonitor() *CompositeMonitor {
	return &CompositeMonitor{
		collectors: make([]collector.Collector, 0),
		eventChan:  make(chan collector.Event, 1000),
	}
}

// AddCollector adds a new collector to the composite
func (c *CompositeMonitor) AddCollector(collector collector.Collector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectors = append(c.collectors, collector)
}

// Start starts all collectors
func (c *CompositeMonitor) Start(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, collector := range c.collectors {
		c.wg.Add(1)
		go func(col collector.Collector) {
			defer c.wg.Done()
			if err := col.Start(ctx); err != nil {
				slog.Error("Failed to start collector",
					"error", err,
					"type", col.GetType())
			}
		}(collector)
	}

	go c.aggregateEvents(ctx)
	return nil
}

// Stop stops all collectors
func (c *CompositeMonitor) Stop(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, collector := range c.collectors {
		if err := collector.Stop(ctx); err != nil {
			slog.Error("Failed to stop collector",
				"error", err,
				"type", collector.GetType())
		}
	}

	c.wg.Wait()
	close(c.eventChan)
	return nil
}

// Collect returns the event channel
func (c *CompositeMonitor) Collect(ctx context.Context) (<-chan collector.Event, error) {
	return c.eventChan, nil
}

// aggregateEvents aggregates events from all collectors
func (c *CompositeMonitor) aggregateEvents(ctx context.Context) {
	for _, col := range c.collectors {
		c.wg.Add(1)
		go func(collector collector.Collector) {
			defer c.wg.Done()
			events, err := collector.Collect(ctx)
			if err != nil {
				slog.Error("Failed to collect events",
					"error", err,
					"type", collector.GetType())
				return
			}

			for event := range events {
				select {
				case c.eventChan <- event:
				case <-ctx.Done():
					return
				}
			}
		}(col)
	}
}
