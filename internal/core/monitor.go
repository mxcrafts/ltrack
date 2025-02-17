package core

import (
	"context"
	"sync"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/config"
)

// Monitor represents the main monitoring system
type Monitor struct {
	collectors []collector.Collector
	config     *config.Config
	wg         sync.WaitGroup
}

func NewMonitor(cfg *config.Config) *Monitor {
	return &Monitor{
		config:     cfg,
		collectors: make([]collector.Collector, 0),
	}
}

func (m *Monitor) AddCollector(c collector.Collector) {
	m.collectors = append(m.collectors, c)
}

func (m *Monitor) Start(ctx context.Context) error {
	for _, c := range m.collectors {
		m.wg.Add(1)
		go func(collector collector.Collector) {
			defer m.wg.Done()
			if err := collector.Start(ctx); err != nil {
				// Handle error
			}
		}(c)
	}
	return nil
}

func (m *Monitor) Stop(ctx context.Context) error {
	for _, c := range m.collectors {
		if err := c.Stop(ctx); err != nil {
			// Handle error
		}
	}
	m.wg.Wait()
	return nil
}
