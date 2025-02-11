package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/mxcrafts/mxtrack/internal/collector"
	"github.com/mxcrafts/mxtrack/internal/config"
	"github.com/mxcrafts/mxtrack/pkg/logger"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS network ../../../pkg/ebpf/c/network.c

func NewMonitor(cfg *config.Config) (*Monitor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	m := &Monitor{
		config:    cfg,
		ports:     make(map[int]bool),
		protocols: make(map[string]bool),
	}

	// Initialize monitored ports
	for _, port := range cfg.NetworkMonitor.Ports {
		m.ports[port] = true
	}

	// Initialize monitored protocols
	for _, proto := range cfg.NetworkMonitor.Protocols {
		m.protocols[proto] = true
	}

	return m, nil
}

func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.isRunning {
		m.mu.Unlock()
		return fmt.Errorf("monitor is already running")
	}
	m.isRunning = true
	m.mu.Unlock()

	if err := loadNetworkObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}

	// Get network interface
	iface := "lo" // Default to local loopback interface
	devID, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("getting interface: %w", err)
	}
	logger.Global.Info("Network interface initialized",
		"interface", iface,
		"index", devID.Index)

	// Attach XDP program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.HandleXdp,
		Interface: devID.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}
	m.link = l

	// Create a performance event reader
	reader, err := perf.NewReader(m.objs.Events, 4096)
	if err != nil {
		m.link.Close()
		return fmt.Errorf("creating perf reader: %w", err)
	}
	m.reader = reader
	logger.Global.Info("Network monitor started successfully",
		"monitored_ports", m.config.NetworkMonitor.Ports,
		"monitored_protocols", m.config.NetworkMonitor.Protocols)

	go m.handleEvents(ctx)

	return nil
}

func (m *Monitor) handleEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := m.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				logger.Global.Error("Error reading perf event", "error", err)
				continue
			}

			if record.LostSamples != 0 {
				logger.Global.Warn("Perf event samples lost", "count", record.LostSamples)
				continue
			}

			var event Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				logger.Global.Error("Error parsing event", "error", err)
				continue
			}

			// Check if the traffic should be monitored
			if !m.shouldMonitor(event.DstPort, event.Protocol) {
				continue
			}

			srcIP := intToIP(event.SrcAddr)
			dstIP := intToIP(event.DstAddr)

			// Record network events
			logger.Global.Info("Network traffic detected",
				"src_ip", srcIP,
				"dst_ip", dstIP,
				"src_port", event.SrcPort,
				"dst_port", event.DstPort,
				"protocol", protocolToString(event.Protocol),
				"length", event.DataLen)
		}
	}
}

func (m *Monitor) Stop(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return
	}

	if m.reader != nil {
		m.reader.Close()
	}
	if m.link != nil {
		m.link.Close()
	}
	m.objs.Close()
	m.isRunning = false
}

func (m *Monitor) shouldMonitor(port uint16, protocol uint8) bool {
	// If no ports are configured, monitor all ports
	if len(m.ports) == 0 {
		return true
	}

	// Check if the port is in the monitoring list
	if !m.ports[int(port)] {
		return false
	}

	// Check if the protocol is in the monitoring list
	protoStr := protocolToString(protocol)
	if len(m.protocols) > 0 && !m.protocols[protoStr] {
		return false
	}

	return true
}

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip))
}

func protocolToString(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}

// GetType returns the type of the monitor
func (m *Monitor) GetType() string {
	return "network"
}

// Collect implements the collector.Collector interface
func (m *Monitor) Collect(ctx context.Context) (<-chan collector.Event, error) {
	// TODO: Implement event collection
	return nil, nil
}
