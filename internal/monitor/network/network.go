package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/config"
	"github.com/mxcrafts/ltrack/pkg/logger"
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
		eventChan: make(chan collector.Event, 1000),
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

	// Get network interface - try multiple interfaces
	interfaces := []string{"eth0", "ens33", "enp0s3", "lo"}
	var devID *net.Interface
	var err error
	var iface string

	for _, ifName := range interfaces {
		devID, err = net.InterfaceByName(ifName)
		if err == nil {
			iface = ifName
			logger.Global.Info("Selected network interface",
				"interface", iface,
				"index", devID.Index)
			break
		}
	}

	if devID == nil {
		return fmt.Errorf("failed to find a suitable network interface: %w", err)
	}

	// Try attaching with XDP generic mode first
	logger.Global.Info("Attempting to attach XDP program in generic mode",
		"interface", iface)

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.HandleXdp,
		Interface: devID.Index,
		Flags:     link.XDPGenericMode, // Use generic mode instead of native
	})

	if err != nil {
		logger.Global.Warn("Failed to attach XDP in generic mode, using alternative monitoring method",
			"error", err)

		// As a fallback, use perf event tracepoints instead
		tp, tpErr := link.Tracepoint("net", "net_dev_queue", m.objs.HandleXdp, nil)
		if tpErr != nil {
			return fmt.Errorf("failed to attach alternative tracepoint: %w", tpErr)
		}

		logger.Global.Info("Successfully attached network tracepoint as fallback")
		m.link = tp
	} else {
		m.link = l
		logger.Global.Info("XDP program attached successfully in generic mode")
	}

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
			protocolStr := protocolToString(event.Protocol)

			// Create network event for collection
			networkEvent := &NetworkEvent{
				Type: "NETWORK_TRAFFIC",
				Data: map[string]interface{}{
					"src_ip":   srcIP,
					"dst_ip":   dstIP,
					"src_port": event.SrcPort,
					"dst_port": event.DstPort,
					"protocol": protocolStr,
					"length":   event.DataLen,
				},
				Timestamp: time.Now(),
			}

			// Send event to collection channel
			select {
			case m.eventChan <- networkEvent:
				// Event sent successfully
			default:
				// Channel buffer is full, log a warning
				logger.Global.Warn("Network event channel buffer is full, dropping event")
			}

			// Record network events
			logger.Global.Info("Network traffic detected",
				"src_ip", srcIP,
				"dst_ip", dstIP,
				"src_port", event.SrcPort,
				"dst_port", event.DstPort,
				"protocol", protocolStr,
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
	return m.eventChan, nil
}
