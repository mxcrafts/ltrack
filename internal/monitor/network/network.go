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

// XDP程序附加模式
const (
	// XDP通用/仿真模式 - 最低性能但兼容性最好
	XDP_FLAGS_SKB_MODE = 1 << 1
	// XDP原生模式 - 高性能但需要驱动支持
	XDP_FLAGS_DRV_MODE = 1 << 2
	// XDP硬件模式 - 需要网卡硬件支持
	XDP_FLAGS_HW_MODE = 1 << 3
)

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

	// 尝试加载程序
	err := m.tryAttachXDP()
	if err != nil {
		m.objs.Close()
		m.isRunning = false
		return fmt.Errorf("failed to attach XDP program: %w", err)
	}

	// 创建性能事件读取器
	reader, err := perf.NewReader(m.objs.Events, 4096)
	if err != nil {
		if m.link != nil {
			m.link.Close()
		}
		m.objs.Close()
		m.isRunning = false
		return fmt.Errorf("creating perf reader: %w", err)
	}
	m.reader = reader

	logger.Global.Info("Network monitor started successfully",
		"monitored_ports", m.config.NetworkMonitor.Ports,
		"monitored_protocols", m.config.NetworkMonitor.Protocols)

	go m.handleEvents(ctx)

	return nil
}

// 尝试以不同模式附加XDP程序
func (m *Monitor) tryAttachXDP() error {
	// 尝试获取可用的网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("getting network interfaces: %w", err)
	}

	// 过滤出可能支持XDP的接口
	var candidateInterfaces []net.Interface
	for _, iface := range interfaces {
		// 跳过禁用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 优先选择真实物理接口，但也包括虚拟接口和本地环回作为备选
		candidateInterfaces = append(candidateInterfaces, iface)
	}

	if len(candidateInterfaces) == 0 {
		return fmt.Errorf("no available network interfaces found")
	}

	// 按优先级排序 - 优先使用物理接口
	// 本实现简单起见，不做排序

	// 不同的XDP附加模式
	modes := []struct {
		name  string
		flags link.XDPAttachFlags
	}{
		{"Generic/SKB", link.XDPGenericMode},
		{"Native/Driver", link.XDPDriverMode},
		{"Hardware Offload", link.XDPOffloadMode},
		{"Default", 0},
	}

	// 尝试在每个接口上使用不同模式附加XDP程序
	for _, iface := range candidateInterfaces {
		for _, mode := range modes {
			logger.Global.Info("Attempting to attach XDP program",
				"interface", iface.Name,
				"index", iface.Index,
				"mode", mode.name)

			// 尝试附加XDP程序
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   m.objs.HandleXdp,
				Interface: iface.Index,
				Flags:     mode.flags,
			})

			if err != nil {
				logger.Global.Debug("Failed to attach XDP program",
					"interface", iface.Name,
					"mode", mode.name,
					"error", err)
				continue
			}

			// 成功附加
			m.link = l
			logger.Global.Info("Successfully attached XDP program",
				"interface", iface.Name,
				"index", iface.Index,
				"mode", mode.name)
			return nil
		}
	}

	return fmt.Errorf("could not attach XDP program to any interface in any mode")
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

			// Create a network event for the collector channel
			if m.eventChan != nil {
				netEvent := &NetworkEvent{
					Type:      "network",
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"src_ip":     srcIP,
						"dst_ip":     dstIP,
						"src_port":   event.SrcPort,
						"dst_port":   event.DstPort,
						"protocol":   protocolToString(event.Protocol),
						"data_len":   event.DataLen,
						"event_type": "TRAFFIC", // 固定为流量事件
					},
				}

				// Send the event to the event channel
				select {
				case m.eventChan <- netEvent:
					// Event sent successfully
				default:
					// Channel is full, log and continue
					logger.Global.Warn("Event channel is full, dropping network event")
				}
			}
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
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return nil, fmt.Errorf("monitor is not running")
	}

	return m.eventChan, nil
}
