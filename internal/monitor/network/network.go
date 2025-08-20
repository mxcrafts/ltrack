package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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

	// 检查是否有root权限（eBPF通常需要root权限）
	if os.Geteuid() != 0 {
		logger.Global.Warn("Network monitor is not running as root, eBPF functionality may be limited")
	}

	// 尝试加载eBPF对象，如果失败则回退到socket模式
	var loadErr error
	if loadErr = loadNetworkObjects(&m.objs, nil); loadErr != nil {
		logger.Global.Warn("Failed to load eBPF objects, falling back to socket mode",
			"error", loadErr)

		// 直接跳转到socket模式监控
		return m.startPacketSocketMonitoring(ctx)
	}

	// 优先使用活跃的外部网络接口，避免使用lo接口
	interfaces := getActiveInterfaces()
	if len(interfaces) == 0 {
		logger.Global.Warn("No active network interfaces found, falling back to default list")
		interfaces = []string{"eth0", "ens33", "enp0s3", "wlan0"}
	}

	// 避免将lo作为第一选择
	for i, iface := range interfaces {
		if iface == "lo" {
			// 将lo移到列表末尾
			interfaces = append(interfaces[:i], interfaces[i+1:]...)
			interfaces = append(interfaces, "lo")
			break
		}
	}

	var attached bool

	// 尝试使用XDP附加到网络接口
	logger.Global.Info("Attempting to attach XDP program to network interfaces")
	attached = m.tryXDPAttachment(interfaces, ctx)

	// 如果所有eBPF方法都失败，回退到原生Go socket监控
	if !attached {
		logger.Global.Info("Could not attach eBPF program to any interface, falling back to packet socket monitoring")
		if err := m.startPacketSocketMonitoring(ctx); err != nil {
			// 释放eBPF资源
			m.objs.Close()
			return fmt.Errorf("failed to start packet socket monitoring: %v", err)
		}
	} else {
		// XDP 成功附加，但为了监控本地回环流量，我们还需要启动一个轻量级的本地监控
		logger.Global.Info("XDP attached successfully, starting additional localhost monitoring for loopback traffic")
		go m.startLocalhostMonitoring(ctx)
	}

	return nil
}

// 尝试使用XDP附加（作为备选方案）
func (m *Monitor) tryXDPAttachment(interfaces []string, ctx context.Context) bool {
	// 尝试不同的XDP模式
	modes := []struct {
		name string
		flag link.XDPAttachFlags
	}{
		{"skb", link.XDPGenericMode},   // 通用/SKB模式（首选，兼容性更好）
		{"native", link.XDPDriverMode}, // 原生驱动模式（次选，性能更好但兼容性较差）
		{"off", 0},                     // 无特定标志（备选）
	}

	for _, iface := range interfaces {
		// 跳过lo接口，它通常不支持XDP
		if iface == "lo" {
			logger.Global.Info("Skipping lo interface for XDP as it often doesn't support it")
			continue
		}

		devID, err := net.InterfaceByName(iface)
		if err != nil {
			logger.Global.Warn("Failed to get interface",
				"interface", iface,
				"error", err)
			continue
		}

		// 检查接口状态
		if devID.Flags&net.FlagUp == 0 {
			logger.Global.Warn("Network interface is down, skipping",
				"interface", iface)
			continue
		}

		// 清理已有的XDP程序
		if err := m.cleanupExistingXDP(iface); err != nil {
			logger.Global.Warn("Failed to cleanup existing XDP program",
				"interface", iface,
				"error", err)
		}

		for _, mode := range modes {
			logger.Global.Info("Attempting to attach XDP program",
				"interface", iface,
				"mode", mode.name,
				"index", devID.Index)

			// 检查XDP程序是否可用
			if m.objs.HandleXdp == nil {
				logger.Global.Error("XDP program is nil, cannot attach")
				break
			}

			// 尝试附加XDP程序
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   m.objs.HandleXdp,
				Interface: devID.Index,
				Flags:     mode.flag,
			})

			if err != nil {
				logger.Global.Warn("Failed to attach XDP program",
					"interface", iface,
					"mode", mode.name,
					"error", err)
				continue
			}

			// 成功附加
			m.links = append(m.links, l)
			// 兼容旧代码，保持link字段也设置为当前附加的链接
			m.link = l

			// 创建性能事件读取器
			reader, err := perf.NewReader(m.objs.Events, 4096)
			if err != nil {
				for _, l := range m.links {
					l.Close()
				}
				m.links = nil
				m.link = nil
				logger.Global.Warn("Failed to create perf reader", "error", err)
				continue
			}
			m.reader = reader

			logger.Global.Info("Network monitor started successfully with XDP",
				"interface", iface,
				"mode", mode.name,
				"monitored_ports", m.config.NetworkMonitor.Ports,
				"monitored_protocols", m.config.NetworkMonitor.Protocols)

			go m.handleEvents(ctx)
			return true
		}
	}

	return false
}

// 获取系统中活跃的网络接口
func getActiveInterfaces() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		logger.Global.Warn("Failed to get network interfaces", "error", err)
		return nil
	}

	var activeInterfaces []string
	for _, iface := range interfaces {
		// 忽略非活跃或loopback接口
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			activeInterfaces = append(activeInterfaces, iface.Name)
		}
	}

	// 如果没有找到活跃的外部接口，也加入loopback接口
	if len(activeInterfaces) == 0 {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp != 0 {
				activeInterfaces = append(activeInterfaces, iface.Name)
			}
		}
	}

	return activeInterfaces
}

// 启动本地回环流量监控（用于配合XDP监控外部流量）
func (m *Monitor) startLocalhostMonitoring(ctx context.Context) error {
	logger.Global.Info("Starting localhost monitoring for loopback traffic")

	// 使用简单的端口扫描方式监控本地端口状态变化
	return m.startLocalhostPortMonitoring(ctx)
}

// 本地监控方法：使用端口状态检查
func (m *Monitor) startLocalhostPortMonitoring(ctx context.Context) error {
	logger.Global.Info("Starting localhost port monitoring")

	// 获取要监控的端口列表
	portsToMonitor := make([]int, 0, len(m.ports))
	for port := range m.ports {
		portsToMonitor = append(portsToMonitor, port)
	}

	if len(portsToMonitor) == 0 {
		logger.Global.Warn("No ports configured for localhost monitoring")
		return nil
	}

	// 定期检查端口状态
	ticker := time.NewTicker(500 * time.Millisecond) // 更频繁的检查
	defer ticker.Stop()

	portStates := make(map[string]bool) // 记录端口的上一次状态，key格式: "tcp:1234"

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, port := range portsToMonitor {
				// 检查TCP端口
				if len(m.protocols) == 0 || m.protocols["tcp"] {
					m.checkLocalhostPort("tcp", port, portStates)
				}
			}
		}
	}
}

// 检查本地端口状态
func (m *Monitor) checkLocalhostPort(protocol string, port int, portStates map[string]bool) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	portKey := fmt.Sprintf("%s:%d", protocol, port)

	conn, err := net.DialTimeout(protocol, addr, 50*time.Millisecond)
	isOpen := err == nil
	if conn != nil {
		conn.Close()
	}

	wasOpen, existed := portStates[portKey]
	portStates[portKey] = isOpen

	// 如果端口状态发生变化，记录事件
	if !existed || wasOpen != isOpen {
		eventType := "PORT_CLOSED"
		if isOpen {
			eventType = "PORT_OPENED"
		}

		event := &NetworkEvent{
			Type:      "network",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"dst_ip":     "127.0.0.1",
				"dst_port":   port,
				"protocol":   protocol,
				"event_type": eventType,
				"interface":  "lo",
			},
		}

		select {
		case m.eventChan <- event:
			logger.Global.Info("Localhost port state changed",
				"port", port,
				"protocol", protocol,
				"state", eventType)
		default:
			logger.Global.Warn("Event channel is full, dropping localhost port event")
		}
	}
}

// 使用原始套接字作为备选的网络监控方法
func (m *Monitor) startPacketSocketMonitoring(ctx context.Context) error {
	logger.Global.Info("Starting packet socket monitoring as fallback")

	// 尝试监听的端口列表
	portsToMonitor := make([]int, 0, len(m.ports))
	for port := range m.ports {
		portsToMonitor = append(portsToMonitor, port)
	}

	// 如果没有指定端口，使用一些常用端口
	if len(portsToMonitor) == 0 {
		portsToMonitor = []int{80, 443, 22, 8080, 53}
	}

	// 启动TCP监听器
	for _, proto := range []string{"tcp", "udp"} {
		// 如果配置了协议限制，并且当前协议不在列表中，则跳过
		if len(m.protocols) > 0 && !m.protocols[proto] {
			continue
		}

		for _, port := range portsToMonitor {
			go func(proto string, port int) {
				m.monitorPort(ctx, proto, port)
			}(proto, port)
		}
	}

	logger.Global.Info("Packet socket monitoring started",
		"monitored_ports", portsToMonitor)

	return nil
}

// 监控特定端口的网络活动
func (m *Monitor) monitorPort(ctx context.Context, proto string, port int) {
	var listener net.Listener
	var err error

	addr := fmt.Sprintf(":%d", port)

	switch proto {
	case "tcp":
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			logger.Global.Warn("Failed to listen on TCP port",
				"port", port,
				"error", err)
			return
		}
		defer listener.Close()

		logger.Global.Info("Monitoring TCP port", "port", port)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				tcpListener := listener.(*net.TCPListener)
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))

				conn, err := listener.Accept()
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// Just a timeout, continue
						continue
					}
					logger.Global.Error("Error accepting TCP connection",
						"port", port,
						"error", err)
					continue
				}

				// Process the connection
				remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
				localAddr := conn.LocalAddr().(*net.TCPAddr)

				// Create an event
				event := &NetworkEvent{
					Type:      "network",
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"src_ip":     remoteAddr.IP.String(),
						"dst_ip":     localAddr.IP.String(),
						"src_port":   remoteAddr.Port,
						"dst_port":   localAddr.Port,
						"protocol":   "tcp",
						"event_type": "CONNECT",
					},
				}

				// Send the event
				select {
				case m.eventChan <- event:
					// Event sent successfully
				default:
					// Channel is full, log warning
					logger.Global.Warn("Event channel is full, dropping network event")
				}

				// Log the connection
				logger.Global.Info("TCP connection detected",
					"src_ip", remoteAddr.IP.String(),
					"dst_ip", localAddr.IP.String(),
					"src_port", remoteAddr.Port,
					"dst_port", localAddr.Port)

				conn.Close()
			}
		}

	case "udp":
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
		if err != nil {
			logger.Global.Warn("Failed to resolve UDP address",
				"port", port,
				"error", err)
			return
		}

		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			logger.Global.Warn("Failed to listen on UDP port",
				"port", port,
				"error", err)
			return
		}
		defer conn.Close()

		logger.Global.Info("Monitoring UDP port", "port", port)

		buffer := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))

				n, remoteAddr, err := conn.ReadFromUDP(buffer)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// Just a timeout, continue
						continue
					}
					logger.Global.Error("Error reading UDP packet",
						"port", port,
						"error", err)
					continue
				}

				// Create an event
				event := &NetworkEvent{
					Type:      "network",
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"src_ip":     remoteAddr.IP.String(),
						"dst_ip":     conn.LocalAddr().(*net.UDPAddr).IP.String(),
						"src_port":   remoteAddr.Port,
						"dst_port":   conn.LocalAddr().(*net.UDPAddr).Port,
						"protocol":   "udp",
						"data_len":   n,
						"event_type": "TRAFFIC",
					},
				}

				// Send the event
				select {
				case m.eventChan <- event:
					// Event sent successfully
				default:
					// Channel is full, log warning
					logger.Global.Warn("Event channel is full, dropping network event")
				}

				// Log the packet
				logger.Global.Info("UDP packet detected",
					"src_ip", remoteAddr.IP.String(),
					"dst_ip", conn.LocalAddr().(*net.UDPAddr).IP.String(),
					"src_port", remoteAddr.Port,
					"dst_port", conn.LocalAddr().(*net.UDPAddr).Port,
					"length", n)
			}
		}
	}
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

			// Create and send network event to the event channel
			networkEvent := &NetworkEvent{
				Type:      "network",
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"src_ip":     srcIP,
					"dst_ip":     dstIP,
					"src_port":   event.SrcPort,
					"dst_port":   event.DstPort,
					"protocol":   protocolToString(event.Protocol),
					"data_len":   event.DataLen,
					"event_type": "TRAFFIC",
				},
			}

			select {
			case m.eventChan <- networkEvent:
				// Event sent successfully
			default:
				// Channel is full, log warning
				logger.Global.Warn("Event channel is full, dropping network event")
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

	// 关闭性能事件读取器
	if m.reader != nil {
		m.reader.Close()
	}

	// 关闭所有链接
	for _, l := range m.links {
		l.Close()
	}

	// 兼容旧代码，关闭单个链接（如果存在）
	if m.link != nil && len(m.links) == 0 {
		m.link.Close()
	}

	// 关闭eBPF对象
	m.objs.Close()

	m.isRunning = false
	logger.Global.Info("Network monitor stopped")
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

func (m *Monitor) cleanupExistingXDP(iface string) error {
	logger.Global.Info("Attempting to clean up any existing XDP programs",
		"interface", iface)

	// 使用bpftool命令尝试清理接口上已有的XDP程序
	cmd := exec.Command("bpftool", "net", "detach", "xdp", "dev", iface)
	if err := cmd.Run(); err != nil {
		logger.Global.Warn("Failed to detach XDP with bpftool, may not be installed or no program attached",
			"interface", iface,
			"error", err)
		// 错误不是致命的，继续尝试其他命令
	}

	// 尝试使用ip命令清理
	cmd = exec.Command("ip", "link", "set", "dev", iface, "xdp", "off")
	if err := cmd.Run(); err != nil {
		logger.Global.Warn("Failed to detach XDP with ip command",
			"interface", iface,
			"error", err)
		// 错误不是致命的，继续进行
	}

	// 尝试所有可能的XDP模式进行清理
	xdpModes := []string{"xdpgeneric", "xdpdrv", "xdpoffload", "xdp"}
	for _, mode := range xdpModes {
		cmd = exec.Command("ip", "link", "set", "dev", iface, mode, "off")
		_ = cmd.Run() // 忽略错误，因为不是所有模式都可能支持
	}

	// 清理尝试完成
	logger.Global.Info("XDP cleanup attempts completed",
		"interface", iface)
	return nil
}
