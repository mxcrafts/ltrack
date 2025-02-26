package file

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/pkg/logger"
	"github.com/mxcrafts/ltrack/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS file ../../../pkg/ebpf/c/file.c

func NewMonitor() (collector.Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memory lock: %w", err)
	}
	return &Monitor{
		dirs:      make([]string, 0),
		eventChan: make(chan collector.Event, 1000),
	}, nil
}

func (m *Monitor) AddMonitoredDir(path string) error {
	if len(path) >= 256 {
		return fmt.Errorf("path too long: %s", path)
	}
	m.dirs = append(m.dirs, path)
	return nil
}

func (m *Monitor) Start(ctx context.Context) error {
	if m.running {
		return fmt.Errorf("monitor already running")
	}

	objs := fileObjects{}
	if err := loadFileObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	m.objs = &objs

	// Create required kprobes
	probes := []struct {
		name    string
		program *ebpf.Program
	}{
		{"do_sys_openat2", m.objs.DoSysOpenat2Enter},
		{"do_unlinkat", m.objs.DoUnlinkatEnter},
		{"do_mkdirat", m.objs.DoMkdiratEnter},
		{"do_renameat2", m.objs.DoRenameat2Enter},
	}

	// Create each kprobe
	for _, probe := range probes {
		kp, err := link.Kprobe(probe.name, probe.program, nil)
		if err != nil {
			for _, link := range m.links {
				link.Close()
			}
			m.objs.Close()
			return fmt.Errorf("attaching kprobe %s: %w", probe.name, err)
		}
		m.links = append(m.links, kp)
		logger.Global.Info("Successfully attached kprobe",
			"probe", probe.name,
			"program", fmt.Sprintf("%T", probe.program))
	}

	// Add debug logs
	logger.Global.Info("Probe registration statistics",
		"total", len(probes),
		"registered", len(m.links),
		"probes", strings.Join(func() []string {
			names := make([]string, len(m.links))
			for i, link := range m.links {
				names[i] = fmt.Sprintf("%T", link)
			}
			return names
		}(), ", "))

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(m.objs.Events)
	if err != nil {
		for _, link := range m.links {
			link.Close()
		}
		m.objs.Close()
		return fmt.Errorf("creating reader: %w", err)
	}
	m.reader = reader

	// Start event handling
	go m.handleEvents(ctx)
	m.running = true

	logger.Global.Info("File monitor started",
		"monitored_dirs_count", len(m.dirs),
		"monitored_dirs", strings.Join(m.dirs, ", "),
		"registered_probes", len(m.links))

	return nil
}

func (m *Monitor) Stop(ctx context.Context) error {
	if !m.running {
		return nil
	}

	// Create a new context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if m.reader != nil {
		if err := m.reader.Close(); err != nil {
			logger.Global.Error("Failed to close reader", "error", err)
		}
	}

	select {
	case <-timeoutCtx.Done():
		logger.Global.Warn("Timeout while stopping monitor")
	default:
		for _, link := range m.links {
			if err := link.Close(); err != nil {
				logger.Global.Error("Failed to close probe", "error", err)
			}
		}
		m.links = nil

		if m.objs != nil {
			m.objs.Close()
			m.objs = nil
		}

		m.running = false
		logger.Global.Debug("Monitor stopped")
	}

	return nil
}

func getEventTypeName(eventType uint32) string {
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

// Debug function to log the status of the probes
func (m *Monitor) logProbeStatus() {
	logger.Global.Info("Currently registered probes",
		"total", len(m.links),
		"probes", fmt.Sprintf("%v", m.links))
}

func (m *Monitor) handleEvents(ctx context.Context) {
	logger.Global.Debug("Starting file event processing")
	m.logProbeStatus()

	errChan := make(chan error, 1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				logger.Global.Debug("Received exit signal, stopping file event processing")
				errChan <- nil
				return
			default:
				record, err := m.reader.Read()
				if err != nil {
					if err == ringbuf.ErrClosed {
						logger.Global.Debug("Ring buffer closed")
						errChan <- nil
						return
					}
					errChan <- fmt.Errorf("reading event: %w", err)
					continue
				}

				var event Event
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					logger.Global.Error("Failed to parse event", "error", err)
					continue
				}

				fileName := utils.CleanString(event.FileName[:])
				processName := utils.CleanProcessName(event.Comm[:])
				parentProcessName := utils.CleanProcessName(event.Pcomm[:])

				// Check if file is in monitored directories
				monitored := false
				for _, dir := range m.dirs {
					if strings.HasPrefix(fileName, dir) {
						monitored = true
						break
					}
				}

				if !monitored {
					// Use Debug level instead of Trace
					logger.Global.Debug("Ignoring event for non-monitored directory",
						"path", fileName,
						"event_type", getEventTypeName(event.EventType))
					continue
				}

				baseFileName := filepath.Base(fileName)

				logger.Global.Info("File operation",
					"type", getEventTypeName(event.EventType),
					"path", fileName,
					"filename", baseFileName,
					"process", processName,
					"pid", event.Pid,
					"parent_process", parentProcessName,
					"ppid", event.Ppid,
					"uid", event.Uid,
					"event_type_code", event.EventType)
			}
		}
	}()

	select {
	case err := <-errChan:
		if err != nil {
			logger.Global.Error("Event processing error", "error", err)
		}
	case <-ctx.Done():
		logger.Global.Debug("Closing event processing")
		<-errChan
	}
}

func (m *Monitor) Collect(ctx context.Context) (<-chan collector.Event, error) {
	return m.eventChan, nil
}

// GetType returns the type of the monitor
func (m *Monitor) GetType() string {
	return "file"
}
