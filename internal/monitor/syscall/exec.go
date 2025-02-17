package exec

import (
	"context"
	"encoding/binary"
	"fmt"

	"bytes"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/mxcrafts/ltrack/internal/config"
	"github.com/mxcrafts/ltrack/pkg/logger"
	"github.com/mxcrafts/ltrack/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS exec ../../../pkg/ebpf/c/exec.c

func NewMonitor(cfg *config.Config) (*Monitor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	m := &Monitor{
		config:   cfg,
		commands: make(map[string]bool),
	}

	for _, cmd := range cfg.ExecMonitor.WatchCommands {
		m.commands[cmd] = true
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

	if err := loadExecObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", m.objs.TraceExecEntry, nil)
	if err != nil {
		m.objs.Close()
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	m.link = tp

	reader, err := ringbuf.NewReader(m.objs.Events)
	if err != nil {
		m.link.Close()
		m.objs.Close()
		return fmt.Errorf("creating ringbuf reader: %w", err)
	}
	m.reader = reader

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
				if err == ringbuf.ErrClosed {
					return
				}
				logger.Global.Error("Error reading from ringbuf", "error", err)
				continue
			}

			var event Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				logger.Global.Error("Failed to parse event", "error", err)
				continue
			}

			comm := utils.CleanString(event.Comm[:])
			filename := utils.CleanString(event.Filename[:])
			argv := utils.CleanCommandArgs(event.Argv[:], event.ArgvSize)

			if m.shouldMonitor(comm) {
				logger.Global.Info("Process execution detected",
					"command", comm,
					"filename", filename,
					"argv", argv,
					"pid", event.PID,
					"ppid", event.PPID,
					"uid", event.UID,
					"gid", event.GID)
			}
		}
	}
}

func (m *Monitor) shouldMonitor(comm string) bool {
	return m.commands[comm]
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

// GetType returns the type of the monitor
func (m *Monitor) GetType() string {
	return "exec"
}
