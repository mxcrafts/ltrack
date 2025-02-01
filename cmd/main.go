package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"runtime/debug"

	"github.com/mxcrafts/mxtrack/internal/config"
	"github.com/mxcrafts/mxtrack/internal/monitor/file"
	"github.com/mxcrafts/mxtrack/internal/monitor/network"
	exec "github.com/mxcrafts/mxtrack/internal/monitor/syscall"
	"github.com/mxcrafts/mxtrack/pkg/logger"
	"github.com/mxcrafts/mxtrack/pkg/version"
)

func main() {
	// Print logo and version
	logger.Global.Info(version.PrintLogo())

	// Defer panic handler
	defer func() {
		if r := recover(); r != nil {
			logger.Global.Error("Program encountered a critical error",
				"error", r)
			os.Exit(1)
		}
	}()

	// Load configuration
	config, err := config.Load("policy.toml")
	if err != nil {
		logger.Global.Error("Failed to load configuration",
			"error", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.InitLogger(&config.Log); err != nil {
		panic(err)
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create wait group
	var wg sync.WaitGroup

	// Create file monitor
	if config.FileMonitor.Enabled {
		monitor, err := file.NewMonitor()
		if err != nil {
			logger.Global.Error("Failed to create monitor",
				"error", err)
			os.Exit(1)
		}

		// Type assertion
		if fileMonitor, ok := monitor.(*file.Monitor); ok {
			// Add monitored directories
			for _, dir := range config.FileMonitor.Directories {
				if err := fileMonitor.AddMonitoredDir(dir); err != nil {
					logger.Global.Error("Failed to add monitored directory",
						"dir", dir,
						"error", err)
					continue
				}
			}
		}

		// Start monitoring
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitor.Start(ctx); err != nil {
				logger.Global.Error("Failed to start monitoring",
					"error", err)
				return
			}
			<-ctx.Done()
			monitor.Stop(ctx)
		}()
	}

	// Create exec monitor
	if config.ExecMonitor.Enabled {
		logger.Global.Info("Initializing exec monitor...",
			"watch_commands", config.ExecMonitor.WatchCommands)

		monitor, err := exec.NewMonitor(config)
		if err != nil {
			logger.Global.Error("Failed to create exec monitor",
				"error", err)
			os.Exit(1)
		}
		logger.Global.Info("Exec monitor created successfully")

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Global.Info("Starting exec monitor goroutine")

			if err := monitor.Start(ctx); err != nil {
				logger.Global.Error("Failed to start exec monitoring",
					"error", err)
				return
			}

			logger.Global.Info("Exec monitor is running",
				"watch_commands", config.ExecMonitor.WatchCommands)

			<-ctx.Done()
			logger.Global.Info("Stopping exec monitor...")
			monitor.Stop(ctx)
			logger.Global.Info("Exec monitor stopped successfully")
		}()
	} else {
		logger.Global.Info("Exec monitor is disabled in configuration")
	}

	// Create network monitor
	if config.NetworkMonitor.Enabled {
		logger.Global.Info("Initializing network monitor...",
			"ports", config.NetworkMonitor.Ports,
			"protocols", config.NetworkMonitor.Protocols)

		monitor, err := network.NewMonitor(config)
		if err != nil {
			logger.Global.Error("Failed to create network monitor",
				"error", err)
			os.Exit(1)
		}
		logger.Global.Info("Network monitor created successfully")

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Global.Info("Starting network monitor goroutine")

			if err := monitor.Start(ctx); err != nil {
				logger.Global.Error("Failed to start network monitoring",
					"error", err, "stack", debug.Stack())
				return
			}

			logger.Global.Info("Network monitor is running",
				"monitored_ports", config.NetworkMonitor.Ports,
				"monitored_protocols", config.NetworkMonitor.Protocols)

			<-ctx.Done()
			logger.Global.Info("Stopping network monitor...")
			monitor.Stop(ctx)
			logger.Global.Info("Network monitor stopped successfully")
		}()
	} else {
		logger.Global.Info("Network monitor is disabled in configuration")
	}

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigChan
	logger.Global.Info("Received signal, preparing to exit",
		"signal", sig.String())

	// Cancel context
	cancel()

	// Wait for all goroutines to complete with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Global.Info("Program exited normally")
	case <-time.After(5 * time.Second):
		logger.Global.Warn("Program exit timed out")
	}
}
