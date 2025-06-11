package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"runtime/debug"

	"github.com/mxcrafts/ltrack/cmd/options"
	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/config"
	"github.com/mxcrafts/ltrack/internal/monitor/file"
	"github.com/mxcrafts/ltrack/internal/monitor/network"
	exec "github.com/mxcrafts/ltrack/internal/monitor/syscall"
	"github.com/mxcrafts/ltrack/internal/storage"
	"github.com/mxcrafts/ltrack/pkg/logger"
	"github.com/mxcrafts/ltrack/pkg/version"
)

func main() {

	// Defer panic handler
	defer func() {
		if r := recover(); r != nil {
			logger.Global.Error("Program encountered a critical error",
				"error", r)
			os.Exit(1)
		}
	}()

	// Parse command line options
	opts, err := options.Parse()
	if err != nil {
		fmt.Printf("Error parsing options: %v\n", err)
		os.Exit(1)
	}

	// Validate options
	if err := opts.Validate(); err != nil {
		fmt.Printf("Invalid options: %v\n", err)
		os.Exit(1)
	}

	// Defer panic handler
	defer func() {
		if r := recover(); r != nil {
			logger.Global.Error("Program encountered a critical error",
				"error", r,
				"stack", string(debug.Stack()))
			os.Exit(1)
		}
	}()

	// Load configuration
	config, err := config.Load(opts.ConfigPath)
	if err != nil {
		logger.Global.Error("Load Configuration Failed",
			"path", opts.ConfigPath,
			"error", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.InitLogger(&config.Log); err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}

	// Log startup message
	logger.Global.Info("ltrack Started",
		"version", version.Version)

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create wait group
	var wg sync.WaitGroup

	// 初始化存储系统
	var eventChan chan interface{}
	var storageManager *storage.StorageManager

	if config.Storage.Enabled {
		logger.Global.Info("初始化存储系统...",
			"type", config.Storage.Type,
			"format", config.Storage.Format,
			"adapter", config.Storage.Adapter)

		// 转换存储配置
		storageCfg, err := config.Storage.ToStorageConfig()
		if err != nil {
			logger.Global.Error("转换存储配置失败", "error", err)
			os.Exit(1)
		}

		// 创建存储管理器
		storageManager, err = storage.NewStorageManager(storageCfg, config.Storage.Adapter)
		if err != nil {
			logger.Global.Error("创建存储管理器失败", "error", err)
			os.Exit(1)
		}
		defer storageManager.Stop()

		// 创建事件通道
		eventChan = make(chan interface{}, 1000)

		// 启动存储处理
		if err := storageManager.StartProcessing(eventChan); err != nil {
			logger.Global.Error("启动存储处理失败", "error", err)
			os.Exit(1)
		}

		logger.Global.Info("存储系统初始化成功",
			"file_path", config.Storage.FilePath)
	} else {
		logger.Global.Info("存储系统已禁用")
	}

	// Create file monitor
	if config.FileMonitor.Enabled {
		monitor, err := file.NewMonitor()
		if err != nil {
			logger.Global.Error("Create File Monitor Failed",
				"error", err)
			os.Exit(1)
		}

		// Check if monitor implements collector.Collector interface
		fileCollector, isCollector := monitor.(collector.Collector)

		// Type assertion for file monitor specific functions
		if fileMonitor, ok := monitor.(*file.Monitor); ok {
			// Add monitored directories
			for _, dir := range config.FileMonitor.Directories {
				if err := fileMonitor.AddMonitoredDir(dir); err != nil {
					logger.Global.Error("Add Monitored Directory Failed",
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
				logger.Global.Error("Start File Monitor Failed",
					"error", err)
				return
			}

			// 如果存储系统已启用，收集文件监控事件
			if config.Storage.Enabled && eventChan != nil && isCollector {
				eventCh, err := fileCollector.Collect(ctx)
				if err != nil {
					logger.Global.Error("收集文件监控事件失败", "error", err)
				} else {
					// 转发事件到存储系统
					go func() {
						for {
							select {
							case <-ctx.Done():
								return
							case event, ok := <-eventCh:
								if !ok {
									return
								}
								eventChan <- event
							}
						}
					}()
				}
			}

			<-ctx.Done()
			monitor.Stop(ctx)
		}()
	} else {
		logger.Global.Info("File Monitor Disabled")
	}

	// Create exec monitor
	if config.ExecMonitor.Enabled {
		logger.Global.Info("Initializing Exec Monitor...",
			"watch_commands", config.ExecMonitor.WatchCommands)

		monitor, err := exec.NewMonitor(config)
		if err != nil {
			logger.Global.Error("Create Exec Monitor Failed",
				"error", err)
			os.Exit(1)
		}
		logger.Global.Info("Exec Monitor Created Successfully!")

		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := monitor.Start(ctx); err != nil {
				logger.Global.Error("Start Exec Monitor Failed",
					"error", err)
				return
			}

			logger.Global.Info("Exec Monitor Running...",
				"watch_commands", config.ExecMonitor.WatchCommands)

			// 注意：exec监控器可能没有实现Collect方法，取决于其实现
			// 如需在此处收集事件，需先确认exec.Monitor是否实现了collector.Collector接口
			// 以下仅为示例注释
			/*
				if config.Storage.Enabled && eventChan != nil {
					// 在此处添加exec监控器事件收集逻辑，如果支持的话
				}
			*/

			<-ctx.Done()
			logger.Global.Info("Stopping exec monitor...")
			monitor.Stop(ctx)
			logger.Global.Info("Exec Monitor Stopped Successfully!")
		}()
	} else {
		logger.Global.Info("Exec Monitor Disabled")
	}

	// Create network monitor
	if config.NetworkMonitor.Enabled {
		logger.Global.Info("Initializing network monitor...",
			"ports", config.NetworkMonitor.Ports,
			"protocols", config.NetworkMonitor.Protocols)

		monitor, err := network.NewMonitor(config)
		if err != nil {
			logger.Global.Error("Create Network Monitor Failed",
				"error", err)
			os.Exit(1)
		}
		logger.Global.Info("Network Monitor Created Successfully!")

		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := monitor.Start(ctx); err != nil {
				logger.Global.Error("Start Network Monitor Failed",
					"error", err, "stack", debug.Stack())
				return
			}

			logger.Global.Info("Network Monitor Running...",
				"monitored_ports", config.NetworkMonitor.Ports,
				"monitored_protocols", config.NetworkMonitor.Protocols)

			// 注意：网络监控器可能没有实现Collect方法，取决于其实现
			// 如需在此处收集事件，需先确认network.Monitor是否实现了collector.Collector接口
			// 以下仅为示例注释
			/*
				if config.Storage.Enabled && eventChan != nil {
					// 在此处添加网络监控器事件收集逻辑，如果支持的话
				}
			*/

			<-ctx.Done()
			logger.Global.Info("Stopping Network Monitor...")
			monitor.Stop(ctx)
			logger.Global.Info("Network Monitor Stopped Successfully!")
		}()
	} else {
		logger.Global.Info("Network Monitor Disabled")
	}

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigChan
	logger.Global.Info("Received Signal, Preparing Exit",
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
		logger.Global.Info("Program Exited Normally!")
	case <-time.After(5 * time.Second):
		logger.Global.Warn("Program Exit Timed Out!")
	}
}
