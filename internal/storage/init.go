package storage

import (
	"context"
	"fmt"
	"strings"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/config"
	"github.com/mxcrafts/ltrack/internal/types"
	"github.com/mxcrafts/ltrack/pkg/logger"
)

// InitStorageFromConfig initializes the storage system according to the configuration
func InitStorageFromConfig(cfg types.StorageConfig, adapterName string) (Storage, error) {
	var store Storage
	var err error

	// If an adapter is specified, use the adapter
	if adapterName != "" && adapterName != "default" {
		logger.Global.Debug("Trying to initialize adapter storage",
			"adapter", adapterName,
			"type", string(cfg.Type),
			"format", string(cfg.Format),
			"file_path", cfg.FilePath)

		adapter, err := GetAdapterByName(strings.ToLower(adapterName), cfg)
		if err != nil {
			logger.Global.Error("Failed to get adapter", "error", err, "adapter", adapterName)
			return nil, fmt.Errorf("failed to get adapter: %w", err)
		}

		store, err = NewAdapterStorage(cfg, adapter)
		if err != nil {
			logger.Global.Error("Failed to create adapter storage", "error", err)
			return nil, fmt.Errorf("failed to create adapter storage: %w", err)
		}

		logger.Global.Info("Initialized storage with adapter",
			"adapter", adapterName,
			"type", string(cfg.Type),
			"format", string(cfg.Format))
	} else {
		// Use base storage
		logger.Global.Debug("Trying to initialize base storage",
			"type", string(cfg.Type),
			"format", string(cfg.Format),
			"file_path", cfg.FilePath)

		store, err = NewStorage(cfg)
		if err != nil {
			logger.Global.Error("Failed to create base storage", "error", err)
			return nil, fmt.Errorf("failed to create base storage: %w", err)
		}

		logger.Global.Info("Initialized storage with base config",
			"type", string(cfg.Type),
			"format", string(cfg.Format),
			"file_path", cfg.FilePath)
	}

	return store, nil
}

// StorageManager manages the lifecycle of storage
type StorageManager struct {
	store      Storage
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewStorageManager creates a new storage manager
func NewStorageManager(cfg types.StorageConfig, adapterName string) (*StorageManager, error) {
	logger.Global.Debug("Starting to create storage manager",
		"type", string(cfg.Type),
		"adapter", adapterName,
		"file_path", cfg.FilePath)

	store, err := InitStorageFromConfig(cfg, adapterName)
	if err != nil {
		logger.Global.Error("Failed to initialize storage", "error", err)
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger.Global.Debug("Storage manager created successfully")
	return &StorageManager{
		store:      store,
		ctx:        ctx,
		cancelFunc: cancel,
	}, nil
}

// NewStorageManagerWithKafka 创建支持Kafka的存储管理器
func NewStorageManagerWithKafka(cfg types.StorageConfig, adapterName string, kafkaConfig config.KafkaConfig) (*StorageManager, error) {
	logger.Global.Debug("Starting to create storage manager with Kafka support",
		"type", string(cfg.Type),
		"adapter", adapterName,
		"kafka_enabled", kafkaConfig.Enabled)

	var store Storage
	var err error

	// 如果适配器是kafka，使用特殊的初始化逻辑
	if strings.ToLower(adapterName) == "kafka" && kafkaConfig.Enabled {
		adapter, err := NewKafkaAdapter(cfg, kafkaConfig)
		if err != nil {
			logger.Global.Error("Failed to create kafka adapter", "error", err)
			return nil, fmt.Errorf("failed to create kafka adapter: %w", err)
		}

		store, err = NewAdapterStorage(cfg, adapter)
		if err != nil {
			logger.Global.Error("Failed to create kafka adapter storage", "error", err)
			return nil, fmt.Errorf("failed to create kafka adapter storage: %w", err)
		}

		logger.Global.Info("Initialized storage with Kafka adapter",
			"brokers", kafkaConfig.Brokers,
			"topic", kafkaConfig.Topic,
			"compression", kafkaConfig.Compression)
	} else {
		// 使用标准初始化逻辑
		store, err = InitStorageFromConfig(cfg, adapterName)
		if err != nil {
			logger.Global.Error("Failed to initialize storage", "error", err)
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger.Global.Debug("Storage manager with Kafka support created successfully")
	return &StorageManager{
		store:      store,
		ctx:        ctx,
		cancelFunc: cancel,
	}, nil
}

// GetStorage gets the storage instance
func (sm *StorageManager) GetStorage() Storage {
	return sm.store
}

// StartProcessing starts processing the event channel
func (sm *StorageManager) StartProcessing(eventChan <-chan interface{}) error {
	logger.Global.Debug("Starting event processing flow")

	// Check if storage is properly initialized
	if sm.store == nil {
		logger.Global.Error("Storage not initialized")
		return fmt.Errorf("storage not initialized")
	}

	// Convert channel of interface{} to channel of collector.Event
	typedChan := make(chan collector.Event, 1000)

	go func() {
		defer close(typedChan)
		logger.Global.Debug("Event type conversion goroutine started")

		for {
			select {
			case <-sm.ctx.Done():
				logger.Global.Debug("Received exit signal, closing event type conversion goroutine")
				return
			case event, ok := <-eventChan:
				if !ok {
					logger.Global.Debug("Event channel closed, exiting conversion goroutine")
					return
				}

				if event == nil {
					logger.Global.Warn("Received nil event, skipped")
					continue
				}

				if e, ok := event.(collector.Event); ok {
					logger.Global.Debug("Event type conversion succeeded",
						"type", e.GetType(),
						"timestamp", e.GetTimestamp().Format("2006-01-02 15:04:05"))
					typedChan <- e
				} else {
					logger.Global.Warn("Received non-Event type event, ignored",
						"type", fmt.Sprintf("%T", event))
				}
			}
		}
	}()

	// Start storage processing
	go func() {
		logger.Global.Debug("Event storage goroutine started")

		if err := sm.store.ProcessEvents(sm.ctx, typedChan); err != nil && err != context.Canceled {
			logger.Global.Error("Failed to process event stream", "error", err)
		}

		logger.Global.Debug("Event storage goroutine exited")
	}()

	logger.Global.Info("Event processing flow started")
	return nil
}

// Stop stops the storage manager
func (sm *StorageManager) Stop() error {
	logger.Global.Debug("Preparing to stop storage manager")
	sm.cancelFunc()

	err := sm.store.Close()
	if err != nil {
		logger.Global.Error("Failed to close storage", "error", err)
	} else {
		logger.Global.Debug("Storage closed")
	}

	logger.Global.Info("Storage manager stopped")
	return err
}
