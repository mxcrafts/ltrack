package server

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mxcrafts/ltrack/internal/collector"
	"github.com/mxcrafts/ltrack/internal/config"
	"github.com/mxcrafts/ltrack/pkg/logger"
)

//go:embed templates
var templatesFS embed.FS

// LogEntry 表示一个标准化的日志条目
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
}

// Server 表示HTTP服务器
type Server struct {
	config    *config.Config
	server    *http.Server
	logs      map[string][]LogEntry
	logsMutex sync.RWMutex
	templates *template.Template
}

// NewServer 创建一个新的HTTP服务器
func NewServer(cfg *config.Config) (*Server, error) {
	// 加载模板
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	s := &Server{
		config:    cfg,
		logs:      make(map[string][]LogEntry),
		templates: tmpl,
	}

	// 如果存储系统启用，从存储文件加载日志
	if cfg.Storage.Enabled {
		if err := s.loadLogsFromStorage(); err != nil {
			logger.Global.Warn("Failed to load logs from storage", "error", err)
		}
	}

	return s, nil
}

// loadLogsFromStorage 从存储文件加载日志
func (s *Server) loadLogsFromStorage() error {
	// 检查存储类型是否为文件
	if s.config.Storage.Type != "file" {
		logger.Global.Info("Storage type is not file, skipping log loading")
		return nil
	}

	// 检查文件是否存在
	filePath := s.config.Storage.FilePath
	if filePath == "" {
		return fmt.Errorf("storage file path is empty")
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Global.Info("Storage file does not exist, skipping log loading", "path", filePath)
			return nil
		}
		return fmt.Errorf("failed to stat storage file: %w", err)
	}

	// 检查文件大小
	if fileInfo.Size() == 0 {
		logger.Global.Info("Storage file is empty, skipping log loading", "path", filePath)
		return nil
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open storage file: %w", err)
	}
	defer file.Close()

	// 为支持滚动日志，检查备份文件
	var filesToRead []string
	filesToRead = append(filesToRead, filePath)

	// 检查是否有备份文件
	if s.config.Storage.MaxBackups > 0 {
		dir := filepath.Dir(filePath)
		base := filepath.Base(filePath)
		pattern := fmt.Sprintf("%s.*", base)
		backupFiles, err := filepath.Glob(filepath.Join(dir, pattern))
		if err == nil {
			// 将备份文件添加到读取列表
			filesToRead = append(filesToRead, backupFiles...)
		}
	}

	// 记录文件数量
	logger.Global.Info("Found log files to load", "count", len(filesToRead), "files", filesToRead)

	// 从每个文件读取日志
	for _, file := range filesToRead {
		if err := s.loadLogsFromFile(file); err != nil {
			logger.Global.Warn("Failed to load logs from file", "file", file, "error", err)
		}
	}

	// 记录已加载的日志条目数
	totalLogs := 0
	for _, entries := range s.logs {
		totalLogs += len(entries)
	}

	logger.Global.Info("Loaded logs from storage", "total", totalLogs, "types", len(s.logs))

	return nil
}

// loadLogsFromFile 从单个文件加载日志
func (s *Server) loadLogsFromFile(filePath string) error {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// 创建扫描器
	scanner := bufio.NewScanner(file)
	// 设置较大的缓冲区以处理大型行
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	// 加载计数
	loadedCount := 0

	// 根据存储格式选择解析方法
	switch s.config.Storage.Format {
	case "json", "ndjson":
		// 解析JSON或NDJSON格式
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}

			// 清理行，确保它是有效的JSON
			line = strings.TrimSpace(line)

			var logData map[string]interface{}
			if err := json.Unmarshal([]byte(line), &logData); err != nil {
				// 尝试修复可能的格式问题（如有额外的空格或非标准的JSON格式）
				logger.Global.Debug("Failed to parse JSON log line, trying to fix", "line", line, "error", err)

				// 尝试移除非ASCII字符和控制字符
				cleanLine := ""
				for _, r := range line {
					if r >= 32 && r < 127 {
						cleanLine += string(r)
					}
				}

				if err := json.Unmarshal([]byte(cleanLine), &logData); err != nil {
					logger.Global.Debug("Failed to parse JSON after cleaning", "error", err)
					continue
				}
			}

			// 提取必要的字段
			timestamp, ok := logData["@timestamp"].(string)
			if !ok {
				timestamp = time.Now().Format(time.RFC3339)
			}

			logType, ok := logData["type"].(string)
			if !ok {
				// 尝试其他可能的字段名
				if typeVal, ok := logData["event_type"]; ok {
					logType = fmt.Sprintf("%v", typeVal)
				} else {
					logType = "unknown"
				}
			}

			// 标准化日志类型
			switch strings.ToLower(logType) {
			case "open", "read", "write", "close", "create", "unlink", "rename":
				logType = "file"
			case "connect", "accept", "send", "recv", "bind":
				logType = "network"
			case "execve", "exec", "fork", "clone":
				logType = "exec"
			}

			// 创建日志条目
			entry := LogEntry{
				Timestamp: timestamp,
				Type:      logType,
				Data:      make(map[string]interface{}),
			}

			// 复制数据字段，排除特定字段
			for k, v := range logData {
				if k != "@timestamp" && k != "type" {
					entry.Data[k] = v
				}
			}

			// 确保Data字段有有意义的内容
			// 根据日志类型添加一些关键信息
			switch logType {
			case "file":
				// 添加文件操作相关信息
				if path, ok := logData["path"].(string); ok {
					entry.Data["路径"] = path
				}
				if filename, ok := logData["filename"].(string); ok {
					entry.Data["文件名"] = filename
				}
				if process, ok := logData["process"].(string); ok {
					entry.Data["进程"] = process
				}
				if pid, ok := logData["pid"].(float64); ok {
					entry.Data["PID"] = pid
				}
				// 添加原始事件类型
				if origType, ok := logData["type"].(string); ok {
					entry.Data["操作类型"] = origType
				}
			case "network":
				// 添加网络相关信息
				if srcIP, ok := logData["source_ip"].(string); ok {
					entry.Data["源IP"] = srcIP
				}
				if dstIP, ok := logData["destination_ip"].(string); ok {
					entry.Data["目标IP"] = dstIP
				}
				if srcPort, ok := logData["source_port"].(float64); ok {
					entry.Data["源端口"] = srcPort
				}
				if dstPort, ok := logData["destination_port"].(float64); ok {
					entry.Data["目标端口"] = dstPort
				}
				if protocol, ok := logData["protocol"].(string); ok {
					entry.Data["协议"] = protocol
				}
				if process, ok := logData["process"].(string); ok {
					entry.Data["进程"] = process
				}
			case "exec":
				// 添加执行相关信息
				if process, ok := logData["process"].(string); ok {
					entry.Data["进程"] = process
				}
				if cmd, ok := logData["command"].(string); ok {
					entry.Data["命令"] = cmd
				} else if filename, ok := logData["filename"].(string); ok {
					entry.Data["命令"] = filename
				}
				if pid, ok := logData["pid"].(float64); ok {
					entry.Data["PID"] = pid
				}
				if ppid, ok := logData["ppid"].(float64); ok {
					entry.Data["父PID"] = ppid
				}
				if user, ok := logData["user"].(string); ok {
					entry.Data["用户"] = user
				} else if uid, ok := logData["uid"].(float64); ok {
					entry.Data["UID"] = uid
				}
			}

			// 如果Data仍然为空，添加一些基本信息
			if len(entry.Data) == 0 || (len(entry.Data) == 1 && entry.Data["raw"] != nil) {
				for k, v := range logData {
					if k != "@timestamp" && k != "type" && k != "tag" &&
						k != "tags" && k != "host" && k != "service" &&
						k != "environment" && k != "facility" &&
						k != "index_prefix" {
						entry.Data[k] = v
					}
				}
			}

			// 存储日志条目
			s.logsMutex.Lock()
			if len(s.logs[logType]) >= 1000 {
				// 限制每种类型的日志条目数量
				s.logs[logType] = s.logs[logType][1:]
			}
			s.logs[logType] = append(s.logs[logType], entry)
			s.logsMutex.Unlock()

			loadedCount++
		}
	case "text":
		// 解析文本格式 (基本实现，可能需要根据实际文本格式调整)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}

			// 尝试解析文本格式的日志
			parts := strings.SplitN(line, "]", 2)
			if len(parts) < 2 {
				continue
			}

			timestampPart := strings.TrimPrefix(parts[0], "[")
			timestamp, err := time.Parse(time.RFC3339, timestampPart)
			if err != nil {
				timestamp = time.Now()
			}

			typeParts := strings.SplitN(parts[1], ":", 2)
			logType := "unknown"
			logContent := parts[1]

			if len(typeParts) == 2 {
				logType = strings.TrimSpace(typeParts[0])
				logContent = strings.TrimSpace(typeParts[1])
			}

			// 创建日志条目
			entry := LogEntry{
				Timestamp: timestamp.Format(time.RFC3339),
				Type:      logType,
				Data: map[string]interface{}{
					"content": logContent,
				},
			}

			// 存储日志条目
			s.logsMutex.Lock()
			if len(s.logs[logType]) >= 1000 {
				s.logs[logType] = s.logs[logType][1:]
			}
			s.logs[logType] = append(s.logs[logType], entry)
			s.logsMutex.Unlock()

			loadedCount++
		}
	default:
		return fmt.Errorf("unsupported storage format: %s", s.config.Storage.Format)
	}

	// 检查扫描错误
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning file: %w", err)
	}

	logger.Global.Info("Loaded logs from file", "file", filePath, "count", loadedCount)
	return nil
}

// Start 启动HTTP服务器
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// 注册路由
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/api/logs", s.apiLogsHandler)

	// 配置服务器
	addr := fmt.Sprintf("%s:%d", s.config.HttpServer.Host, s.config.HttpServer.Port)
	s.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// 启动服务器
	go func() {
		logger.Global.Info("HTTP server started", "address", addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Global.Error("HTTP server error", "error", err)
		}
	}()

	return nil
}

// Stop 停止HTTP服务器
func (s *Server) Stop(ctx context.Context) error {
	if s.server != nil {
		logger.Global.Info("Stopping HTTP server")
		return s.server.Shutdown(ctx)
	}
	return nil
}

// ProcessEvent 处理来自监控器的事件
func (s *Server) ProcessEvent(event collector.Event) {
	if event == nil {
		return
	}

	s.logsMutex.Lock()
	defer s.logsMutex.Unlock()

	// 获取原始事件类型
	origType := event.GetType()

	// 标准化事件类型
	eventType := origType
	switch strings.ToLower(origType) {
	case "open", "read", "write", "close", "create", "unlink", "rename":
		eventType = "file"
	case "connect", "accept", "send", "recv", "bind":
		eventType = "network"
	case "execve", "exec", "fork", "clone":
		eventType = "exec"
	}

	// 创建日志条目
	entry := LogEntry{
		Timestamp: event.GetTimestamp().Format(time.RFC3339),
		Type:      eventType,
		Data:      make(map[string]interface{}),
	}

	// 添加事件数据
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		rawData := dataProvider.GetData()

		// 复制所有数据
		for k, v := range rawData {
			entry.Data[k] = v
		}

		// 根据事件类型添加中文标签
		switch eventType {
		case "file":
			// 添加文件操作相关信息
			if path, ok := rawData["path"].(string); ok {
				entry.Data["路径"] = path
			}
			if filename, ok := rawData["filename"].(string); ok {
				entry.Data["文件名"] = filename
			}
			if process, ok := rawData["process"].(string); ok {
				entry.Data["进程"] = process
			}
			if pid, ok := rawData["pid"].(float64); ok {
				entry.Data["PID"] = pid
			}
			// 添加原始事件类型
			entry.Data["操作类型"] = origType
		case "network":
			// 添加网络相关信息
			if srcIP, ok := rawData["source_ip"].(string); ok {
				entry.Data["源IP"] = srcIP
			}
			if dstIP, ok := rawData["destination_ip"].(string); ok {
				entry.Data["目标IP"] = dstIP
			}
			if srcPort, ok := rawData["source_port"].(float64); ok {
				entry.Data["源端口"] = srcPort
			}
			if dstPort, ok := rawData["destination_port"].(float64); ok {
				entry.Data["目标端口"] = dstPort
			}
			if protocol, ok := rawData["protocol"].(string); ok {
				entry.Data["协议"] = protocol
			}
			if process, ok := rawData["process"].(string); ok {
				entry.Data["进程"] = process
			}
		case "exec":
			// 添加执行相关信息
			if process, ok := rawData["process"].(string); ok {
				entry.Data["进程"] = process
			}
			if cmd, ok := rawData["command"].(string); ok {
				entry.Data["命令"] = cmd
			} else if filename, ok := rawData["filename"].(string); ok {
				entry.Data["命令"] = filename
			}
			if pid, ok := rawData["pid"].(float64); ok {
				entry.Data["PID"] = pid
			}
			if ppid, ok := rawData["ppid"].(float64); ok {
				entry.Data["父PID"] = ppid
			}
			if user, ok := rawData["user"].(string); ok {
				entry.Data["用户"] = user
			} else if uid, ok := rawData["uid"].(float64); ok {
				entry.Data["UID"] = uid
			}
		}
	} else {
		entry.Data = map[string]interface{}{
			"raw":  fmt.Sprintf("%v", event),
			"操作类型": origType,
		}
	}

	// 按类型分类存储日志
	if len(s.logs[eventType]) >= 1000 {
		// 限制每种类型的日志条目数量，避免内存泄漏
		s.logs[eventType] = s.logs[eventType][1:]
	}

	// 将新的日志添加到开头，而不是末尾
	s.logs[eventType] = append([]LogEntry{entry}, s.logs[eventType]...)
}

// indexHandler 处理首页请求
func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		logger.Global.Error("Failed to execute template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// apiLogsHandler 处理API日志请求
func (s *Server) apiLogsHandler(w http.ResponseWriter, r *http.Request) {
	logType := r.URL.Query().Get("type")

	limitStr := r.URL.Query().Get("limit")
	limit := 100 // 默认显示100条
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	s.logsMutex.RLock()
	var entries []LogEntry
	if logType == "" {
		// 返回所有类型的日志
		entries = make([]LogEntry, 0)
		for _, typeEntries := range s.logs {
			if len(typeEntries) > 0 {
				if len(typeEntries) > limit {
					entries = append(entries, typeEntries[:limit]...)
				} else {
					entries = append(entries, typeEntries...)
				}
			}
		}
	} else {
		// 返回特定类型的日志
		typeEntries := s.logs[logType]
		if len(typeEntries) > limit {
			entries = typeEntries[:limit]
		} else {
			entries = typeEntries
		}
	}
	s.logsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if err := json.NewEncoder(w).Encode(entries); err != nil {
		logger.Global.Error("Failed to encode JSON", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
