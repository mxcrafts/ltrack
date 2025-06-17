package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
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

	return s, nil
}

// Start 启动HTTP服务器
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// 注册路由
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/logs", s.logsHandler)
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

	// 创建日志条目
	entry := LogEntry{
		Timestamp: event.GetTimestamp().Format(time.RFC3339),
		Type:      event.GetType(),
	}

	// 添加事件数据
	if dataProvider, ok := event.(interface{ GetData() map[string]interface{} }); ok {
		entry.Data = dataProvider.GetData()
	} else {
		entry.Data = map[string]interface{}{
			"raw": fmt.Sprintf("%v", event),
		}
	}

	// 按类型分类存储日志
	eventType := event.GetType()
	if len(s.logs[eventType]) >= 1000 {
		// 限制每种类型的日志条目数量，避免内存泄漏
		s.logs[eventType] = s.logs[eventType][1:]
	}
	s.logs[eventType] = append(s.logs[eventType], entry)
}

// indexHandler 处理首页请求
func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.logsMutex.RLock()
	logTypes := make([]string, 0, len(s.logs))
	for logType := range s.logs {
		logTypes = append(logTypes, logType)
	}
	s.logsMutex.RUnlock()

	data := struct {
		LogTypes []string
	}{
		LogTypes: logTypes,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "index.html", data); err != nil {
		logger.Global.Error("Failed to execute template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// logsHandler 处理日志查看请求
func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	logType := r.URL.Query().Get("type")
	if logType == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100 // 默认显示100条
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	s.logsMutex.RLock()
	entries := s.logs[logType]
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	s.logsMutex.RUnlock()

	data := struct {
		LogType  string
		Entries  []LogEntry
		LogTypes []string
	}{
		LogType:  logType,
		Entries:  entries,
		LogTypes: make([]string, 0, len(s.logs)),
	}

	s.logsMutex.RLock()
	for lt := range s.logs {
		data.LogTypes = append(data.LogTypes, lt)
	}
	s.logsMutex.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "logs.html", data); err != nil {
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
					entries = append(entries, typeEntries[len(typeEntries)-limit:]...)
				} else {
					entries = append(entries, typeEntries...)
				}
			}
		}
	} else {
		// 返回特定类型的日志
		typeEntries := s.logs[logType]
		if len(typeEntries) > limit {
			entries = typeEntries[len(typeEntries)-limit:]
		} else {
			entries = typeEntries
		}
	}
	s.logsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		logger.Global.Error("Failed to encode JSON", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
