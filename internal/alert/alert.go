package alert

import (
	"context"
	"fmt"
	"time"
)

// AlertLevel represents the severity level of an alert
type AlertLevel int

const (
	// InfoLevel represents information level alerts
	InfoLevel AlertLevel = iota
	// WarnLevel represents warning level alerts
	WarnLevel
	// ErrorLevel represents error level alerts
	ErrorLevel
	// CriticalLevel represents critical level alerts
	CriticalLevel
)

// Alert represents an alert message
type Alert struct {
	Level     AlertLevel             `json:"level"`     // Alert severity level
	Title     string                 `json:"title"`     // Alert title
	Message   string                 `json:"message"`   // Alert message content
	Source    string                 `json:"source"`    // Alert source (e.g., "file_monitor")
	Timestamp time.Time              `json:"timestamp"` // Alert creation time
	Metadata  map[string]interface{} `json:"metadata"`  // Additional alert metadata
}

// Alerter defines the interface for alert notification systems
type Alerter interface {
	// Send sends an alert notification
	Send(ctx context.Context, alert *Alert) error
	// Close closes the alerter and releases resources
	Close() error
}

// AlertManager manages multiple alert notification systems
type AlertManager struct {
	alerters []Alerter
}

// NewAlertManager creates a new AlertManager instance
func NewAlertManager() *AlertManager {
	return &AlertManager{
		alerters: make([]Alerter, 0),
	}
}

// RegisterAlerter adds a new alerter to the manager
func (m *AlertManager) RegisterAlerter(alerter Alerter) {
	m.alerters = append(m.alerters, alerter)
}

// Send sends an alert to all registered alerters
func (m *AlertManager) Send(ctx context.Context, alert *Alert) error {
	if len(m.alerters) == 0 {
		return fmt.Errorf("no alerters registered")
	}

	var lastErr error
	for _, alerter := range m.alerters {
		if err := alerter.Send(ctx, alert); err != nil {
			lastErr = fmt.Errorf("failed to send alert: %w", err)
		}
	}
	return lastErr
}

// Close closes all registered alerters
func (m *AlertManager) Close() error {
	var lastErr error
	for _, alerter := range m.alerters {
		if err := alerter.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close alerter: %w", err)
		}
	}
	return lastErr
}

// NewAlert creates a new Alert instance with the given parameters
func NewAlert(level AlertLevel, title, message, source string, metadata map[string]interface{}) *Alert {
	return &Alert{
		Level:     level,
		Title:     title,
		Message:   message,
		Source:    source,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
}

// Example implementation of a console alerter
type ConsoleAlerter struct{}

// NewConsoleAlerter creates a new ConsoleAlerter instance
func NewConsoleAlerter() *ConsoleAlerter {
	return &ConsoleAlerter{}
}

// Send implements the Alerter interface for ConsoleAlerter
func (a *ConsoleAlerter) Send(ctx context.Context, alert *Alert) error {
	fmt.Printf("[%s] %s - %s: %s\n", alert.Level, alert.Timestamp.Format(time.RFC3339), alert.Title, alert.Message)
	return nil
}

// Close implements the Alerter interface for ConsoleAlerter
func (a *ConsoleAlerter) Close() error {
	return nil
}

// String returns the string representation of AlertLevel
func (l AlertLevel) String() string {
	switch l {
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case CriticalLevel:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}
