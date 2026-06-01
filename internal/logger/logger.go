// Package logger provides structured JSON logging to stdout.
// Each log entry is a single JSON line with timestamp, level, message, and fields.
package logger

import (
	"encoding/json"
	"os"
	"time"
)

type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Logger writes structured JSON log lines to stdout.
type Logger struct {
	minLevel Level
}

// New returns a logger that emits entries at or above minLevel.
func New(minLevel Level) *Logger {
	return &Logger{minLevel: minLevel}
}

type logEntry struct {
	Timestamp string         `json:"timestamp"`
	Level     Level          `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

func (l *Logger) log(level Level, msg string, fields map[string]any) {
	if !l.shouldLog(level) {
		return
	}
	entry := logEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Message:   msg,
		Fields:    fields,
	}
	_ = json.NewEncoder(os.Stdout).Encode(entry)
}

func (l *Logger) shouldLog(level Level) bool {
	order := map[Level]int{LevelInfo: 0, LevelWarn: 1, LevelError: 2}
	return order[level] >= order[l.minLevel]
}

func (l *Logger) Info(msg string, fields map[string]any)  { l.log(LevelInfo, msg, fields) }
func (l *Logger) Warn(msg string, fields map[string]any)  { l.log(LevelWarn, msg, fields) }
func (l *Logger) Error(msg string, fields map[string]any) { l.log(LevelError, msg, fields) }
