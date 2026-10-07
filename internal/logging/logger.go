// Package logging is a small leveled key=value logger.
//
// Output format (one event per line):
//
//	2026-10-07T21:12:16+03:00 WARN country rejected ip=198.51.100.27 country=DE expected=TH
package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	default:
		return "ERROR"
	}
}

// ParseLevel converts a config string into a Level.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "", "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	}
	return LevelInfo, fmt.Errorf("unknown log level %q", s)
}

// Logger writes every event to out and ERROR events additionally to errOut.
type Logger struct {
	mu     sync.Mutex
	level  Level
	out    io.Writer
	errOut io.Writer
	now    func() time.Time
}

// New creates a logger. errOut may be nil.
func New(out, errOut io.Writer, level Level) *Logger {
	return &Logger{out: out, errOut: errOut, level: level, now: time.Now}
}

// Discard returns a logger that drops everything (used in tests).
func Discard() *Logger { return New(io.Discard, nil, LevelError+1) }

// Stderr returns a logger that prints to stderr (CLI usage).
func Stderr(level Level) *Logger { return New(os.Stderr, nil, level) }

// SetLevel changes the minimum level.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
}

func (l *Logger) Debug(msg string, kv ...any) { l.log(LevelDebug, msg, kv) }
func (l *Logger) Info(msg string, kv ...any)  { l.log(LevelInfo, msg, kv) }
func (l *Logger) Warn(msg string, kv ...any)  { l.log(LevelWarn, msg, kv) }
func (l *Logger) Error(msg string, kv ...any) { l.log(LevelError, msg, kv) }

func (l *Logger) log(level Level, msg string, kv []any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level < l.level {
		return
	}
	var b strings.Builder
	b.WriteString(l.now().Format(time.RFC3339))
	b.WriteByte(' ')
	b.WriteString(level.String())
	b.WriteByte(' ')
	b.WriteString(msg)
	for i := 0; i < len(kv); i += 2 {
		b.WriteByte(' ')
		b.WriteString(fmt.Sprint(kv[i]))
		b.WriteByte('=')
		if i+1 < len(kv) {
			b.WriteString(formatValue(kv[i+1]))
		}
	}
	b.WriteByte('\n')
	line := b.String()
	_, _ = io.WriteString(l.out, line)
	if level >= LevelError && l.errOut != nil {
		_, _ = io.WriteString(l.errOut, line)
	}
}

func formatValue(v any) string {
	var s string
	switch t := v.(type) {
	case error:
		if t == nil {
			return "<nil>"
		}
		s = t.Error()
	case time.Duration:
		s = t.String()
	case time.Time:
		s = t.Format(time.RFC3339)
	default:
		s = fmt.Sprint(v)
	}
	if s == "" || strings.ContainsAny(s, " \t\n\"=") {
		return fmt.Sprintf("%q", s)
	}
	return s
}
