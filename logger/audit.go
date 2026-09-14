package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry represents one logged decision
type Entry struct {
	Timestamp    string   `json:"timestamp"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	RemoteAddr   string   `json:"remote_addr"`
	Action       string   `json:"action"` // block / redact / log / pass
	Direction    string   `json:"direction,omitempty"` // request / response
	BlockedNames []string `json:"blocked_names,omitempty"`
	Detections   []string `json:"detections,omitempty"`
}

// AuditLog writes entries to a JSONL file and keeps in-memory copies
type AuditLog struct {
	mu       sync.Mutex
	path     string
	entries  []Entry
	lastSync time.Time
}

// New creates an audit log appended to path
func New(path string) (*AuditLog, error) {
	l := &AuditLog{
		path:    path,
		entries: []Entry{},
	}
	return l, nil
}

// Record writes a single entry to the log
func (l *AuditLog) Record(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e.Timestamp = time.Now().Format(time.RFC3339)
	l.entries = append(l.entries, e)

	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	if err := appendToFile(l.path, append(line, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "[promptshield] audit log error: %v\n", err)
	}
}

// Recent returns the most recent n entries
func (l *AuditLog) Recent(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	if n <= 0 || n > len(l.entries) {
		n = len(l.entries)
	}
	start := len(l.entries) - n
	if start < 0 {
		start = 0
	}
	out := make([]Entry, 0, n)
	for i := start; i < len(l.entries); i++ {
		out = append(out, l.entries[i])
	}
	return out
}

// Stats returns aggregated counters
func (l *AuditLog) Stats() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()

	stats := map[string]int{
		"total":  0,
		"block":  0,
		"redact": 0,
		"log":    0,
		"pass":   0,
		"allow":  0,
	}
	for _, e := range l.entries {
		stats["total"]++
		stats[e.Action]++
	}
	return stats
}

func appendToFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}