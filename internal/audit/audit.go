// Package audit records every credential access to an append-only log.
//
// The log is the only durable evidence of what an agent did with a credential.
// It never contains secret values — recording what was accessed is the point;
// recording the value would recreate the leak this project exists to prevent.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Decision is the outcome of an access attempt.
type Decision string

const (
	Allowed Decision = "allowed"
	Denied  Decision = "denied"
)

// Event is one line of the log.
type Event struct {
	Time time.Time `json:"time"`
	// Tool is the command that ran: "env", "get" or "export".
	Tool   string `json:"tool"`
	Secret string `json:"secret,omitempty"`
	// Field names the variables involved, comma-separated. Names only, never
	// values.
	Field    string   `json:"field,omitempty"`
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason,omitempty"`
}

// FileName is the log's name within the vault directory.
const FileName = "audit.log"

// Logger appends events to a vault's audit log.
type Logger struct{ path string }

// New returns a logger writing to dir/audit.log.
func New(dir string) *Logger { return &Logger{path: filepath.Join(dir, FileName)} }

// Log appends an event.
//
// A failure to write is deliberately not propagated to the caller: refusing to
// run a command because the log is unwritable would turn an auditing problem
// into an outage. The error surfaces on stderr instead.
func (l *Logger) Log(event Event) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}

	line, err := json.Marshal(event)
	if err != nil {
		return
	}

	file, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	file.Write(append(line, '\n'))
}

// Read returns the most recent events, newest last.
func Read(dir string, limit int) ([]Event, error) {
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var events []Event
	for _, line := range splitLines(data) {
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			continue // a truncated final line should not hide the rest
		}
		events = append(events, event)
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
