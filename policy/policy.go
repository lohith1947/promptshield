package policy

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/promptshield/promptshield/scanner"
)

// Mode controls how strictly the guard behaves
type Mode string

const (
	ModeBlock   Mode = "block"   // block critical data, redact medium, log low
	ModeRedact  Mode = "redact"  // never block, just redact
	ModeObserve Mode = "observe" // log everything, never touch
)

// Action is the decision taken for a detection
type Action string

const (
	ActionBlock   Action = "block"
	ActionRedact  Action = "redact"
	ActionLog     Action = "log"
	ActionPass    Action = "pass"
)

// Policy decides what to do with detections
type Policy struct {
	mu      sync.RWMutex
	Mode    Mode
	Actions map[string]Action // per-pattern-name action override
}

// Default returns a sensible default policy
func Default() *Policy {
	return &Policy{
		Mode:    ModeBlock,
		Actions: map[string]Action{},
	}
}

// Decision is the outcome of evaluating detections against the policy
type Decision struct {
	Action       Action               `json:"action"`
	BlockedNames []string             `json:"blocked_names"`
	RedactedName string               `json:"redacted_name"`
	SafeText     string               `json:"safe_text"`
	Detections   []scanner.Detection  `json:"detections"`
	HadSensitive bool                 `json:"had_sensitive"`
	// KnownSecrets carries the raw secret values found in the request so the
	// response scanner can detect echoes. Never serialized to the audit log.
	KnownSecrets []string `json:"-"`
}

// Evaluate applies policy to detections and returns the decision
func (p *Policy) Evaluate(text string, detections []scanner.Detection) Decision {
	if len(detections) == 0 {
		return Decision{
			Action:       ActionPass,
			SafeText:     text,
			HadSensitive: false,
		}
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	var blocked []string
	var redactables []scanner.Detection

	for _, d := range detections {
		// Per-pattern override takes priority
		if override, ok := p.Actions[d.Name]; ok && override == ActionBlock {
			blocked = append(blocked, d.Name)
			continue
		}
		redactables = append(redactables, d)
	}

	switch p.Mode {
	case ModeBlock:
		// Block on any critical severity
		for _, d := range detections {
			if d.Severity == "critical" {
				blocked = append(blocked, d.Name)
			}
		}
		// Deduplicate
		blocked = uniqueStrings(blocked)
		if len(blocked) > 0 {
			return Decision{
				Action:       ActionBlock,
				BlockedNames: blocked,
				SafeText:     "",
				Detections:   detections,
				HadSensitive: true,
			}
		}
	case ModeRedact:
		// Redact everything, block nothing
		redactables = detections
	case ModeObserve:
		return Decision{
			Action:       ActionLog,
			SafeText:     text,
			Detections:   detections,
			HadSensitive: true,
		}
	}

	// Redact the collected items
	safeText := text
	for i, d := range redactables {
		red, _, _ := redactOnce(safeText, d)
		safeText = red
		_ = i
	}

	if len(redactables) > 0 {
		return Decision{
			Action:       ActionRedact,
			SafeText:     safeText,
			Detections:   redactables,
			HadSensitive: true,
		}
	}

	return Decision{
		Action:       ActionLog,
		SafeText:     text,
		Detections:   detections,
		HadSensitive: true,
	}
}

// redactOnce replaces a single detection with a placeholder
func redactOnce(text string, d scanner.Detection) (string, string, bool) {
	if d.Match == "" {
		return text, "", false
	}
	placeholder := "[REDACTED_" + d.Name + "]"
	// Simple replace-all using the detection match
	replaced := replaceAllLiteral(text, d.Match, placeholder)
	return replaced, placeholder, true
}

// replaceAllLiteral does a literal (non-regex) replacement
func replaceAllLiteral(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 {
			out += s
			break
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
	return out
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ToJSON serializes a decision for logging
func DecisionToJSON(d Decision) ([]byte, error) {
	return json.Marshal(d)
}

// LoadFromFile loads policy config from a JSON file
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg struct {
		Mode    string            `json:"mode"`
		Actions map[string]string `json:"actions"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	p := Default()
	switch cfg.Mode {
	case "block":
		p.Mode = ModeBlock
	case "redact":
		p.Mode = ModeRedact
	case "observe":
		p.Mode = ModeObserve
	}
	for k, v := range cfg.Actions {
		p.Actions[k] = Action(v)
	}
	return p, nil
}