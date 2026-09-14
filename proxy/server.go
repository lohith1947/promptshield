package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/promptshield/promptshield/logger"
	"github.com/promptshield/promptshield/policy"
	"github.com/promptshield/promptshield/scanner"
)

// Config holds upstream provider settings
type Config struct {
	Upstream   string // e.g. https://api.openai.com/v1
	ListenAddr string // e.g. :8080
	AuthKey    string // optional shared secret clients must send
	// ConfirmBlocked asks the user before blocking a flagged request. When
	// true, a native dialog offers "send it anyway" (like the browser
	// extension) before data leaves the machine.
	ConfirmBlocked bool
	// ConfirmTimeout is how long to wait for the confirmation dialog before
	// failing closed and blocking.
	ConfirmTimeout time.Duration
}

// Message is the OpenAI-compatible chat message shape
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the outgoing request body shape
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
}

// Decider asks the user to allow or block a flagged request.
// Ask returns true when the user chose to send it anyway, false to block.
type Decider interface {
	Ask(title, message string) (bool, error)
}

// Server is the promptshield proxy
type Server struct {
	cfg     Config
	scanner *scanner.Scanner
	policy  *policy.Policy
	al      *logger.AuditLog
	client  *http.Client
	decider Decider
	// dlgMu serializes confirmation dialogs so concurrent blocked requests
	// do not stack popups on top of each other.
	dlgMu sync.Mutex
}

// ScanRequest is what the browser extension POSTs for a pre-send check
type ScanRequest struct {
	Text string `json:"text"`
}

// ScanDetection is one finding reported back to the caller.
// The raw secret value is intentionally never returned.
type ScanDetection struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// ScanResponse is the verdict from a /api/scan call
type ScanResponse struct {
	Ok         bool            `json:"ok"`
	Verdict    string          `json:"verdict"` // block / redact / log / pass
	Detections []ScanDetection `json:"detections"`
	Blocked    []string        `json:"blocked_names"`
	// SafeText is the input with every detected value replaced by a
	// [REDACTED_*] placeholder. The raw secrets are never returned. Empty
	// when nothing was detected.
	SafeText string `json:"safe_text,omitempty"`
}

// New builds a Server
func New(cfg Config, s *scanner.Scanner, p *policy.Policy, al *logger.AuditLog) *Server {
	server := &Server{
		cfg:     cfg,
		scanner: s,
		policy:  p,
		al:      al,
	// No global timeout: streaming requests need unbounded body reads.
	// Non-streaming requests set a per-request context timeout in forward().
	client: &http.Client{},
	}
	if cfg.ConfirmBlocked {
		server.decider = WindowsDialog{Timeout: cfg.ConfirmTimeout}
	}
	return server
}

// Handler returns the root HTTP handler
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// /v1/chat/completions and /v1/* forward to the upstream
	mux.HandleFunc("/v1/", s.handleProxy)

	// browser-extension pre-send scan endpoint
	mux.HandleFunc("/api/scan", s.handleScan)

	// health endpoint for dashboard / sanity checks
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		for k, v := range newSecurityHeaders() {
			w.Header()[k] = v
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fmt.Fprint(w, "ok")
	})

	return mux
}

// newSecurityHeaders sets CORS + Private Network Access headers so the browser
// extension (running on HTTPS chat sites) can call the local gateway. Modern
// Chrome requires "Access-Control-Allow-Private-Network: true" for requests
// from public pages into the loopback network, otherwise the fetch is silently
// blocked and the extension fails open without a dialog.
func newSecurityHeaders() http.Header {
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	h.Set("Access-Control-Allow-Private-Network", "true")
	return h
}

// handleScan checks arbitrary text for sensitive data without forwarding it
// anywhere. Used by the browser extension to intercept prompts before they are
// sent to chat websites. CORS is wide open because callers come from the
// browser extension (chrome-extension:// origins) and the local dashboard.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	for k, v := range newSecurityHeaders() {
		w.Header()[k] = v
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Text) == "" {
		http.Error(w, `{"ok":false,"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	detections := s.scanner.Scan(req.Text)
	decision := s.policy.Evaluate(req.Text, detections)

	resp := ScanResponse{
		Ok:      true,
		Verdict: string(decision.Action),
		Blocked: decision.BlockedNames,
	}
	for _, d := range detections {
		resp.Detections = append(resp.Detections, ScanDetection{Name: d.Name, Severity: d.Severity})
	}
	// Provide a mask-and-send variant regardless of verdict severity, so the
	// browser extension can offer "mask the sensitive parts and still send".
	if len(detections) > 0 {
		resp.SafeText = scanner.MaskValues(req.Text, detections, "REDACTED")
	}

	s.al.Record(logger.Entry{
		Method:       "POST",
		Path:         "/api/scan",
		RemoteAddr:   r.RemoteAddr,
		Action:       string(decision.Action),
		Direction:    "scan",
		BlockedNames: decision.BlockedNames,
		Detections:   detectionNames(detections),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleProxy intercepts an OpenAI-compatible request
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Authorization check
	if s.cfg.AuthKey != "" && r.Header.Get("Authorization") != "Bearer "+s.cfg.AuthKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// We only scan chat completions deeply; everything else passes through
	if strings.Contains(r.RequestURI, "/chat/completions") {
		decision := s.processRequest(body, r)

		switch decision.Action {
		case policy.ActionBlock:
			if s.confirmAllowed(r, decision) {
				entry := logger.Entry{
					Method:     r.Method,
					Path:       r.RequestURI,
					RemoteAddr: r.RemoteAddr,
					Action:     "allow",
					Direction:  "request",
					Detections: detectionNames(decision.Detections),
				}
				s.al.Record(entry)
				s.forward(w, r, body, decision.KnownSecrets)
				return
			}
			entry := logger.Entry{
				Method:       r.Method,
				Path:         r.RequestURI,
				RemoteAddr:   r.RemoteAddr,
				Action:       "block",
				Direction:    "request",
				BlockedNames: decision.BlockedNames,
				Detections:   detectionNames(decision.Detections),
			}
			s.al.Record(entry)
			writeJSONError(w, http.StatusForbidden, "Request blocked by promptshield: sensitive data detected ("+strings.Join(decision.BlockedNames, ", ")+")")
			return

		case policy.ActionRedact:
			entry := logger.Entry{
				Method:      r.Method,
				Path:        r.RequestURI,
				RemoteAddr:  r.RemoteAddr,
				Action:      "redact",
				Direction:   "request",
				Detections:  detectionNames(decision.Detections),
			}
			s.al.Record(entry)
			// Forward the redacted body upstream
			s.forward(w, r, []byte(decision.SafeText), decision.KnownSecrets)
			return

		case policy.ActionLog:
			entry := logger.Entry{
				Method:      r.Method,
				Path:        r.RequestURI,
				RemoteAddr:  r.RemoteAddr,
				Action:      "log",
				Direction:   "request",
				Detections:  detectionNames(decision.Detections),
			}
			s.al.Record(entry)
			s.forward(w, r, body, decision.KnownSecrets)
			return

		case policy.ActionPass:
			entry := logger.Entry{
				Method:      r.Method,
				Path:        r.RequestURI,
				RemoteAddr:  r.RemoteAddr,
				Action:      "pass",
				Direction:   "request",
				Detections:  detectionNames(decision.Detections),
			}
			s.al.Record(entry)
			s.forward(w, r, body, decision.KnownSecrets)
			return
		}
	}

	// Non-chat path: pass through
	s.forward(w, r, body, nil)
}

// clientName identifies the calling tool for the confirmation dialog.
func (s *Server) clientName(r *http.Request) string {
	if ua := r.Header.Get("User-Agent"); ua != "" {
		return ua
	}
	return r.RemoteAddr
}

// confirmAllowed asks the user whether to forward a flagged request anyway.
// Returns true when the user chose "send it anyway". Fail-closed when no
// decider is configured, the dialog errors, or the user does not answer.
func (s *Server) confirmAllowed(r *http.Request, decision policy.Decision) bool {
	if s.decider == nil {
		return false
	}
	// One dialog at a time: concurrent blocked requests wait their turn so
	// popups never stack.
	s.dlgMu.Lock()
	defer s.dlgMu.Unlock()

	message := fmt.Sprintf(
		"A request from %s was flagged by promptshield.\n\nDetected sensitive data:\n  %s\n\nThe request has NOT been sent to the AI provider yet.\n\n  Yes = send it anyway\n  No  = block it (default)",
		s.clientName(r),
		strings.Join(decision.BlockedNames, ", "),
	)
	allowed, err := s.decider.Ask("promptshield - send it anyway?", message)
	if err != nil {
		return false
	}
	return allowed
}

// processRequest scans the JSON body and applies policy
func (s *Server) processRequest(body []byte, r *http.Request) policy.Decision {
	var req ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// JSON parse fails: pass it through rather than break the client
		return policy.Decision{
			Action:       policy.ActionPass,
			SafeText:     string(body),
			HadSensitive: false,
		}
	}

	// Concatenate all message content for scanning
	var combined strings.Builder
	for i, msg := range req.Messages {
		combined.WriteString(msg.Content)
		if i < len(req.Messages)-1 {
			combined.WriteString("\n")
		}
	}

	text := combined.String()
	detections := s.scanner.Scan(text)

	// If nothing detected, pass through untouched
	if len(detections) == 0 {
		return policy.Decision{
			Action:       policy.ActionPass,
			SafeText:     string(body),
			HadSensitive: false,
		}
	}

	decision := s.policy.Evaluate(text, detections)

	// Remember the raw secret values so the response scanner can detect echoes
	decision.KnownSecrets = s.secretValues(detections)

	// If the decision is to redact, rebuild the JSON with redacted content
	if decision.Action == policy.ActionRedact && decision.SafeText != "" {
		redactedMessages := s.redactMessages(req, decision.SafeText)
		req.Messages = redactedMessages
		if newBody, err := json.Marshal(req); err == nil {
			decision.SafeText = string(newBody)
		}
	}

	return decision
}

// redactMessages rebuilds messages from the redacted combined text
func (s *Server) redactMessages(req ChatRequest, safeText string) []Message {
	// Split the redacted text back on the newlines we inserted
	parts := strings.Split(safeText, "\n")

	var out []Message
	for i, msg := range req.Messages {
		content := msg.Content
		if i < len(parts) {
			content = parts[i]
		}
		out = append(out, Message{
			Role:    msg.Role,
			Content: content,
		})
	}
	return out
}

// forward relays a request to the upstream provider and scans the response.
// For streaming responses (text/event-stream), it delegates to forwardStream
// which scans each SSE event individually and flushes immediately.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, body []byte, knownSecrets []string) {
	// Build upstream URL
	upstreamURL, err := url.Parse(s.cfg.Upstream)
	if err != nil {
		http.Error(w, "bad upstream config", http.StatusInternalServerError)
		return
	}

	// Combine upstream origin with request path.
	// Clients point at localhost:8080/v1/... so strip the leading
	// "/v1" prefix — the upstream base already includes it.
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/v1")
	if path == "" {
		path = "/"
	}
	target := strings.TrimRight(upstreamURL.String(), "/") + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	// For non-streaming requests, apply a read timeout via context so the
	// proxy never hangs on an unresponsive upstream.  Streaming requests
	// must stay open for the full generation duration — they rely on the
	// downstream client's context for cancellation.
	ctx := r.Context()
	isStreamingReq := bytes.Contains(body, []byte(`"stream":true`))
	if !isStreamingReq {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}

	// Copy relevant headers
	for key, values := range r.Header {
		// Skip hop-by-hop headers
		if strings.EqualFold(key, "Content-Length") || strings.EqualFold(key, "Connection") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[promptshield] upstream error: %v", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Streaming response: forward events line-by-line with per-event scanning.
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		s.forwardStream(w, r, resp, knownSecrets)
		return
	}

	// Non-streaming response: buffer the full body, scan, then write.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Scan the response for leaked data echoed back from the model
	if strings.Contains(r.RequestURI, "/chat/completions") {
		safe, decision := s.processResponse(respBody, knownSecrets)
		switch decision.Action {
		case policy.ActionBlock:
			entry := logger.Entry{
				Method:       r.Method,
				Path:         r.RequestURI,
				RemoteAddr:   r.RemoteAddr,
				Action:       "block",
				Direction:    "response",
				BlockedNames: decision.BlockedNames,
				Detections:   detectionNames(decision.Detections),
			}
			s.al.Record(entry)
			writeJSONError(w, http.StatusForbidden, "Response blocked by promptshield: sensitive data echoed back ("+strings.Join(decision.BlockedNames, ", ")+")")
			return
		case policy.ActionRedact:
			entry := logger.Entry{
				Method:     r.Method,
				Path:       r.RequestURI,
				RemoteAddr: r.RemoteAddr,
				Action:     "redact",
				Direction:  "response",
				Detections: detectionNames(decision.Detections),
			}
			s.al.Record(entry)
			w.WriteHeader(resp.StatusCode)
			w.Write(safe)
			return
		}
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// forwardStream relays an SSE stream event-by-event, scanning each event for
// leaked secrets. Clean events are forwarded immediately with no added latency.
// Secrets spanning two SSE events are not caught — this is an acceptable
// trade-off for real-time streaming because models emit coherent tokens, not
// mid-word secret splits.
func (s *Server) forwardStream(w http.ResponseWriter, r *http.Request, resp *http.Response, knownSecrets []string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(resp.StatusCode)

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback: buffer everything (should never happen in practice)
		body, _ := io.ReadAll(resp.Body)
		w.Write(body)
		return
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1 MB max line

	var eventBuf strings.Builder

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")

		if line == "" {
			// Blank line = event boundary.  Process the accumulated event.
			if eventBuf.Len() == 0 {
				fmt.Fprintf(w, "\n")
				flusher.Flush()
				continue
			}

			eventText := eventBuf.String()
			eventBuf.Reset()

			processed, decision := s.processStreamEvent(eventText, knownSecrets)

			switch decision.Action {
			case policy.ActionBlock:
				s.al.Record(logger.Entry{
					Method:       r.Method,
					Path:         r.RequestURI,
					RemoteAddr:   r.RemoteAddr,
					Action:       "block",
					Direction:    "response",
					BlockedNames: decision.BlockedNames,
					Detections:   detectionNames(decision.Detections),
				})
				errJSON, _ := json.Marshal(map[string]any{
					"error": map[string]any{
						"message": "Response blocked by promptshield: sensitive data echoed back (" + strings.Join(decision.BlockedNames, ", ") + ")",
						"type":    "promptshield_blocked",
					},
				})
				fmt.Fprintf(w, "data: %s\n\n", errJSON)
				flusher.Flush()
				return
			case policy.ActionRedact:
				s.al.Record(logger.Entry{
					Method:     r.Method,
					Path:       r.RequestURI,
					RemoteAddr: r.RemoteAddr,
					Action:     "redact",
					Direction:  "response",
					Detections: detectionNames(decision.Detections),
				})
				fmt.Fprintf(w, "%s\n\n", processed)
				flusher.Flush()
			default:
				fmt.Fprintf(w, "%s\n\n", eventText)
				flusher.Flush()
			}
		} else {
			if eventBuf.Len() > 0 {
				eventBuf.WriteString("\n")
			}
			eventBuf.WriteString(line)
		}
	}

	// Flush any remaining buffered content (e.g. final event without trailing blank line)
	if eventBuf.Len() > 0 {
		processed, decision := s.processStreamEvent(eventBuf.String(), knownSecrets)
		switch decision.Action {
		case policy.ActionBlock:
			s.al.Record(logger.Entry{
				Method:       r.Method,
				Path:         r.RequestURI,
				RemoteAddr:   r.RemoteAddr,
				Action:       "block",
				Direction:    "response",
				BlockedNames: decision.BlockedNames,
				Detections:   detectionNames(decision.Detections),
			})
			errJSON, _ := json.Marshal(map[string]any{
				"error": map[string]any{
					"message": "Response blocked by promptshield: sensitive data echoed back (" + strings.Join(decision.BlockedNames, ", ") + ")",
					"type":    "promptshield_blocked",
				},
			})
			fmt.Fprintf(w, "data: %s\n\n", errJSON)
			flusher.Flush()
			return
		case policy.ActionRedact:
			s.al.Record(logger.Entry{
				Method:     r.Method,
				Path:       r.RequestURI,
				RemoteAddr: r.RemoteAddr,
				Action:     "redact",
				Direction:  "response",
				Detections: detectionNames(decision.Detections),
			})
		}
		fmt.Fprintf(w, "%s\n\n", processed)
		flusher.Flush()
	}
}

// processStreamEvent scans a single SSE event for leaked secrets and applies
// the current policy.  Returns the (possibly redacted) event text and the
// decision taken.
func (s *Server) processStreamEvent(eventText string, knownSecrets []string) (string, policy.Decision) {
	detections := s.scanner.Scan(eventText)

	// Literal echo detection — check if a known secret reappears in this event.
	for _, secret := range knownSecrets {
		if secret == "" {
			continue
		}
		if strings.Index(eventText, secret) >= 0 {
			detections = append(detections, scanner.Detection{
				Name:     "EchoedSecret",
				Severity: "critical",
				Match:    secret,
			})
		}
	}

	if len(detections) == 0 {
		return eventText, policy.Decision{Action: policy.ActionPass}
	}

	if s.policy.Mode == policy.ModeObserve {
		return eventText, policy.Decision{
			Action:     policy.ActionLog,
			Detections: detections,
		}
	}

	if s.policy.Mode == policy.ModeBlock {
		var blocked []string
		for _, d := range detections {
			if d.Severity == "critical" {
				blocked = append(blocked, d.Name)
			}
		}
		if len(blocked) > 0 {
			return eventText, policy.Decision{
				Action:       policy.ActionBlock,
				BlockedNames: blocked,
				Detections:   detections,
			}
		}
	}

	// Redact mode (or non-critical findings in block mode): mask leaked
	// values but still deliver the event.
	masked := scanner.MaskValues(eventText, detections, "REDACTED")
	return masked, policy.Decision{
		Action:     policy.ActionRedact,
		Detections: detections,
	}
}

// detectionNames dedupes detection names for the audit log
func detectionNames(dets []scanner.Detection) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range dets {
		if d.Name != "" && !seen[d.Name] {
			seen[d.Name] = true
			out = append(out, d.Name)
		}
	}
	return out
}

// secretValues flattens detections into the raw secret values worth tracking.
// For "key=value / key: value" patterns (e.g. password=Hunter2) it also keeps
// the bare value, since a model echoing a secret back usually repeats just the
// value without the surrounding label.
func (s *Server) secretValues(detections []scanner.Detection) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range detections {
		m := strings.TrimSpace(d.Match)
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
		if i := strings.IndexAny(m, "=:"); i >= 0 && i < len(m)-1 {
			rest := strings.Trim(m[i+1:], `"' `)
			if rest != "" && !seen[rest] {
				seen[rest] = true
				out = append(out, rest)
			}
		}
	}
	return out
}

// processResponse scans an upstream response for leaked data.
// knownSecrets are the raw values that were redacted in the request, so we can
// detect the model echoing them back even if they no longer match a pattern.
func (s *Server) processResponse(body []byte, knownSecrets []string) ([]byte, policy.Decision) {
	text := string(body)
	detections := s.scanner.Scan(text)

	// Literal echo detection: check whether any previously-known secret value
	// reappears in the response (e.g. the model guessed the redacted value)
	for _, secret := range knownSecrets {
		if secret == "" {
			continue
		}
		if i := strings.Index(text, secret); i >= 0 {
			detections = append(detections, scanner.Detection{
				Name:     "EchoedSecret",
				Severity: "critical",
				Match:    secret,
				Position: i,
			})
		}
	}

	if len(detections) == 0 {
		return body, policy.Decision{Action: policy.ActionPass}
	}

	if s.policy.Mode == policy.ModeObserve {
		return body, policy.Decision{
			Action:     policy.ActionLog,
			Detections: detections,
		}
	}

	if s.policy.Mode == policy.ModeBlock {
		var blocked []string
		for _, d := range detections {
			if d.Severity == "critical" {
				blocked = append(blocked, d.Name)
			}
		}
		if len(blocked) > 0 {
			return nil, policy.Decision{
				Action:       policy.ActionBlock,
				BlockedNames: blocked,
				Detections:   detections,
			}
		}
	}

	// Redact mode (or non-critical findings in block mode): mask the leaked
	// values but still deliver the response.
	masked := scanner.MaskValues(text, detections, "REDACTED")
	return []byte(masked), policy.Decision{
		Action:     policy.ActionRedact,
		Detections: detections,
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "promptshield_blocked",
		},
	})
}