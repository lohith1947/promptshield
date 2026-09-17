//go:build integration

// Package e2e is a black-box test of the real promptshield binary. It builds
// the executable, starts it on spare ports pointing at a fake upstream, then
// exercises the live HTTP surface (proxy, redaction, blocking, response
// scanning, audit log and dashboard APIs).
//
// Run with:
//
//	go test -tags integration -v ./e2e/
//
// The native confirmation dialog is intentionally not automated here (it is a
// modal Windows UI); the allow/deny decision is covered by the handler-level
// fakeDecider tests in proxy/server_test.go.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureUpstream is a fake AI provider that records every request body it
// receives and replies with a configurable canned response.
type captureUpstream struct {
	mu       sync.Mutex
	bodies   []string
	response string
	srv      *httptest.Server
}

func newCaptureUpstream(t *testing.T) *captureUpstream {
	t.Helper()
	u := &captureUpstream{
		response: `{"choices":[{"message":{"role":"assistant","content":"Sure."}}]}`,
	}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.bodies = append(u.bodies, string(b))
		resp := u.response
		u.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, resp)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *captureUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.bodies)
}

func (u *captureUpstream) last() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.bodies) == 0 {
		return ""
	}
	return u.bodies[len(u.bodies)-1]
}

func (u *captureUpstream) setResponse(s string) {
	u.mu.Lock()
	u.response = s
	u.mu.Unlock()
}

// gateway is a running promptshield process under test.
type gateway struct {
	proxyURL string
	dashURL  string
	audit    string
	logPath  string
	cancel   context.CancelFunc
	wait     func()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startGateway(t *testing.T, upstreamURL, auditPath string, proxyPort, dashPort int) *gateway {
	t.Helper()

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "promptshield-e2e.exe")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	logPath := filepath.Join(t.TempDir(), "gateway.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("log file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin,
		"-listen", fmt.Sprintf("127.0.0.1:%d", proxyPort),
		"-upstream", upstreamURL,
		"-dashboard", fmt.Sprintf("127.0.0.1:%d", dashPort),
		"-mode", "block",
		"-confirm=false", // no modal dialog: fail-closed blocks immediately
		"-audit", auditPath,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		cancel()
		t.Fatalf("start gateway: %v", err)
	}

	g := &gateway{
		proxyURL: fmt.Sprintf("http://127.0.0.1:%d", proxyPort),
		dashURL:  fmt.Sprintf("http://127.0.0.1:%d", dashPort),
		audit:    auditPath,
		logPath:  logPath,
		cancel:   cancel,
		wait:     func() { _ = cmd.Wait() },
	}
	t.Cleanup(func() {
		g.cancel()
		g.wait()
		logFile.Close()
	})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(g.proxyURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return g
			}
		}
		time.Sleep(150 * time.Millisecond)
	}

	out, _ := os.ReadFile(logPath)
	t.Fatalf("gateway did not become ready; output:\n%s", out)
	return nil
}

func (g *gateway) postChat(t *testing.T, content string) (int, string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	resp, err := http.Post(g.proxyURL+"/v1/chat/completions", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("post chat: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestGatewayEndToEnd(t *testing.T) {
	upstream := newCaptureUpstream(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	g := startGateway(t, upstream.srv.URL+"/v1", auditPath, freePort(t), freePort(t))

	// 1) A benign prompt is forwarded untouched.
	code, body := g.postChat(t, "Explain Go closures with an example")
	if code != http.StatusOK {
		t.Fatalf("benign: expected 200, got %d: %s", code, body)
	}
	if !strings.Contains(upstream.last(), "Explain Go closures") {
		t.Errorf("benign: upstream did not receive the prompt: %s", upstream.last())
	}
	if strings.Contains(upstream.last(), "REDACTED") {
		t.Errorf("benign: prompt should not be modified: %s", upstream.last())
	}

	// 2) A high-severity finding (email) is redacted before it leaves the box.
	before := upstream.count()
	code, body = g.postChat(t, "Email the invoice to sales@acme-corp.com please")
	if code != http.StatusOK {
		t.Fatalf("redact: expected 200, got %d: %s", code, body)
	}
	if upstream.count() != before+1 {
		t.Fatalf("redact: expected exactly one forwarded request, got %d new", upstream.count()-before)
	}
	if strings.Contains(upstream.last(), "sales@acme-corp.com") {
		t.Errorf("redact: raw email reached upstream: %s", upstream.last())
	}
	if !strings.Contains(upstream.last(), "[REDACTED_Email]") {
		t.Errorf("redact: expected [REDACTED_Email] placeholder upstream: %s", upstream.last())
	}

	// 3) A critical secret is blocked and never forwarded.
	before = upstream.count()
	code, body = g.postChat(t, "My key is AKIAIOSFODNN7EXAMPLE")
	if code != http.StatusForbidden {
		t.Fatalf("block: expected 403, got %d: %s", code, body)
	}
	if !strings.Contains(body, "AWS_Access_Key") {
		t.Errorf("block: response should name the finding, got: %s", body)
	}
	if upstream.count() != before {
		t.Errorf("block: blocked request still reached upstream")
	}

	// 4) A response that leaks a critical secret is blocked on the way back.
	upstream.setResponse(`{"choices":[{"message":{"role":"assistant","content":"Here it is: AKIAIOSFODNN7EXAMPLE"}}]}`)
	code, body = g.postChat(t, "What does an AWS key look like?")
	if code != http.StatusForbidden {
		t.Fatalf("response block: expected 403, got %d: %s", code, body)
	}
	if !strings.Contains(body, "AWS_Access_Key") {
		t.Errorf("response block: should name the finding, got: %s", body)
	}

	// 4b) A response with a non-critical finding is redacted, delivered
	// intact (regression: a copied Content-Length truncated the body).
	upstream.setResponse(`{"choices":[{"message":{"role":"assistant","content":"Contact bob@example.org for the report"}}]}`)
	code, body = g.postChat(t, "Who should I contact?")
	if code != http.StatusOK {
		t.Fatalf("response redact: expected 200, got %d: %s", code, body)
	}
	if strings.Contains(body, "bob@example.org") {
		t.Errorf("response redact: email leaked into response: %s", body)
	}
	if !strings.Contains(body, "[REDACTED_Email") {
		t.Errorf("response redact: expected a redaction token, got: %s", body)
	}

	// 5) The audit log records one line per decision.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	actions, directions := map[string]int{}, map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e struct {
			Action    string `json:"action"`
			Direction string `json:"direction"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		actions[e.Action]++
		directions[e.Direction]++
	}
	for _, want := range []string{"pass", "redact", "block"} {
		if actions[want] == 0 {
			t.Errorf("audit log missing %q decision; got %v", want, actions)
		}
	}
	if directions["request"] == 0 || directions["response"] == 0 {
		t.Errorf("audit log should cover both directions; got %v", directions)
	}

	// 6) The embedded dashboard is served and its API reflects the activity.
	resp, err := http.Get(g.dashURL + "/")
	if err != nil {
		t.Fatalf("dashboard root: %v", err)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(html) == "" || !strings.Contains(string(html), "promptshield") {
		t.Errorf("dashboard root did not serve the UI")
	}

	resp, err = http.Get(g.dashURL + "/api/stats")
	if err != nil {
		t.Fatalf("dashboard stats: %v", err)
	}
	var stats map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		resp.Body.Close()
		t.Fatalf("decode stats: %v", err)
	}
	resp.Body.Close()
	if stats["total"] < 4 {
		t.Errorf("dashboard stats should count every decision, got %v", stats)
	}
	if stats["block"] < 1 || stats["redact"] < 1 || stats["pass"] < 1 {
		t.Errorf("dashboard stats missing expected actions: %v", stats)
	}
}
