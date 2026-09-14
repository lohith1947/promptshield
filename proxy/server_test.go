package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/promptshield/promptshield/logger"
	"github.com/promptshield/promptshield/policy"
	"github.com/promptshield/promptshield/scanner"
)

// testUpstream wraps an echo server and the body it last received
type testUpstream struct {
	srv      *httptest.Server
	received *[]byte
}

func (u *testUpstream) Close() {
	if u.srv != nil {
		u.srv.Close()
	}
}

// echoUpstream returns a server that echoes the request body back as JSON
func echoUpstream(t *testing.T) *testUpstream {
	t.Helper()
	received := []byte{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	return &testUpstream{srv: srv, received: &received}
}

// leakyUpstream returns a server that always answers with the given response
// body regardless of what is sent to it.
func leakyUpstream(t *testing.T, responseBody string) *testUpstream {
	t.Helper()
	received := []byte{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	return &testUpstream{srv: srv, received: &received}
}

func newTestServer(t *testing.T, mode policy.Mode) (*Server, *testUpstream) {
	t.Helper()
	upstream := echoUpstream(t)
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = mode
	return New(Config{
		Upstream: upstream.srv.URL + "/v1",
	}, scanner.New(), p, al), upstream
}

func sendChat(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "http://localhost:8080/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestBlockModeBlocksSecret(t *testing.T) {
	server, upstream := newTestServer(t, policy.ModeBlock)
	defer upstream.Close()

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My key is AKIAIOSFODNN7EXAMPLE"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "AWS_Access_Key") {
		t.Errorf("response should mention AWS_Access_Key, got: %s", w.Body.String())
	}
}

func TestRedactModeRedactsEmailBeforeForwarding(t *testing.T) {
	server, upstream := newTestServer(t, policy.ModeRedact)
	defer upstream.Close()

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Email the invoice to sales@acme-corp.com please"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from echo upstream, got %d", w.Code)
	}

	var received map[string]any
	if err := json.Unmarshal(*upstream.received, &received); err != nil {
		t.Fatalf("failed to parse upstream body: %v", err)
	}
	messages := received["messages"].([]any)
	content := messages[0].(map[string]any)["content"].(string)

	if strings.Contains(content, "sales@acme-corp.com") {
		t.Errorf("email still present in forwarded body: %q", content)
	}
	if !strings.Contains(content, "[REDACTED_Email]") {
		t.Errorf("expected [REDACTED_Email] placeholder in forwarded body: %q", content)
	}
}

func TestBlockModeRedactsMediumSeverity(t *testing.T) {
	server, upstream := newTestServer(t, policy.ModeBlock)
	defer upstream.Close()

	// Email is "high" severity -> not blocked, should be redacted & forwarded
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Reach me at bob@example.org"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (email redacted not blocked), got %d", w.Code)
	}
	var received map[string]any
	if err := json.Unmarshal(*upstream.received, &received); err != nil {
		t.Fatalf("failed to parse upstream body: %v", err)
	}
	content := received["messages"].([]any)[0].(map[string]any)["content"].(string)
	if strings.Contains(content, "bob@example.org") {
		t.Errorf("email still present in forwarded body: %q", content)
	}
	if !strings.Contains(content, "[REDACTED_Email]") {
		t.Errorf("expected [REDACTED_Email] placeholder, got: %q", content)
	}
}

func TestSafeRequestPassesThroughUnchanged(t *testing.T) {
	server, upstream := newTestServer(t, policy.ModeBlock)
	defer upstream.Close()

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Explain closures in Go with an example"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(string(*upstream.received), "closures in Go") {
		t.Errorf("safe request should be forwarded unchanged, got: %s", string(*upstream.received))
	}
	if strings.Contains(string(*upstream.received), "[REDACTED_") {
		t.Errorf("safe request should contain no redaction markers: %s", string(*upstream.received))
	}
}

func TestRedactModeForwardedBodyIsValidJSON(t *testing.T) {
	server, upstream := newTestServer(t, policy.ModeRedact)
	defer upstream.Close()

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Call 555-123-4567 and send to a@b.com, my SSN is 123-45-6789"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var received map[string]any
	if err := json.Unmarshal(*upstream.received, &received); err != nil {
		t.Fatalf("redacted body is not valid JSON: %v\n%q", err, *upstream.received)
	}
}

func TestResponseBlock_CriticalSecretInResponse(t *testing.T) {
	upstream := leakyUpstream(t, `{"choices":[{"message":{"role":"assistant","content":"Here is the key you asked for: AKIAIOSFODNN7EXAMPLE"}}]}`)
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Explain what an AWS key looks like"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when response leaks a critical secret, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "AWS_Access_Key") {
		t.Errorf("expected block reason AWS_Access_Key, got: %s", w.Body.String())
	}
}

func TestResponseRedact_NonCriticalSecretMasked(t *testing.T) {
	upstream := leakyUpstream(t, `{"choices":[{"message":{"role":"assistant","content":"Contact bob@example.org for the report"}}]}`)
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Who should I contact?"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (email masked, response delivered), got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "bob@example.org") {
		t.Errorf("email leaked into response: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "[REDACTED_Email_1]") {
		t.Errorf("expected redaction token in response: %s", w.Body.String())
	}
}

func TestResponseBlock_EchoedRequestSecretBlocked(t *testing.T) {
	// The request sends password=SuperSecret42. That is a "high" severity ->
	// redacted and forwarded, not blocked. But when the model echoes the raw
	// value back, it no longer matches any pattern (no "password=" prefix), so
	// only the literal echo check can catch it. It must be blocked.
	upstream := leakyUpstream(t, `{"choices":[{"message":{"role":"assistant","content":"No problem, I remember your password is SuperSecret42."}}]}`)
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"save password=SuperSecret42"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when response echoes the request secret, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "EchoedSecret") {
		t.Errorf("expected block reason EchoedSecret, got: %s", w.Body.String())
	}
}

func TestScanEndpoint_BlocksSensitiveText(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)
	h := server.Handler()

	send := func(text string) ScanResponse {
		t.Helper()
		body, _ := json.Marshal(ScanRequest{Text: text})
		req := httptest.NewRequest("POST", "/api/scan", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("scan returned %d: %s", rec.Code, rec.Body.String())
		}
		var out ScanResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("bad scan response: %v", err)
		}
		return out
	}

	if r := send("Please review my AWS key AKIAIOSFODNN7EXAMPLE"); r.Verdict != "block" {
		t.Errorf("expected verdict block, got %q", r.Verdict)
	}
	if r := send("Call me at bob@example.org later"); r.Verdict != "redact" {
		t.Errorf("expected verdict redact, got %q", r.Verdict)
	}
	if r := send("What is the capital of France?"); r.Verdict != "pass" {
		t.Errorf("expected verdict pass, got %q", r.Verdict)
	}
	if r := send("Oh no, my card is 4111 1111 1111 1111"); r.Verdict != "block" {
		t.Errorf("expected verdict block for credit card, got %q", r.Verdict)
	}
}

func TestScanEndpoint_CORSHeaders(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	req := httptest.NewRequest("OPTIONS", "/api/scan", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("missing CORS allow-origin header")
	}
}

func TestScanEndpoint_ReturnsMaskedText(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	text := "My AWS key is AKIAIOSFODNN7EXAMPLE and email bob@example.org"
	handle := server.Handler()
	reqBody, _ := json.Marshal(ScanRequest{Text: text})
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handle.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad scan response: %v", err)
	}
	if out.SafeText == "" {
		t.Fatal("expected safe_text to be populated when detections exist")
	}
	if strings.Contains(out.SafeText, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("safe_text must not contain the AWS key: %q", out.SafeText)
	}
	if strings.Contains(out.SafeText, "bob@example.org") {
		t.Errorf("safe_text must not contain the email: %q", out.SafeText)
	}
	if !strings.Contains(out.SafeText, "REDACTED") {
		t.Errorf("safe_text should contain REDACTED placeholders: %q", out.SafeText)
	}
}

// fakeDecider lets tests simulate the native confirmation dialog.
type fakeDecider struct{ allowed bool }

func (f fakeDecider) Ask(string, string) (bool, error) { return f.allowed, nil }

func TestConfirmAllowed_ForwardsRequestUnchanged(t *testing.T) {
	// leakyUpstream answers with a safe body while still capturing what we sent
	// upstream, so the request-forward path can be asserted without the echo
	// response scanner blocking the loopback.
	upstream := leakyUpstream(t, `{"choices":[{"message":{"role":"assistant","content":"Sure thing."}}]}`)
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)
	server.decider = fakeDecider{allowed: true}

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My key is AKIAIOSFODNN7EXAMPLE"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when user allows the send, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(string(*upstream.received), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("allowed request should be forwarded unchanged, got: %s", string(*upstream.received))
	}
}

func TestConfirmDenied_StillBlocks(t *testing.T) {
	server, upstream := newTestServer(t, policy.ModeBlock)
	defer upstream.Close()
	server.decider = fakeDecider{allowed: false}

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My key is AKIAIOSFODNN7EXAMPLE"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when user blocks, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "AWS_Access_Key") {
		t.Errorf("response should mention AWS_Access_Key, got: %s", w.Body.String())
	}
	if len(*upstream.received) != 0 {
		t.Errorf("blocked request must not reach upstream, got: %s", string(*upstream.received))
	}
}

// --- SSE streaming tests ---

// streamingUpstream returns a server that streams SSE events to the client.
func streamingUpstream(t *testing.T, events []string) *testUpstream {
	t.Helper()
	received := []byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = body
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		for _, event := range events {
			fmt.Fprintf(w, "data: %s\n\n", event)
			if flusher != nil {
				flusher.Flush()
			}
		}
		fmt.Fprintf(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	return &testUpstream{srv: srv, received: &received}
}

func TestStreamForwardsCleanChunks(t *testing.T) {
	upstream := streamingUpstream(t, []string{
		`{"choices":[{"delta":{"content":"Hello"}}]}`,
		`{"choices":[{"delta":{"content":" world"}}]}`,
	})
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello there"}],"stream":true}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for clean stream, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Hello") {
		t.Errorf("expected Hello in streamed response, got: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "[DONE]") {
		t.Errorf("expected [DONE] in streamed response, got: %s", w.Body.String())
	}
}

func TestStreamBlocksLeakedCriticalSecret(t *testing.T) {
	upstream := streamingUpstream(t, []string{
		`{"choices":[{"delta":{"content":"Sure, "}}]}`,
		`{"choices":[{"delta":{"content":"here is the key: AKIAIOSFODNN7EXAMPLE"}}]}`,
	})
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What is an AWS key?"}],"stream":true}`
	w := sendChat(t, server.Handler(), body)

	bodyStr := w.Body.String()
	if !strings.Contains(bodyStr, "promptshield_blocked") {
		t.Errorf("expected blocked event in stream, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "AWS_Access_Key") {
		t.Errorf("expected AWS_Access_Key in block reason, got: %s", bodyStr)
	}
}

func TestStreamRedactsNonCriticalInBlockMode(t *testing.T) {
	upstream := streamingUpstream(t, []string{
		`{"choices":[{"delta":{"content":"Contact "}}]}`,
		`{"choices":[{"delta":{"content":"bob@example.org for details"}}]}`,
	})
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Who should I contact?"}],"stream":true}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for redacted stream, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "bob@example.org") {
		t.Errorf("email leaked into streamed response: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "REDACTED") {
		t.Errorf("expected redaction token in streamed response: %s", w.Body.String())
	}
}

func TestStreamEchoDetectionBlocksRequestSecret(t *testing.T) {
	upstream := streamingUpstream(t, []string{
		`{"choices":[{"delta":{"content":"Your password is "}}]}`,
		`{"choices":[{"delta":{"content":"SuperSecret42."}}]}`,
	})
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeBlock
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"save password=SuperSecret42"}],"stream":true}`
	w := sendChat(t, server.Handler(), body)

	bodyStr := w.Body.String()
	if !strings.Contains(bodyStr, "promptshield_blocked") {
		t.Errorf("expected blocked event for echoed secret, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "EchoedSecret") {
		t.Errorf("expected EchoedSecret in block reason, got: %s", bodyStr)
	}
}

func TestStreamObserveModeLogsButDoesNotBlock(t *testing.T) {
	upstream := streamingUpstream(t, []string{
		`{"choices":[{"delta":{"content":"The key is AKIAIOSFODNN7EXAMPLE"}}]}`,
	})
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeObserve
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Show me the key"}],"stream":true}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 in observe mode, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("observe mode should forward secrets unchanged, got: %s", w.Body.String())
	}
}

func TestStreamRedactModeMasksSecrets(t *testing.T) {
	upstream := streamingUpstream(t, []string{
		`{"choices":[{"delta":{"content":"Here: sk_test_FAKEKEY12345678901234"}}]}`,
	})
	defer upstream.Close()
	al, err := logger.New(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	p := policy.Default()
	p.Mode = policy.ModeRedact
	server := New(Config{Upstream: upstream.srv.URL + "/v1"}, scanner.New(), p, al)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Show me a test key"}],"stream":true}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 in redact mode, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "sk_test_FAKEKEY12345678901234") {
		t.Errorf("secret leaked into streamed response in redact mode: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "REDACTED") {
		t.Errorf("expected redaction token in streamed response: %s", w.Body.String())
	}
}

func TestStreamNonStreamingResponseStillWorks(t *testing.T) {
	// A non-streaming response (application/json) should still be scanned
	// correctly after the streaming code was added.
	server, upstream := newTestServer(t, policy.ModeBlock)
	defer upstream.Close()

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My key is AKIAIOSFODNN7EXAMPLE"}]}`
	w := sendChat(t, server.Handler(), body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-streaming block, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "AWS_Access_Key") {
		t.Errorf("expected AWS_Access_Key, got: %s", w.Body.String())
	}
}