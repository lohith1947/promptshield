# promptshield

**A local AI security gateway.** Sits between you (or your team) and any LLM API. Scans every prompt for secrets and personally identifiable information (PII) — then blocks, redacts, or logs it **before the data ever leaves your machine**.

> "Because your data should stay yours."

---

## Why this exists

In 2026, developers and employees routinely paste customer data, API keys, and private documents into AI chatbots and AI coding assistants (Cursor, Claude Code, Copilot). GitGuardian's State of Secrets Sprawl reports:

- 29M secrets exposed on public GitHub
- AI-service secrets leaks up **81% YoY**
- AI-assisted commits leak secrets at **2x the rate of human developers**

Most AI tools send the **full editor context** on every request. That context routinely contains credentials. promptshield puts a security checkpoint between your tools and the AI companies — and stops leaks **before they happen**, not after.

---

## Features

| Feature | Description |
|---|---|
| **Local proxy** | Runs on your machine at `127.0.0.1:8080`. Point any OpenAI-compatible tool at it. |
| **PII detection** | 20+ regex patterns: SSN, credit cards (Luhn-validated), emails, phones, IBAN, private keys |
| **Secret detection** | AWS keys, GitHub tokens, Slack tokens, OpenAI/Anthropic keys, Google API keys, Stripe keys, JWTs, PEM private keys |
| **Request scanning** | Scans every prompt before it leaves your machine |
| **Response scanning** | Scans every AI reply for leaked data echoed back — blocks or redacts it before you see it |
| **Echo detection** | Remembers the raw secrets from your request; catches the model repeating them even when they no longer match a pattern |
| **3 policy modes** | `block` (default), `redact`, `observe` — applied to both directions |
| **Send-anyway confirmation** | Native popup (Windows): before a request is blocked, choose **Yes = send it anyway** or **No = block**. Times out → block. |
| **`/api/scan` endpoint** | Scan arbitrary text (used by the extension); one engine, one audit log |
| **Browser extension** | Manifest V3 (Chrome/Edge) — intercepts prompts in chatgpt.com, claude.ai, gemini before they are sent |
| **Audit log** | Every decision recorded to JSONL — block/redact/pass, request vs response, never the raw secret |
| **Embedded dashboard** | HTML control room at `localhost:3000`, served from the binary itself, showing live activity |
| **Health endpoint** | `/healthz` for monitoring |

---

## Quick start

### 1. Build

```bash
go build -o promptshield main.go
```

Or run directly:

```bash
go run main.go -listen 127.0.0.1:8080 -upstream https://api.openai.com/v1
```

### 2. Point your AI tool at the gateway

Most OpenAI-compatible tools (Cursor, Claude Code, many SDKs) let you override the **base URL**. Set it to:

```
http://localhost:8080/v1
```

Keep your normal API key in the Authorization header — the proxy forwards it.

### 3. Test it

```bash
# Health check
curl http://localhost:8080/healthz   # → ok

# A safe request passes through
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello, tell me about Go"}]}'

# A request with a secret gets blocked in block mode
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My AWS key is AKIAIOSFODNN7EXAMPLE, please review"}]}'
# → 403 blocked: sensitive data detected (AWS_Access_Key)
```

The same protection applies in reverse: if the model tries to echo a secret back
to you (or it was leaked from your context), the response is scanned too.

```bash
# Model answers with an SSN / API key in its reply → response is dropped
# → 403 blocked: sensitive data echoed back (SSN, AWS_Access_Key)
```

### 4. Dashboard

The dashboard is **embedded in the binary** (no static server needed). Start it
with the proxy:

```bash
go run main.go -dashboard 127.0.0.1:3000
```

Open: [http://localhost:3000](http://localhost:3000)

---

## Browser extension (protect chat websites)

The gateway only protects tools you can *point* at `http://localhost:8080/v1`.
Web UIs (chatgpt.com, claude.ai, gemini.google.com) have no such setting — that
is what the extension is for. It intercepts your prompt **before it is sent**,
asks the local gateway to scan it, and cancels the send if sensitive data is
found. Both paths share the same scanner, audit log, and dashboard.

### Install (Chrome / Edge)

1. Make sure the gateway is running: `go run main.go`
2. Open `chrome://extensions` (Edge: `edge://extensions`)
3. Enable **Developer mode**
4. Click **Load unpacked** and select the `extension/` folder
5. Pin the promptshield icon — the popup shows gateway status and lets you test
   any prompt manually

### Test it

Open chatgpt.com/claude.ai, type something like:

```
My AWS key is AKIAIOSFODNN7EXAMPLE, can you review it?
```

Press send — promptshield pauses the send and shows a **decision dialog**
("Block (don't send)" / "Send it anyway"). If you block, **nothing is
transmitted** and your text stays in the box. If you choose "Send it anyway",
the prompt goes through. Either way, a `scan` event appears in the dashboard.
Safe prompts pass through with no dialog.

> **Fail-open by design:** if the gateway is off, the chat site keeps working
> and the banner/pill turns red ("gateway offline"). If your policy is strict,
> flip this in `extension/content.js` (`shouldBlock` on an unreachable gateway).

### How it works

```
chat UIs ──▶ content.js intercepts send ──▶ POST /api/scan (127.0.0.1:8080)
                                                 │
                       blocked/redact ──▶ cancel send + red banner
                       pass/safe      ──▶ re-trigger the send normally
```

---

## Policy modes

| Mode | Critical secrets (API keys, SSN, cards) | Medium PII (email, phone) | Everything else |
|---|---|---|---|
| `block` (default) | **Blocked** (403) | Redacted | Logged |
| `redact` | Redacted | Redacted | Logged |
| `observe` | Logged | Logged | Logged |

Change mode at startup: `go run main.go -mode redact`

---

## Command-line flags

| Flag | Default | Description |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | Address the proxy binds to |
| `-dashboard` | `127.0.0.1:3000` | Dashboard listen address (empty = disabled) |
| `-upstream` | `https://api.openai.com/v1` | Upstream AI provider base URL |
| `-mode` | `block` | Policy mode: `block`, `redact`, `observe` |
| `-audit` | `promptshield-audit.jsonl` | Audit log file |
| `-auth-key` | *(none)* | Optional shared secret (requires `Authorization: Bearer <key>`) |
| `-confirm` | `true` | Ask before blocking: native popup, Yes = send it anyway, No/timeout = block |
| `-confirm-timeout-sec` | `60` | Seconds to wait for the confirmation popup before auto-blocking |

---

## Architecture

```
promptshield/
├── main.go             # entry point, flags, wiring
├── proxy/server.go     # HTTP proxy: intercept → scan → policy → forward → scan response
├── scanner/            # detection engine
│   ├── scanner.go      # Scan + Redact + MaskValues + Luhn validation + private-IP filter
│   ├── patterns.go     # 20+ regex patterns
│   └── scanner_test.go # 195 tests
├── policy/             # the rule book (block / redact / log / observe)
├── logger/             # audit trail (JSONL)
├── dashboard/          # embedded HTML control room
└── extension/          # Chrome/Edge Manifest V3 extension
    ├── manifest.json
    ├── content.js      # send interception in chat pages
    └── popup.*         # status + manual scan tester
```

Flow — both directions are guarded:

```
Your AI tool ──▶ promptshield :8080 ──▶ [scan prompt] ──▶ [policy] ──▶ upstream AI provider
      ▲                                                                      │
      │            ┌──────────── [scan reply] ◀─ look for echoes of redacted │
      │            ▼                                                        ▼
      └───── block / redacted reply ◀───────────── confirm-safe reply ──┘
```

Every decision — request **and** response — lands in the audit log with a
`direction` field so you can trace exactly where a leak was stopped.

---

## Roadmap

- [x] Request scanning (text in chat completions)
- [x] Response scanning (catch PII echoed back in AI replies)
- [x] Browser extension (Manifest V3, protects chat web UIs)
- [x] Streaming responses (SSE) — scan each chunk instead of buffering
- [ ] MCP / agent-tool-call auditing
- [ ] System-wide capture via HTTPS MITM (TLS cert, protects browser AI tools)
- [ ] AI-assisted context detection ("my password is X")
- [ ] Multi-provider support (Anthropic, Gemini) verified
- [ ] Docker packaging
- [ ] Prometheus metrics endpoint

---

## License

MIT