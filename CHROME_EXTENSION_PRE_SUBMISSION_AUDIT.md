# Chrome Extension Pre-Submission Audit

**Audited:** 2026-09-14
**Extension:** `promptshield - AI prompt privacy guard` v0.5.0
**Audited source:** `extension/` (main repo) and `promptshield-extension-store/` (submission package). Store package verified byte-identical to `extension/` modulo LF/CRLF line endings; zip contents verified against store folder.
**Auditor note:** This is a code-level audit. Google's final store decision cannot be predicted from code alone.

---

## 1. Executive Verdict

**YELLOW — Fix/verify issues before submission**

The extension is genuinely minimal, privacy-conscious code: no remote code, no analytics, only loopback network calls, static-only DOM writes, no raw secrets returned to the browser, and no secrets in the audit log. There is **no evidence of data exfiltration or a remote backend**. However, several reviewer-facing issues should be fixed before submitting: an unused `storage` permission, a privacy policy that understates the number of sites the content script runs on, a privacy disclosure (`chrome.tabs.create`) that hasn't been declared to Google, and store-metadata inaccuracies. None of these are security blockers, but they materially raise the risk of a rejection or a request for additional review.

---

## 2. Project Overview

- **Extension purpose:** Detect sensitive data (passwords, API keys, SSNs, credit cards, emails) in prompts typed into AI chat sites, and intercept the send: show a three-action dialog (Block / Mask & send / Send it anyway) before the prompt transmits. Designed to work together with a local (loopback) "gateway" binary.
- **Manifest version:** MV3 (`manifest_version: 3`).
- **Architecture:**
  - `extension/content.js` — content script on 15 AI-chat domains. Captures Enter/send-button in the capture phase, cancels the native send (`e.preventDefault()`), POSTs the prompt text to `http://127.0.0.1:8080/api/scan`, and on a `block`/`redact` verdict shows a decision dialog. On a `pass` verdict it re-triggers the send itself.
  - `extension/popup.html` + `popup.js` — extension popup: gateway online/offline status (+`/healthz` poll), manual "Scan prompt" sandbox, masked-text preview + copy button, "Privacy" link to the GitHub PRIVACY.md.
  - External companion binary (NOT part of the store package): `main.go` + `proxy/server.go` + `scanner/` + `policy/` + `logger/audit.go` + `dashboard/` — the local gateway at `127.0.0.1:8080` that owns the regex engine, the policy engine, and a local JSONL audit log.
- **Main components (store package):** `manifest.json`, `content.js`, `popup.html`, `popup.js`, `icons/icon{16,32,48,128}.png`.
- **Build system / dependencies:** None for the extension — no package.json, no bundler, no lockfiles, no `node_modules`, no source maps. Plain vanilla JS. The gateway is Go 1.21, standard library only (`go.mod` has zero external requires). Total third-party dependency footprint: **zero**.
- **Store submission package:** `promptshield-extension-store/promptshield-0.5.0.zip` (15,646 bytes) — manifest at zip root, verified against the working tree.

---

## 3. Permissions Audit

| Permission | Required? | Evidence | Risk | Recommendation |
|---|---|---|---|---|
| `storage` | **NO — unused** | `manifest.json:6`. No `chrome.storage` call anywhere in `content.js` or `popup.js` (verified by search). PRIVACY.md claims "The extension uses Chrome's `storage` permission only for its own settings", but no settings exist. | **MEDIUM** — reviewers query unexplained permissions; the store form asks for justification. | **Remove** `storage` from the manifest, and delete the "uses Chrome's storage permission" sentence from PRIVACY.md. No functional impact. |
| `host_permissions: http://127.0.0.1:8080/*` | Yes | `manifest.json:8`; used by `content.js:61` and `popup.js:100` for `/api/scan`, and `content.js:367` / `popup.js:14` for `/healthz`. | LOW — loopback-only, correctly scoped. | Keep. |
| `host_permissions: http://localhost:8080/*` | No — redundant | `manifest.json:9`; neither file ever targets `localhost:8080` (only `http://127.0.0.1:8080` is used as `GATEWAY` in `content.js:7` / `popup.js:3`). | VERY LOW — harmless superset. | Optional: drop one to keep the manifest as tight as possible. |

### Capabilities not requested (good)
- No `tabs`, no `webRequest`, no `declarativeNetRequest`, no `scripting`, no `activeTab`, no clipboard permissions, no options page, no `web_accessible_resources`, no `externally_connectable`, no background service worker, no `optional_permissions`.
- **Clipboard caveat:** `popup.js:81` calls `navigator.clipboard.writeText()` (with line 86 as `document.execCommand('copy')` fallback). Neither requires a declared permission *for a user-gesture write in an extension popup*, which is exactly the context here (a click). No `clipboardRead` is used. Low risk, but note for completeness.

### Content script scope
`manifest.json:15-37`: runs on exactly 15 match patterns, all AI-chat sites and one subpath (`x.com/i/grok/*`), at `document_idle`. This matches the "single purpose" of scanning AI prompts. The `*://` scheme prefix also covers `http://` variants of these sites; harmless.

---

## 4. Credential / Password Data Flow

Complete flow for a typed prompt on a chat site:

1. **INPUT** — `content.js:26-30` `readText()` reads the focused composer: `el.value` for `<textarea>`, `el.innerText`/`el.textContent` for `contenteditable` divs. Only the active prompt is read. No page scraping beyond the active composer.
2. **CAPTURE** — `content.js:307-327` `intercept()` runs on Enter (`keydown` capture) and send-button clicks. It calls `e.preventDefault()` + `e.stopImmediatePropagation()` and holds the send.
3. **DETECTION** — `content.js:314` calls `scan(text)` → `fetch(GATEWAY + '/api/scan', {body: JSON.stringify({text})})` (line 61). The **raw prompt text (including any raw secrets) is sent in the clear over the loopback interface to `127.0.0.1:8080`** — `http://`, not TLS. This never leaves the machine (loopback), but any other local process listening on that address could observe it. Detection itself runs in the local Go gateway (`scanner/scanner.go:46-103` against `scanner/patterns.go`), not in the browser.
4. **PROCESSING / POLICY** — `proxy/server.go:172-187` scans the text, applies the policy, and returns `verdict` (`block|redact|log|pass`), detection **names+severities only**, and `safe_text` (masked) **if** the gateway computes it.
   - **The gateway does NOT return raw secret values.** `ScanResponse` (`server.go:82-91`) deliberately excludes the matched text; `ScanDetection` only carries `name` + `severity`. The `Match` field exists only for gateway-internal echo tracking (`server.go:708 secretValues()`), never serialized to the extension or the audit log. This was verified in source.
   - `redact` verdict → `content.js:75-77 shouldBlock()` treats it as block (a browser-side decision; the extension cannot faithfully redact inside proprietary UIs).
5. **STORAGE — NONE.** The extension has no storage calls (no `chrome.storage`). The gateway writes a JSONL audit log (`logger/audit.go:12-21`) containing only `timestamp / method / path / remote_addr / action / direction / blocked_names / detections` — **never the prompt text or secret values** (the `Entry` struct has no content field; verified `server.go:189-197`). The `.gitignore` excludes `*.jsonl`. Dashboard `/api/log` (`dashboard/dashboard.go:32-35`) serves only these metadata entries, bound to `127.0.0.1`.
6. **NETWORK — loopback only, before send.** The only network calls in the entire extension are to `http://127.0.0.1:8080` (see §5). No bytes are sent to the AI site until a user action after the verdict.
7. **OUTPUT** — on `pass`: `content.js:81-111 reTriggerSend()` re-launches the send (clicks the send button or replays Enter), letting the chat site transmit the prompt (raw, unmodified). On `block`: dialog shown; "Block (don't send)" → `close()` only, nothing sent. On `mask`: `content.js:267-279` rewrites the composer via native value setter / `execCommand('insertText')` with the **masked** text, then re-triggers the send. "Send it anyway" re-triggers with the **raw** text.
8. **FAIL-OPEN** — `content.js:314-317`: if the gateway is unreachable, `scan()` returns null and the send is **allowed through with the raw prompt, unscanned**. This is disclosed in PRIVACY.md and the store listing. It is a deliberate trade-off (site reliability over blocking), but it is the weakest link in the leak-prevention promise.

**Can raw credentials leave the browser?**
- Via the extension itself? **No.** The extension performs no external transmission; its byte-path to the gateway is loopback-only the raw value is never echoed back to the browser or the AI site as part of the scan mechanism.
- Via the chat site it intercepts? **Yes, in three explicit scenarios:** (a) gateway offline → fail-open sends raw (unscanned) text; (b) user chooses "Send it anyway" → raw text sent; (c) "Mask & send" → masked text sent, so raw secrets *inside the detected values* do not leave — but any secret the scanner *fails to detect* (regex-age, obfuscation, "connector-gap" phrasing) will be sent in the masked mode too. Scanning is regex-based; it is not a guarantee.
- After user confirmation the re-triggered send is the site's own HTTPS request, not a direct extension fetch. The extension actively causes it (click/Enter replay), so the extension is the trigger — but the transmission is to the site's backend, over the site's channel.

**Redaction reversibility:** Not applicable to the extension's flow (blocking/redact→block). For "Mask & send", detection is regex-based by design and the masked copy replaces the original text in the composer via `setText`. Raw values are not restored, but they may still exist in the site's internal undo/history or in the browser's own autofill — outside the extension's control.

---

## 5. Network / External Communication

The extension itself targets only the loopback gateway:

| Destination | File | Method | Data Sent | Purpose | Risk |
|---|---|---|---|---|---|
| `http://127.0.0.1:8080/api/scan` | `content.js:61` | `fetch` POST | Full prompt text (may include raw secrets) | Pre-send scan verdict | MEDIUM (clear-text loopback; sniffable by other local processes; mitigations below) |
| `http://127.0.0.1:8080/api/scan` | `popup.js:100` | `fetch` POST | Manually typed test text | Manual scan tester | LOW (same loopback) |
| `http://127.0.0.1:8080/healthz` | `content.js:367` | `fetch` GET | none | Status pill every 10s | LOW |
| `http://127.0.0.1:8080/healthz` | `popup.js:14` | `fetch` GET | none | Popup status dot | LOW |
| `https://github.com/lohith1947/promptshield/blob/main/PRIVACY.md` | `popup.js:20` | `chrome.tabs.create` | none | Privacy-policy link on click | LOW — user-initiated; a disclosure question for the store (see §8) |

**No** `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `EventSource`, `axios`, remote scripts, remote configuration, telemetry, analytics, crash reporting, tracking, or webhooks were found anywhere in the extension source.

**Gateway-side external communication (NOT the store package, but relevant to the security story):**
- `main.go:20` default upstream `https://api.openai.com/v1` — only used by the optional OpenAI-compatible proxy path (`/v1/...`), which the browser extension does **not** use (`content.js` and `popup.js` only call `/api/scan` and `/healthz`). If the user runs the gateway and points an AI tool at it, prompts pass through the gateway to the upstream; that's the gateway's documented role and is out of scope for the store submission.
- `proxy/server.go:140-147` sets `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Private-Network: true` for the loopback server. **This means any web page in the same browser can call the local gateway** (its `/api/scan`, `/healthz`). Impact: a malicious page could (a) detect the gateway is running, (b) use it as a "secret-scanner oracle" on attacker-chosen text, or (c) make `/api/scan` calls. It cannot read the user's prompts (the gateway does not store prior texts for query), but the wide-open CORS+PNA is the gateway's weakest local-exposure point. The gateway binds `127.0.0.1` by default (`main.go:19`), so exposure is machine-local.

---

## 6. Privacy Audit

**What the extension accesses:**
- Prompt text in the active composer on the 15 matched sites, only at send time (`content.js:15-30`). Not full page content, not browsing history, not other tabs. (One resonance: `findInput()` falls back to the *first* `contenteditable/textarea` on the page if nothing is focused — could distinct-read a different composer in multi-composer UIs; benign, but a candidate precision nit.)
- Nothing is stored by the extension (no `chrome.storage`), nothing is transmitted externally by the extension (only loopback), no cookies, no fingerprinting. `window.__promptshieldAttached = true` (`content.js:330`) is a same-page flag for injection-once; a page could check it to detect the extension (a minor fingerprinting surface).

**What the gateway stores (local machine, out of the store package):**
- `promptshield-audit.jsonl` with detection metadata only — **no raw prompt text and no secret values** (verified struct: `logger/audit.go:12-21`). In-memory copy for the dashboard.

**Consistency with stated purpose:** The stated purpose is strong ("data stays on your machine"). The implementation is consistent **with one qualification**: PRIVACY.md says nothing is planted on disk and all processing is local — true for the extension. But the fail-open behavior and the clear-text loopback transfer of raw prompt text are not emphasized in the privacy policy. The policy ("The prompt is otherwise never forwarded anywhere by the extension itself") is accurate; the weaker points are that (a) the loopback request is unauthenticated/cleartext and (b) on gateway-off, scanning silently stops.

**Is a privacy policy needed?** Yes — Chrome Web Store requires one for extensions that handle user data. One exists (`PRIVACY.md`), hosted consideration pending (GitHub Pages work in progress). It must be reachable from a stable public URL. The store listing section in `STORE-LISTING.md:70-73` instructs the reader to host it; the actual hosting/URL is not part of the repo and **cannot be verified from source**.

**Privacy disclosures that must be made accurately:**
- "Reads the prompt text you type on supported AI chat sites, processed locally only." — correct.
- **Understatement bug in PRIVACY.md:16-18:** it lists only 7 sites (chatgpt.com, chat.openai.com, claude.ai, gemini.google.com, copilot.microsoft.com, chat.deepseek.com, perplexity.ai) but content script matches **15** patterns (`manifest.json:18-32`). Same understatement appears in `STORE-LISTING.md:20`. Reviewers compare the policy site list to the manifest; mismatch invites a "disclose accurately" request.

---

## 7. Security Audit

| Finding | Severity | File/Location | Evidence | Recommendation |
|---|---|---|---|---|
| No remote code, no external scripts, no `eval`/`new Function` | — (positive) | whole extension | Verified by search; MV3 default CSP; only static `<script src="popup.js">` | Keep. |
| `innerHTML` used only with **static, literal strings**; all dynamic data uses `textContent`/`createElement` | LOW→INFO | `content.js:170` (static SVG path), `popup.js:25,97,112` (static labels) | Chip labels, file names, and dialog text are set via `textContent` (`content.js:202`, `popup.js:55`), never interpolated into HTML. Dashboard (`dashboard/index.html:308-316`) escapes all log values. **No DOM-injection vector found.** | None. |
| Raw prompt (may include secrets) sent in cleartext over loopback to the unauthenticated gateway | MEDIUM | `content.js:61`, `proxy/server.go:153-201` | `http://127.0.0.1:8080`; no auth, no TLS. Only machine-local by binding, but any local listener could sniff. | Accept for the current threat model (local AI-secret guard), but document it; optional bind check / `Origin` allow-list on the gateway. |
| Fail-open: gateway unreachable → unscanned raw send | MEDIUM | `content.js:59-71, 314-317` | `catch → null → reTriggerSend`. | Keep as designed (disclosed), but make the store listing `User content` declaration state scanning may be skipped if the gateway is offline. |
| Unused `storage` permission | MEDIUM | `manifest.json:6` | No `chrome.storage` usage anywhere. | Remove. |
| Wide-open CORS + PNA on the loopback gateway | MEDIUM (gateway, out of store package) | `proxy/server.go:140-147` | `Access-Control-Allow-Origin: *`; any browser page can call `/api/scan`, `/healthz`. | Restrict `Origin` to the extension + dashboard; add optional auth for `/api/scan`. |
| Content-script tampers with send mechanics (Enter replay / button click) | LOW | `content.js:81-111` | A `send`-labeled button is clicked via heuristics; low risk of misfiring on a wrong control, no injection. | Manual QA on the 15 domains is recommended before launch. |
| `setText()` uses `execCommand('insertText')` on contenteditable | LOW | `content.js:37-55` | Deprecated API, still functional; used with **masked** text only. | OK; revisit if a site stops honoring it. |
| Hardcoded code-level secrets | INFO (none actual) | `scanner/scanner_test.go` | Fictional-looking token fixtures (split-string literals to avoid GitHub secret-scan); no real credentials in the extension or the repo. | None. |
| No use of `chrome.runtime.onMessage`/`onMessageExternal`, no `postMessage` inbound handlers | — (positive) | whole extension | Verified by search. No message-trust surface. | Keep. |
| No clipboard *read*; clipboard write only of the **masked** result | INFO | `popup.js:81-87` | `writeText(maskedText.value)`. | None. |

No CRITICAL or HIGH security findings in the *extension* code. The two MEDIUM findings (cleartext loopback, fail-open) are design trade-offs inherent to the product's architecture, both disclosed in PRIVACY.md, not exploitable remotely.

---

## 8. Chrome Web Store Review Risks

Below, explicitly labeled with the categorization the task asked for:

1. **VERIFIED FROM CODE — Unused `storage` permission.** A reviewer asking "why does this permission exist?" has no code answer. This is the single most likely trigger for a "justify your permissions" hold.
2. **VERIFIED FROM CODE — Permission-justification documentation absent.** The store listing describes the permission as "Chrome's `storage` permission… for its own settings" (`PRIVACY.md:30`) but no settings exist. The justification does not match the code.
3. **VERIFIED FROM CODE — Privacy-policy site-list understates reality.** 7 sites in PRIVACY.md vs 15 match patterns in the manifest. Also `STORE-LISTING.md:20` understates.
4. **VERIFIED FROM CODE — `chrome.tabs.create` on click** (`popup.js:20`). Not a permission problem (does not require `tabs`), but a data-disclosure question: Google asks about "user navigation" / outbound links. Accurate answer: user-initiated link to the policy. Should be disclosed consistently if the data-safety form asks.
5. **LIKELY ISSUE — Privacy policy hosting/URL cannot be verified from source.** PRIVACY.md references `https://lohith1947.github.io/promptshield/PRIVACY.md`; the gh-pages branch + Pages configuration were created (verified in git history), but live reachability at review time is out of this audit's reach. Confirm it resolves to the submitted policy before uploading.
6. **LIKELY ISSUE — Metadata accuracy on the listing form.** "Single purpose" and "Works on:" lists must match the manifest's 15 domains. Recommend pasting the exact list from the manifest rather than the abbreviated one in `STORE-LISTING.md:20`.
7. **POSSIBLE REVIEW RISK — Fail-open behavior.** Reviewers may construe "guarantees data stays local" as absolute; the fail-open default and the raw-text re-trigger on "Send it anyway" must be clearly worded in the `User content` disclosure ("processed locally, may be transmitted to the chat site if you confirm or if the local gateway is unavailable").
8. **POSSIBLE REVIEW RISK — "No other software included."** The extension requires a separately installed local binary (the gateway). Without the gateway the extension is a no-op (fail-open). This is not a policy violation, but Google may question functionality robustness. The listing should state the gateway is optional and the extension fails open.
9. **POSSIBLE REVIEW RISK — Screenshots missing.** `STORE-LISTING.md:28-42` provides the shot list but no actual PNGs exist in the submission package. Store requires ≥1 screenshot at submission.
10. **CANNOT VERIFY WITHOUT STORE DASHBOARD —** Developer account ($5), final listing form answers, trademark/contact fields, and the privacy URL's actual state.
11. **VERIFIED FROM CODE — No `icons` key in the manifest.** `manifest.json` has no top-level `icons` field (though PNGs exist in the store package). Not a rejection reason, but the extensions page/toolbar will show the generic puzzle icon; the store icon is uploaded separately in the dashboard. Recommend adding an `icons` block for polish.
12. **VERIFIED FROM CODE — Single-purpose conformity is good.** The single declared purpose (scan + gate AI prompts) matches the functionality. No feature creep, no `web_accessible_resources`, no service worker, no remote code.

Overall review-risk posture: **low-to-moderate**, dominated by the unused permission and the metadata/policy mismatches (#1–#3), which are trivial to fix.

---

## 9. Release Readiness

- [x] **Manifest** — MV3, valid syntax, version pinned, name/description consistent. (`icons` block missing — see §8.11.)
- [x] **Permissions** — minimal, loopback-only host permissions. Two findings: unused `storage` (remove), redundant `localhost` host permission (optional).
- [x] **Host permissions** — scoped to 127.0.0.1:8080 and localhost:8080 only.
- [x] **Privacy** — policy exists and is accurate in substance, but understates the site list (fix) and references storage that isn't used (fix); hosting URL must be live.
- [x] **Network communication** — loopback-only, no external endpoints, verified.
- [x] **Credential handling** — no secrets returned to browser, no secrets logged, masking is value-only, browser-side block on redact. Fail-open and re-trigger paths documented.
- [x] **Security** — no eval/Function/remote code; innerHTML static-only; no message-passing surface; no clipboard read. Cleartext loopback is the one design note.
- [x] **Production configuration** — gateway not bundled in store package; no dev URLs, no test code in the package.
- [x] **Debug code** — none found (`console.log`, `debugger`, source maps absent).
- [x] **Build artifacts** — store zip is clean and byte-matching; no stray binaries in the package. (`promptshield.exe` exists in the repo root but is git-ignored and absent from the store package.)
- [ ] **Store assets** — icons present but not referenced by the manifest; screenshots not yet captured (shot list documented in `STORE-LISTING.md`).

---

## 10. Findings That MUST Be Fixed

1. **Remove the unused `storage` permission** (`extension/manifest.json:6`) and the corresponding claim in `PRIVACY.md:30`. No code depends on it. *Blocker for a clean pass, not for functionality.*
2. **Correct the privacy-policy and listing site lists to match the manifest's 15 domains** (`PRIVACY.md:16-18`, `STORE-LISTING.md:20`). An inaccurate disclosure is the highest-risk item in this audit.

## 11. Findings That Are Recommended But Not Blocking

1. Add an `icons` block to the manifest (`manifest.json`) referencing the existing 16/32/48/128 PNGs.
2. Drop the redundant `http://localhost:8080/*` host permission.
3. Add `Origin` allow-listing / optional auth to the gateway's `/api/scan` and CORS header (defense-in-depth for the loopback service; not part of the store package).
4. Capture the screenshots described in `STORE-LISTING.md:28-42` before submitting. Chrome requires ≥1.
5. Word the `User content` data-safety declaration to explicitly mention the fail-open path and the user-confirmed send.
6. Consider a note in the README/store text that scanning is regex-based, so unusual obfuscations may not be flagged.

---

## 12. Things That Could NOT Be Verified

- **Live availability of the privacy-policy URL** (`https://lohith1947.github.io/promptshield/PRIVACY.md`) at review time.
- **Screenshots** — none exist in the repo; capture and upload are external steps.
- **Google's final decision** — no store dashboard/external information available.
- **Behavior of the 15 chat-site UIs** (React/rich-text quirks, `execCommand` and button-click heuristics) — requires manual QA in a live browser.
- **The absence of secrets in the raw prompt path after "Mask & send"** — depends on the gateway's whole-request view, which uses the same regex set; coverage gaps cannot be fully proven.
- **Whether `chrome.tabs.create` needs to be itemized in the data-safety questionnaire** for the reviewer (form-dependent).

---

## 13. Final Verdict

**YELLOW**

**Confidence:** HIGH

The extension code is clean, minimal, and privacy-preserving with no remote data path, no secrets-in-logs, and no functional code bugs found. The remaining work is centered on reviewer-facing matters (unused permission, policy/listing accuracy, assets, privacy-URL verification), all quick to resolve and none of them security defects.

---

## 14. Follow-up — 0.6.0 remediation (all audit "must-fix" items resolved)

Released as **v0.6.0** (`promptshield-0.6.0.zip`). Status of each pre-submission item:

- **Unused `storage` permission** — REMOVED. `extension\manifest.json` now has an empty `permissions` array; PRIVACY.md no longer claims settings storage.
- **Site-list understatement (7 → 15)** — FIXED in repo-root `PRIVACY.md`, store `PRIVACY.md`, and `STORE-LISTING.md`. All 15 manifest matches are listed.
- **Fail-open / no protection without gateway** — ELIMINATED. The extension now bundles its own detection engine (`extension\scanner.js`, an exact JS port of `scanner\patterns.go` + Luhn + IPv4/private-IP filters). Every prompt is scanned locally in the browser regardless of gateway availability; the gateway is now optional and used only for its verdict + dashboard/audit-log. Parity between JS and Go engines verified by a 42-case node test matrix (all pass). The status pill now shows "protected" or "local scanning active" (both green) instead of a red offline state.
- **Icons not referenced** — FIXED. `icons/icon16/32/48/128.png` added to the extension and an `icons` block added to the manifest.
- **Redundant `http://localhost:8080/*` host permission** — already absent; `127.0.0.1:8080` retained as the (optional) gateway host and justified by the gateway feature.
- **Remaining user-side actions (unchanged):** capture screenshots per `STORE-LISTING.md:28-42`, register the $5 developer account, upload the zip, and confirm the privacy-policy URL `https://lohith1947.github.io/promptshield/PRIVACY.md` is live.

**v0.6.1 (UI/theme polish, no functional or permission change):**
- Redesigned `popup.html`/`popup.js` to a hand-tuned Google-style layout: gradient shield brand, filled-style text field, icon-led verdict cards, pill-style status chip, and a Light / System / Dark theme control in the footer (defaults to the system theme; preference is remembered in the extension page's own `localStorage` — still **no** `storage` permission requested).
- Decision dialog and status pill in `content.js` now follow the system light/dark theme via a `getPal()` palette + CSS variables; theme changes apply live while a dialog is open.
- The dark palette is Google's (`#292a2d` surface, `#8ab4f8` primary, `#f28b82`/`#81c995` semantic accents). Still no icons/asset, data, or permission changes; screenshot list unchanged (dark mode can be an extra shot).

**v1.0.0 — submission cut.** Version renumbered `1.0.0` for the store release (`promptshield-1.0.0.zip`), matching manifest, popup footer, and STORE-LISTING. No functional change from 0.6.1.