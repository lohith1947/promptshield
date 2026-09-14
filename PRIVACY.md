# Privacy Policy

**promptshield** is a browser extension that helps keep sensitive data (passwords, API keys, credentials) from being sent to AI chat websites. This policy describes what the extension does with your data.

*Last updated: September 2026*

## The short version

- The extension **never transmits your prompts to any remote server**.
- Every prompt is scanned **locally in your browser** by the extension's built-in scanner. If the optional local gateway is also running, the text is sent **only to a local gateway at `127.0.0.1:8080`** that runs on your machine.
- Nothing you type is uploaded, stored, or shared with the extension's developer or any third party.
- The gateway, if installed and running, keeps an **audit log on your own machine only** to record what it blocked and why.

## What the extension accesses

The extension runs on these AI chat websites (and only these): chatgpt.com, chat.openai.com, claude.ai, gemini.google.com, grok.com, x.com (Grok), copilot.microsoft.com, chat.deepseek.com, perplexity.ai, you.com, poe.com, chat.mistral.ai, meta.ai, huggingface.co (Chat), and chat.duckduckgo.com.

While you are on one of those sites, the extension reads the text you type into the message box in order to scan it.

## How data flows

1. You type a prompt into an AI chat site.
2. Before the prompt is sent to the AI provider, the extension scans it **locally in your browser** using its built-in detection engine.
3. If the optional local gateway is installed and running, the text is also sent via a **loopback request to `http://127.0.0.1:8080`** — the promptshield gateway running locally on your own computer. A loopback request does not leave your machine. When the gateway is not running, the built-in scanner does all the work, so protection stays on.
4. Only after you choose an action — **Block**, **Mask & send**, or **Send it anyway** — is the message handled. With "Mask & send", sensitive values are replaced with placeholders before anything is sent to the AI provider. The prompt is otherwise never forwarded anywhere by the extension itself; only the AI chat site you are using performs network transmission.

## What is stored

- **Local Gateway**: If you run the optional promptshield gateway, it can keep an audit log (`audit.jsonl`) on your computer recording detections (type of data found, timestamp). This file stays on your machine and is never uploaded.
- **Extension storage**: The extension does not store any data. It uses no storage.
- **Nothing remote**: The extension has no server, no analytics, no telemetry, and no advertising. The developer does not collect, receive, or see any of your prompts.

## What happens if the gateway is not running

The extension's built-in scanner keeps working — prompts are still scanned locally in the browser before they can be sent. The only difference is that the optional dashboard/audit log on your machine is not updated.

## Your data is yours

Because all processing happens on your device, there is nothing for the developer to delete, export, or correct. You can stop collection entirely by uninstalling the extension or pressing the browser's extension toggle to disable it. To remove the local audit log, delete the gateway's log file on your machine.

## Third parties

The extension does not share data with any third party. No tracking, no cookies, no cross-site requests, and no external code.

## Changes to this policy

If this policy changes, the update will be posted here with a new "Last updated" date.

## Contact

For questions about this policy, open an issue at the project repository https://github.com/lohith1947/promptshield.