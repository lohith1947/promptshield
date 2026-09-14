// promptshield local scanner — pure-JS port of the Go detection engine
// (scanner/patterns.go + scanner/scanner.go + policy/policy.go).
// Runs entirely in the browser: no gateway required. When the local gateway
// is also online, content.js prefers its verdict for the audit/dashboard.

const PromptShieldScanner = (function () {
  'use strict';

  const PATTERNS = [
    // === IDENTITY (Critical) ===
    { name: 'SSN', re: /\b\d{3}-\d{2}-\d{4}\b/i, severity: 'critical', blockable: true },
    { name: 'SSN_NoDash', re: /\b[1-9]\d{8}\b/i, severity: 'critical', blockable: true },
    { name: 'Passport', re: /\b[A-Z]{2}\d{6,9}\b/i, severity: 'critical', blockable: true },

    // === FINANCIAL (Critical) ===
    { name: 'CreditCard_Visa', re: /\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/i, severity: 'critical', blockable: true },
    { name: 'CreditCard_Mastercard', re: /\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/i, severity: 'critical', blockable: true },
    { name: 'CreditCard_Amex', re: /\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b/i, severity: 'critical', blockable: true },
    { name: 'CreditCard_Discover', re: /\b6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/i, severity: 'critical', blockable: true },
    { name: 'IBAN', re: /\b[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,7}\b/i, severity: 'critical', blockable: true },

    // === CREDENTIALS (Critical) ===
    { name: 'AWS_Access_Key', re: /\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/i, severity: 'critical', blockable: true },
    { name: 'AWS_Secret_Key', re: /aws[_\-]?secret[_\-]?access[_\-]?key[\s:=]+[A-Za-z0-9/+=]{40}/i, severity: 'critical', blockable: true },
    { name: 'GitHub_Token', re: /\bghp_[A-Za-z0-9]{36,}\b/i, severity: 'critical', blockable: true },
    { name: 'GitHub_Fine_Grained', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/i, severity: 'critical', blockable: true },
    { name: 'GitLab_PAT', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/i, severity: 'critical', blockable: true },
    { name: 'Slack_Token', re: /\bxox[bpoas]-[A-Za-z0-9-]+\b/i, severity: 'critical', blockable: true },
    { name: 'Slack_Webhook', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[A-Za-z0-9]{24}/i, severity: 'critical', blockable: true },
    { name: 'OpenAI_Key', re: /\bsk-[A-Za-z0-9]{20,}\b/i, severity: 'critical', blockable: true },
    { name: 'Anthropic_Key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/i, severity: 'critical', blockable: true },
    { name: 'Google_API_Key', re: /\bAIza[A-Za-z0-9_-]{35}\b/i, severity: 'critical', blockable: true },
    { name: 'Gemini_API_Key', re: /\bAIzaSy[A-Za-z0-9_-]{32}\b/i, severity: 'critical', blockable: true },
    { name: 'xAI_API_Key', re: /\bxai-[A-Za-z0-9]{16,}\b/i, severity: 'critical', blockable: true },
    { name: 'Azure_OpenAI_Key', re: /\b(?:azure|openai)[\sA-Za-z_]{0,40}?\bapi\s*key\s*[:=]\s*["']?[A-Za-z0-9+/=_]{24,}/i, severity: 'high', blockable: true },
    { name: 'GCP_Service_Account', re: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/i, severity: 'critical', blockable: true },
    { name: 'Stripe_Key', re: /\b(rk_live|sk_live|rk_test|sk_test)_[A-Za-z0-9]{20,}\b/i, severity: 'critical', blockable: true },
    { name: 'Groq_Key', re: /\bgsk_[A-Za-z0-9]{16,}\b/i, severity: 'critical', blockable: true },
    { name: 'Perplexity_Key', re: /\bpplx-[A-Za-z0-9]{16,}\b/i, severity: 'critical', blockable: true },
    { name: 'SendGrid_Key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/i, severity: 'critical', blockable: true },
    { name: 'Twilio_API_SID', re: /\bSK[A-Za-z0-9]{32}\b/i, severity: 'critical', blockable: true },
    { name: 'npm_Token', re: /\bnpm_[A-Za-z0-9]{36,}\b/i, severity: 'critical', blockable: true },
    { name: 'HuggingFace_Token', re: /\bhf_[A-Za-z0-9]{20,}\b/i, severity: 'critical', blockable: true },
    { name: 'Discord_Token', re: /\b[MNO][A-Za-z0-9]{20,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/i, severity: 'critical', blockable: true },
    { name: 'Private_Key_PEM', re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/i, severity: 'critical', blockable: true },
    { name: 'JWT_Token', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/i, severity: 'critical', blockable: true },
    // value-only group for masking; keeps "password is [REDACTED]" phrasing
    { name: 'Generic_Password', re: /\b(password|passwd|pwd|secret|token|api[_\-]?key)\b(?:\s*[:=]\s*|\s+\b(?:is|was|had)\b\s*[:=]?\s*|\s+)?["']?([^\s"']{8,})["']?/i, severity: 'high', blockable: true },

    // === CONTACT (High) ===
    { name: 'Email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/i, severity: 'high', blockable: false },
    { name: 'Phone_US', re: /\b(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/i, severity: 'high', blockable: false },

    // === NETWORK (Medium) ===
    { name: 'IPv4', re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/i, severity: 'medium', blockable: false },
    { name: 'IPv6', re: /\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/i, severity: 'medium', blockable: false },
  ];

  // luhnCheck — port of scanner/scanner.go
  function luhnCheck(num) {
    const digits = num.replace(/[\s-]/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let allSame = true;
    for (let i = 1; i < digits.length; i++) {
      if (digits[i] !== digits[0]) { allSame = false; break; }
    }
    if (allSame) return false;
    let sum = 0;
    let alternate = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (d < 0 || d > 9) return false;
      if (alternate) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }

  function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    for (const part of parts) {
      if (part === '') return false;
      let n = 0;
      for (const ch of part) {
        const c = ch.charCodeAt(0);
        if (c < 48 || c > 57) return false;
        n = n * 10 + (c - 48);
      }
      if (n > 255) return false;
    }
    return true;
  }

  // isPrivateIP — port of scanner/scanner.go private-range filter
  function isPrivateIP(ip) {
    return /^10\./.test(ip) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
      /^192\.168\./.test(ip) ||
      /^127\./.test(ip) ||
      /^0\./.test(ip);
  }

  // findAllMatches returns [{match, position}] for a pattern
  function findAllMatches(text, pattern) {
    const results = [];
    const re = new RegExp(pattern.re.source, 'g');
    let m;
    const isContenteditablePwd = pattern.name === 'Generic_Password';
    while ((m = re.exec(text)) !== null) {
      if (isContenteditablePwd) {
        // Only the value (group 2) counts as the match, mirroring Go's
        // FindAllStringSubmatchIndex group-2 handling.
        const val = m[2];
        if (val == null || val.length < 8) { re.lastIndex = m.index + 1; continue; }
        results.push({ match: val, position: m.index + (m[0].lastIndexOf(val)), name: pattern.name });
        if (m[0].length === 0) re.lastIndex++; // avoid infinite loop
      } else {
        let match = m[0];
        let valid = true;
        if (/^CreditCard_/.test(pattern.name)) {
          if (!luhnCheck(match)) valid = false;
        } else if (pattern.name === 'IPv4') {
          if (!isValidIPv4(match) || isPrivateIP(match)) valid = false;
        }
        if (valid) results.push({ match: match, position: m.index, name: pattern.name });
        if (m[0].length === 0) re.lastIndex++;
      }
    }
    return results;
  }

  // scan mirrors scanner.Scan: returns [{name, severity, match, position}]
  function scan(text) {
    const detections = [];
    if (!text) return detections;
    for (const p of PATTERNS) {
      const matches = findAllMatches(text, p);
      for (const m of matches) {
        detections.push({ name: m.name, severity: p.severity, match: m.match, position: m.position });
      }
    }
    return detections;
  }

  // maskValues mirrors scanner.MaskValues
  function maskValues(text, detections, prefix) {
    let result = text;
    const counts = {};
    for (const d of detections) {
      if (!d.match) continue;
      counts[d.name] = (counts[d.name] || 0) + 1;
      const token = '[' + prefix + '_' + d.name + '_' + counts[d.name] + ']';
      result = result.split(d.match).join(token);
    }
    return result;
  }

  // evaluate mirrors policy.Policy.Evaluate in block mode (critical = block,
  // everything else = redact; empty = pass).
  function evaluate(detections) {
    if (!detections.length) return { verdict: 'pass', blocked_names: [] };
    const blocked = [];
    const seen = {};
    for (const d of detections) {
      if (d.severity === 'critical' && !seen[d.name]) {
        seen[d.name] = true;
        blocked.push(d.name);
      }
    }
    if (blocked.length) return { verdict: 'block', blocked_names: blocked };
    return { verdict: 'redact', blocked_names: [] };
  }

  // scanText returns a payload identical to the gateway's /api/scan response,
  // so content.js/popup.js can use either source interchangeably.
  function scanText(text) {
    const detections = scan(text);
    const decision = evaluate(detections);
    const resp = {
      ok: true,
      verdict: decision.verdict,
      detections: detections.map((d) => ({ name: d.name, severity: d.severity })),
      blocked_names: decision.blocked_names,
    };
    if (detections.length) {
      resp.safe_text = maskValues(text, detections, 'REDACTED');
    }
    return resp;
  }

  return { scan: scan, scanText: scanText, maskValues: maskValues };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PromptShieldScanner;
}