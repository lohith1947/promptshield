// promptshield content script
// Intercepts prompts typed into AI chat sites and scans them BEFORE they are
// sent. Scanning runs locally in the browser (PromptShieldScanner, see
// scanner.js); if the optional local gateway is also online, its verdict is
// preferred so it can log to the dashboard/audit log. If sensitive data is
// found, the send is paused and a dialog lets you either block it, mask it,
// or send it anyway. Nothing is transmitted until you choose.

const GATEWAY = 'http://127.0.0.1:8080';

function isEditable(el) {
  return el && (el.tagName === 'TEXTAREA' || (el.getAttribute && el.getAttribute('contenteditable') === 'true'));
}

// Find the active prompt input (ChatGPT/Claude use contenteditable divs,
// Gemini and older UIs use textareas).
function findInput() {
  const focused = document.activeElement;
  if (isEditable(focused)) return focused;
  const selectors = ['#prompt-textarea', 'div[contenteditable="true"]', 'textarea'];
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el) return el;
  }
  return null;
}

function readText(el) {
  if (!el) return '';
  if (el.tagName === 'TEXTAREA') return el.value || '';
  return (el.innerText || el.textContent || '').trim();
}

// Write text into a composer (textarea or contenteditable div) in a way that
// React/Vue/rich-text UIs actually pick up. For textareas this uses the native
// value setter (bypasses React's value tracker) then fires input/change. For
// contenteditable divs (ChatGPT, Claude) it selects all and uses execCommand,
// which natively triggers the framework's input events.
function setText(el, text) {
  if (!el) return;
  if (el.tagName === 'TEXTAREA') {
    const proto = window.HTMLTextAreaElement && window.HTMLTextAreaElement.prototype;
    const setter = proto && Object.getOwnPropertyDescriptor(proto, 'value');
    if (setter && setter.set) setter.set.call(el, text);
    else el.value = text;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return;
  }
  el.focus();
  const sel = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(el);
  sel.removeAllRanges();
  sel.addRange(range);
  document.execCommand('insertText', false, text);
}

// Default: scan locally (runs in every browser with zero setup).
// If the optional gateway is online we also call it so it can log to the
// audit/dashboard — but the local scanner always runs regardless.
// On gateway offline or error the prompt is still blocked if the local scan
// finds sensitive data, so the user is protected either way.
let gatewayOnline = false;

async function scan(text) {
  const local = PromptShieldScanner.scanText(text);
  try {
    const res = await fetch(GATEWAY + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (res.ok) {
      const gw = await res.json();
      if (gw) return gw;
    }
  } catch (_e) { /* fall through to local */ }
  return local;
}

// 'redact' also blocks the send in the browser: we cannot redact inside these
// proprietary UIs, so the safest action is to refuse to send.
function shouldBlock(verdict) {
  return verdict === 'block' || verdict === 'redact';
}

// ---- interception machinery ------------------------------------------
// Scanning is async, but the submit events are sync. So we always cancel the
// native action first, ask the gateway, then either show a banner (blocked)
// or re-trigger the send ourselves (safe). A guard flag prevents our own
// re-trigger from looping back into the interceptor.

let simulating = false;

function reTriggerSend(el, originalEvent) {
  simulating = true;
  try {
    const composer = el.closest('form') || el.closest('[data-testid]') || document;
    const scope = composer && composer.querySelectorAll ? composer : document;
    const btn = Array.from(scope.querySelectorAll('button')).find((b) => {
      const label = (b.getAttribute('aria-label') || b.title || b.textContent || '') + ' ' + (b.getAttribute('data-testid') || '');
      return /send/i.test(label);
    });
    const visibleBtn = btn && btn.offsetParent !== null ? btn : null;
    if (visibleBtn) {
      visibleBtn.click();
      return;
    }
    // Fallback: replay Enter on the input
    el.dispatchEvent(new KeyboardEvent('keydown', {
      key: 'Enter', code: 'Enter', bubbles: true, cancelable: true,
    }));
    el.dispatchEvent(new KeyboardEvent('keyup', {
      key: 'Enter', code: 'Enter', bubbles: true, cancelable: true,
    }));
  } finally {
    setTimeout(() => { simulating = false; }, 100);
  }
}

// If a blocked prompt is detected we do NOT silently refuse the send. Instead
// a top-anchored decision card appears with three actions: "Block (don't send)",
// "Mask & send" (replace the flagged values with placeholders, then send) and
// "Send it anyway". The prompt stays in the composer until the user chooses.
let decisionOpen = false;

function injectDialogStyles() {
  if (document.getElementById('promptshield-style')) return;
  const style = document.createElement('style');
  style.id = 'promptshield-style';
  style.textContent = [
    '@keyframes promptshield-drop {',
    '  from { opacity:0; transform:translate(-50%,-18px); }',
    '  to   { opacity:1; transform:translate(-50%,0); }',
    '}',
    'button.promptshield-psbtn { font-family:Roboto,"Segoe UI",system-ui,sans-serif; }',
    'button.promptshield-psbtn:hover { filter:brightness(1.06); box-shadow:0 1px 3px 0 rgba(60,64,67,.3), 0 2px 6px 2px rgba(60,64,67,.15); }',
  ].join('\n');
  (document.head || document.documentElement).appendChild(style);
}

function showDecisionDialog(names, el, originalEvent, safeText) {
  if (decisionOpen) return;
  decisionOpen = true;
  injectDialogStyles();

  const nameList = Array.isArray(names) && names.length ? names.slice(0, 8) : null;

  const card = document.createElement('div');
  card.id = 'promptshield-dialog';
  card.setAttribute('role', 'alertdialog');
  card.setAttribute('aria-live', 'assertive');
  card.style.cssText = [
    'position:fixed', 'top:16px', 'left:50%', 'z-index:2147483647',
    'width:min(560px,calc(100vw - 32px))', 'box-sizing:border-box',
    'background:#ffffff', 'border:1px solid #dadce0',
    'border-radius:16px', 'box-shadow:0 6px 16px 0 rgba(0,0,0,.2), 0 1px 6px 0 rgba(0,0,0,.12)',
    'padding:20px 22px', 'font:400 14px/1.5 Roboto,"Segoe UI",system-ui,sans-serif',
    'color:#202124', 'animation:promptshield-drop 260ms cubic-bezier(.2,.7,.3,1) both',
  ].join(';');

  const accent = document.createElement('div');
  accent.style.cssText = 'position:absolute;left:0;top:14px;bottom:14px;width:4px;border-radius:2px;background:#d93025;';
  card.appendChild(accent);

  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:flex-start;justify-content:space-between;gap:12px;';

  const titleWrap = document.createElement('div');
  titleWrap.style.cssText = 'display:flex;align-items:center;gap:11px;min-width:0;';

  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  icon.setAttribute('width', '20');
  icon.setAttribute('height', '20');
  icon.setAttribute('viewBox', '0 0 24 24');
  icon.setAttribute('fill', 'none');
  icon.style.cssText = 'flex:none;';
  icon.innerHTML = '<path d="M12 2l8 3.2V11c0 4.7-3.3 8.3-8 11-4.7-2.7-8-6.3-8-11V5.2L12 2z" stroke="#d93025" stroke-width="1.6" fill="#fce8e6"/><path d="M9 11.6l2.1 2.1 4.1-4.3" stroke="#d93025" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>';

  const title = document.createElement('div');
  title.style.cssText = 'font-weight:500;font-size:16px;color:#202124;letter-spacing:.1px;';
  title.textContent = 'Sensitive data detected';

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.textContent = '×';
  closeBtn.title = "Cancel — keep your prompt, don't send";
  closeBtn.setAttribute('aria-label', 'Close dialog');
  closeBtn.style.cssText = [
    'flex:none','width:32px','height:32px','border:none','border-radius:50%',
    'background:transparent','color:#5f6368','font:400 20px/1 Roboto,"Segoe UI",sans-serif',
    'cursor:pointer',
  ].join(';');
  closeBtn.addEventListener('mouseenter', () => { closeBtn.style.background = '#f8f9fa'; });
  closeBtn.addEventListener('mouseleave', () => { closeBtn.style.background = 'transparent'; });

  const body = document.createElement('div');
  body.style.cssText = 'margin:14px 0 0;';

  const chips = document.createElement('div');
  chips.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;';
  (nameList || ['sensitive data']).forEach((n) => {
    const chip = document.createElement('span');
    chip.style.cssText = [
      'font:500 11px/1.4 Roboto,"Segoe UI",system-ui,sans-serif',
      'color:#c5221f','background:#fce8e6',
      'border:1px solid #f2a19c','border-radius:8px',
      'padding:4px 10px',
    ].join(';');
    chip.textContent = n;
    chips.appendChild(chip);
  });
  if (Array.isArray(names) && names.length > 8) {
    const more = document.createElement('span');
    more.style.cssText = 'font:400 11px/1.4 Roboto,"Segoe UI",sans-serif;color:#5f6368;padding:4px 4px;';
    more.textContent = '+' + (names.length - 8) + ' more';
    chips.appendChild(more);
  }

  const msg = document.createElement('div');
  msg.style.cssText = 'color:#5f6368;font-size:13px;margin:12px 0 0;';
  msg.textContent = 'Your prompt was NOT sent and is still in the input box. ' +
    '"Mask & send" replaces the flagged values with placeholders before sending; ' +
    'sending it anyway will expose this data to the AI provider.';

  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:20px;';

  const blockBtn = document.createElement('button');
  blockBtn.type = 'button';
  blockBtn.textContent = "Block (don't send)";
  blockBtn.title = 'Keep your prompt; nothing is sent';
  blockBtn.style.cssText = [
    'font:500 14px/1 Roboto,"Segoe UI",system-ui,sans-serif','padding:0 22px','height:36px',
    'border-radius:4px','cursor:pointer','color:#ffffff','background:#d93025',
    'border:none','box-shadow:0 1px 2px 0 rgba(60,64,67,.3), 0 1px 3px 1px rgba(60,64,67,.15)',
  ].join(';');

  const maskBtn = document.createElement('button');
  maskBtn.type = 'button';
  maskBtn.textContent = 'Mask & send';
  maskBtn.title = 'Replace the sensitive values with placeholders, then send';
  maskBtn.style.cssText = [
    'font:500 14px/1 Roboto,"Segoe UI",system-ui,sans-serif','padding:0 22px','height:36px',
    'border-radius:4px','cursor:pointer','color:#1a73e8','background:#ffffff',
    'border:1px solid #dadce0',
  ].join(';');

  const sendBtn = document.createElement('button');
  sendBtn.type = 'button';
  sendBtn.textContent = 'Send it anyway';
  sendBtn.title = 'Send despite the warning; data leaves this machine';
  sendBtn.style.cssText = [
    'font:500 14px/1 Roboto,"Segoe UI",system-ui,sans-serif','padding:0 10px','height:36px',
    'border-radius:4px','cursor:pointer','color:#b06000','background:transparent',
    'border:none',
  ].join(';');

  const onEsc = (ev) => {
    if (ev.key === 'Escape') {
      ev.preventDefault();
      ev.stopPropagation();
      close();
    }
  };
  const close = () => {
    decisionOpen = false;
    window.removeEventListener('keydown', onEsc, true);
    card.remove();
  };

  blockBtn.addEventListener('click', close);
  closeBtn.addEventListener('click', close);

  maskBtn.addEventListener('click', () => {
    decisionOpen = false;
    window.removeEventListener('keydown', onEsc, true);
    card.remove();
    // Rewrite the composer with the masked text, then send. A short delay lets
    // the input event propagate so the chat UI reads the new text.
    if (safeText) {
      setText(el, safeText);
      setTimeout(() => reTriggerSend(el, originalEvent), 60);
    } else {
      reTriggerSend(el, originalEvent);
    }
  });

  sendBtn.addEventListener('click', () => {
    decisionOpen = false;
    window.removeEventListener('keydown', onEsc, true);
    card.remove();
    reTriggerSend(el, originalEvent);
  });

  window.addEventListener('keydown', onEsc, true);

  titleWrap.appendChild(icon);
  titleWrap.appendChild(title);
  header.appendChild(titleWrap);
  header.appendChild(closeBtn);
  body.appendChild(chips);
  body.appendChild(msg);
  actions.appendChild(blockBtn);
  actions.appendChild(maskBtn);
  actions.appendChild(sendBtn);
  card.appendChild(header);
  card.appendChild(body);
  card.appendChild(actions);

  document.body.appendChild(card);
  blockBtn.focus();
}

function intercept(el, e) {
  const text = readText(el);
  if (!text.trim()) return;

  e.preventDefault();
  e.stopImmediatePropagation();

  scan(text).then((result) => {
    if (shouldBlock(result.verdict)) {
      if (decisionOpen) return;
      const names = result.blocked_names || (result.detections || []).map((d) => d.name);
      showDecisionDialog(names, el, e, result.safe_text);
      return; // keep the text, nothing was sent yet
    }
    reTriggerSend(el, e);
  });
}

function attach() {
  if (window.__promptshieldAttached) return;
  window.__promptshieldAttached = true;

  // Enter-to-send (capture phase so we run before the site's handler)
  document.addEventListener('keydown', (e) => {
    if (simulating || decisionOpen) return;
    if (e.key !== 'Enter' || e.shiftKey || e.ctrlKey || e.metaKey || e.altKey) return;
    const el = findInput();
    if (el) intercept(el, e);
  }, true);

  // Send-button clicks
  document.addEventListener('click', (e) => {
    if (simulating || decisionOpen) return;
    const btn = e.target && e.target.closest && e.target.closest('button');
    if (!btn) return;
    const label = (btn.getAttribute('aria-label') || btn.title || btn.getAttribute('data-testid') || '');
    if (!/send/i.test(label)) return;
    const el = findInput();
    if (el && readText(el).trim()) intercept(el, e);
  }, true);

  // Status pill (Material-style floating chip)
  const pill = document.createElement('div');
  pill.id = 'promptshield-pill';
  pill.style.cssText = [
    'position:fixed', 'bottom:16px', 'right:16px', 'z-index:2147483646',
    'padding:10px 16px', 'border-radius:8px',
    'font:500 12px/1.4 Roboto,"Segoe UI",system-ui,sans-serif',
    'background:#ffffff', 'color:#202124',
    'border:1px solid #dadce0',
    'box-shadow:0 1px 2px 0 rgba(60,64,67,.3), 0 1px 3px 1px rgba(60,64,67,.15)',
  ].join(';');
  pill.textContent = 'promptshield: checking…';
  document.body.appendChild(pill);

  const update = () => {
    fetch(GATEWAY + '/healthz', { method: 'GET' }).then((res) => {
      gatewayOnline = res.ok;
      pill.style.color = '#137333';
      pill.style.borderColor = '#ceead6';
      pill.style.background = '#e6f4ea';
      pill.textContent = res.ok
        ? 'promptshield: protected'
        : 'promptshield: local scanning active';
    }).catch(() => {
      gatewayOnline = false;
      pill.style.color = '#137333';
      pill.style.borderColor = '#ceead6';
      pill.style.background = '#e6f4ea';
      pill.textContent = 'promptshield: local scanning active';
    });
  };
  update();
  setInterval(update, 10000);
}

attach();