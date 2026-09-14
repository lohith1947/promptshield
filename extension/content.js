// promptshield content script
// Intercepts prompts typed into AI chat sites and scans them against the
// local promptshield gateway BEFORE they are sent. If the gateway says the
// text contains sensitive data, the send is paused and a dialog lets you
// either block it or send it anyway. Nothing is transmitted until you choose.

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

// Fail-open: if the local gateway is unreachable we let the message through,
// so the chat site always keeps working. The popup shows gateway status.
async function scan(text) {
  try {
    const res = await fetch(GATEWAY + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (_e) {
    return null;
  }
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
    'button.promptshield-psbtn:hover { filter:brightness(1.12); }',
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
    'background:rgba(22,29,40,.98)', 'border:1px solid rgba(255,255,255,.1)',
    'border-radius:12px', 'box-shadow:0 18px 50px rgba(0,0,0,.5)',
    'padding:16px 18px 16px 22px', 'font:14px/1.5 system-ui',
    'animation:promptshield-drop 260ms cubic-bezier(.2,.7,.3,1) both',
  ].join(';');

  const accent = document.createElement('div');
  accent.style.cssText = 'position:absolute;left:0;top:14px;bottom:14px;width:3px;border-radius:2px;background:linear-gradient(180deg,#ef5350,#ff7043);';
  card.appendChild(accent);

  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:12px;';

  const titleWrap = document.createElement('div');
  titleWrap.style.cssText = 'display:flex;align-items:center;gap:10px;min-width:0;';

  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  icon.setAttribute('width', '18');
  icon.setAttribute('height', '18');
  icon.setAttribute('viewBox', '0 0 24 24');
  icon.setAttribute('fill', 'rgba(239,83,80,.14)');
  icon.style.cssText = 'flex:none;';
  icon.innerHTML = '<path d="M12 2l8 3.2V11c0 4.7-3.3 8.3-8 11-4.7-2.7-8-6.3-8-11V5.2L12 2z" stroke="#ef5350" stroke-width="1.8"/><path d="M9 11.6l2.1 2.1 4.1-4.3" stroke="#ef5350" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/>';

  const title = document.createElement('div');
  title.style.cssText = 'font-weight:700;font-size:14px;color:#f0f5fa;letter-spacing:.1px;';
  title.textContent = 'Sensitive data detected';

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.textContent = '×';
  closeBtn.title = "Cancel — keep your prompt, don't send";
  closeBtn.setAttribute('aria-label', 'Close dialog');
  closeBtn.style.cssText = [
    'flex:none','width:26px','height:26px','border:none','border-radius:6px',
    'background:transparent','color:#8aa0b8','font:600 18px/1 system-ui',
    'cursor:pointer',
  ].join(';');
  closeBtn.addEventListener('mouseenter', () => { closeBtn.style.color = '#fff'; });
  closeBtn.addEventListener('mouseleave', () => { closeBtn.style.color = '#8aa0b8'; });

  const body = document.createElement('div');
  body.style.cssText = 'margin:12px 0 0;';

  const chips = document.createElement('div');
  chips.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;';
  (nameList || ['sensitive data']).forEach((n) => {
    const chip = document.createElement('span');
    chip.style.cssText = [
      'font:600 11px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace',
      'color:#ff8a80','background:rgba(231,76,60,.14)',
      'border:1px solid rgba(231,76,60,.35)','border-radius:999px',
      'padding:3px 9px',
    ].join(';');
    chip.textContent = n;
    chips.appendChild(chip);
  });
  if (Array.isArray(names) && names.length > 8) {
    const more = document.createElement('span');
    more.style.cssText = 'font:600 11px/1.4 system-ui;color:#8aa0b8;padding:3px 4px;';
    more.textContent = '+' + (names.length - 8) + ' more';
    chips.appendChild(more);
  }

  const msg = document.createElement('div');
  msg.style.cssText = 'color:#94a7bd;font-size:12.5px;margin:10px 0 0;';
  msg.textContent = 'Your prompt was NOT sent and is still in the input box. ' +
    '"Mask & send" replaces the flagged values with placeholders before sending; ' +
    'sending it anyway will expose this data to the AI provider.';

  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex;align-items:center;justify-content:flex-end;gap:10px;margin-top:14px;padding-top:12px;border-top:1px solid rgba(255,255,255,.07);';

  const blockBtn = document.createElement('button');
  blockBtn.type = 'button';
  blockBtn.textContent = "Block (don't send)";
  blockBtn.title = 'Keep your prompt; nothing is sent';
  blockBtn.style.cssText = [
    'font:600 13px/1 system-ui','padding:10px 16px','border-radius:8px',
    'cursor:pointer','color:#eef3f9','background:#333f52',
    'border:1px solid rgba(255,255,255,.12)',
  ].join(';');

  const maskBtn = document.createElement('button');
  maskBtn.type = 'button';
  maskBtn.textContent = 'Mask & send';
  maskBtn.title = 'Replace the sensitive values with placeholders, then send';
  maskBtn.style.cssText = [
    'font:600 13px/1 system-ui','padding:10px 16px','border-radius:8px',
    'cursor:pointer','color:#a5d6a7','background:rgba(124,179,66,.14)',
    'border:1px solid rgba(124,179,66,.5)',
  ].join(';');

  const sendBtn = document.createElement('button');
  sendBtn.type = 'button';
  sendBtn.textContent = 'Send it anyway';
  sendBtn.title = 'Send despite the warning; data leaves this machine';
  sendBtn.style.cssText = [
    'font:600 13px/1 system-ui','padding:10px 16px','border-radius:8px',
    'cursor:pointer','color:#ffc46b','background:rgba(245,166,35,.14)',
    'border:1px solid rgba(245,166,35,.55)',
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
    if (!result) {
      reTriggerSend(el, e); // gateway offline -> allow
      return;
    }
    if (shouldBlock(result.verdict)) {
      if (decisionOpen) return; // dialog already asking the user
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

  // Status pill
  const pill = document.createElement('div');
  pill.id = 'promptshield-pill';
  pill.style.cssText = [
    'position:fixed', 'bottom:14px', 'right:14px', 'z-index:2147483646',
    'padding:6px 12px', 'border-radius:999px', 'font:600 12px system-ui',
    'background:rgba(0,0,0,.75)', 'color:#7CB342',
  ].join(';');
  pill.textContent = 'promptshield: checking...';
  document.body.appendChild(pill);

  const update = () => {
    fetch(GATEWAY + '/healthz', { method: 'GET' }).then((res) => {
      pill.style.color = res.ok ? '#7CB342' : '#e74c3c';
      pill.textContent = res.ok ? 'promptshield: protected' : 'promptshield: gateway offline (fail-open)';
    }).catch(() => {
      pill.style.color = '#e74c3c';
      pill.textContent = 'promptshield: gateway offline (fail-open)';
    });
  };
  update();
  setInterval(update, 10000);
}

attach();