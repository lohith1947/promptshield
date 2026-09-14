// promptshield popup — gateway + scan status, manual scanner, light/dark theme.

const GATEWAY = 'http://127.0.0.1:8080';
const dot = document.getElementById('dot');
const statusText = document.getElementById('statusText');
const verdict = document.getElementById('verdict');

// ---- theme (auto by default, remembered in this page's localStorage) ----
const mq = window.matchMedia('(prefers-color-scheme: dark)');
const btnLight = document.getElementById('themeLight');
const btnAuto = document.getElementById('themeAuto');
const btnDark = document.getElementById('themeDark');

function resolveTheme(chosen) {
  if (chosen !== 'light' && chosen !== 'dark') return mq.matches ? 'dark' : 'light';
  return chosen;
}

function applyTheme(chosen) {
  document.documentElement.setAttribute('data-theme', resolveTheme(chosen));
  btnLight.classList.toggle('on', chosen === 'light');
  btnAuto.classList.toggle('on', chosen === 'auto');
  btnDark.classList.toggle('on', chosen === 'dark');
}

let chosenTheme = 'auto';
try {
  const saved = localStorage.getItem('ps-theme');
  if (saved === 'light' || saved === 'dark') chosenTheme = saved;
} catch (_e) {}
applyTheme(chosenTheme);

function selectTheme(t) {
  chosenTheme = t;
  applyTheme(t);
  try { localStorage.setItem('ps-theme', t); } catch (_e) {}
}
btnLight.addEventListener('click', () => selectTheme('light'));
btnAuto.addEventListener('click', () => selectTheme('auto'));
btnDark.addEventListener('click', () => selectTheme('dark'));
mq.addEventListener('change', () => applyTheme(chosenTheme));

// ---- status ----
function setStatus(ok) {
  dot.classList.remove('ok', 'bad');
  dot.classList.add(ok ? 'ok' : 'bad');
  statusText.textContent = ok ? 'gateway online' : 'local scanner';
}

fetch(GATEWAY + '/healthz')
  .then((r) => setStatus(r.ok))
  .catch(() => setStatus(false));

document.getElementById('privacyLink').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: 'https://github.com/lohith1947/promptshield/blob/main/PRIVACY.md' });
});

// ---- verdict cards ----
const ICONS = {
  pass: '<path d="M5 12.5l4.6 4.6L19 7.4" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  block: '<path d="M12 8v5M12 16.4v.2" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round"/><circle cx="12" cy="12" r="8.4" stroke="currentColor" stroke-width="1.9" fill="none"/>',
  redact: '<path d="M12 4l7 2.8V11c0 4.1-2.9 7.3-7 9-4.1-1.7-7-4.9-7-9V6.8L12 4z" stroke="currentColor" stroke-width="1.9" fill="none" stroke-linejoin="round"/>',
  log: '<path d="M4 6.5h16M4 12h16M4 17.5h10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
};

function showVerdict(data) {
  verdict.className = '';
  verdict.innerHTML = '';

  const state = data.verdict === 'redact' ? 'redact' : data.verdict;
  verdict.classList.add('show', 'state-' + state);

  const icon = document.createElement('div');
  icon.className = 'vicon';
  icon.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24">' + (ICONS[state] || ICONS.log) + '</svg>';

  const title = document.createElement('div');
  title.className = 'vtitle';
  const sub = document.createElement('div');
  sub.className = 'vsub';
  const names = (data.blocked_names && data.blocked_names.length)
    ? data.blocked_names
    : (data.detections || []).map((d) => d.name);
  const crit = (data.detections || []).filter((d) => d.severity === 'critical').length;

  if (state === 'pass') {
    title.textContent = 'No sensitive data detected';
    sub.textContent = 'Looks safe — a prompt like this would go through.';
  } else if (state === 'block') {
    title.textContent = 'Critical data found — blocked';
    sub.textContent = crit + ' critical finding' + (crit === 1 ? '' : 's') +
      '. Nothing was sent; ' + (names.length || 'the flagged data') + ' stays in your box.';
  } else if (state === 'redact') {
    title.textContent = 'Would be masked before sending';
    sub.textContent = 'These become ' + (names.length || 'sensitive') + ' placeholders first.';
  } else {
    title.textContent = 'Sensitive data found — logged';
    sub.textContent = 'Logged to your local audit trail.';
  }

  verdict.appendChild(icon);
  verdict.appendChild(title);
  verdict.appendChild(sub);

  if (names && names.length) {
    const wrap = document.createElement('div');
    wrap.className = 'vnames';
    names.forEach((n) => {
      const chip = document.createElement('span');
      chip.textContent = n;
      wrap.appendChild(chip);
    });
    verdict.appendChild(wrap);
  }
}

// ---- masked version ----
const maskedBox = document.getElementById('masked');
const maskedText = document.getElementById('maskedText');
const copyMasked = document.getElementById('copyMasked');

function showMasked(safeText) {
  if (!safeText) {
    maskedBox.classList.remove('show');
    return;
  }
  maskedText.value = safeText;
  maskedBox.classList.add('show');
}

copyMasked.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(maskedText.value);
    copyMasked.textContent = 'Copied';
    setTimeout(() => (copyMasked.textContent = 'Copy'), 1200);
  } catch (_e) {
    maskedText.select();
    document.execCommand('copy');
  }
});

// ---- scan ----
document.getElementById('scan').addEventListener('click', async () => {
  const text = document.getElementById('text').value.trim();
  if (!text) {
    maskedBox.classList.remove('show');
    return;
  }
  verdict.className = '';
  verdict.classList.remove('show');
  maskedBox.classList.remove('show');

  let data;
  // Prefer the local gateway for consistency with the dashboard/audit log;
  // fall back to the in-page scanner when it is unreachable or missing.
  try {
    const res = await fetch(GATEWAY + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) throw new Error('bad status ' + res.status);
    data = await res.json();
  } catch (_e) {
    data = PromptShieldScanner.scanText(text);
    setStatus(false);
  }
  showVerdict(data);
  showMasked(data.safe_text);
});