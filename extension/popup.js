// promptshield popup — protection status + lifetime counters, light/dark theme.

const GATEWAY = 'http://127.0.0.1:8080';
const dot = document.getElementById('dot');
const statusText = document.getElementById('statusText');

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

// The store listing points at the published Pages URL, so use the same one here.
// PRIVACY.md is only published from the gh-pages branch; the repo's default
// branch is master and has no PRIVACY.md at its root, so a blob/main link 404s.
const PRIVACY_URL = 'https://lohith1947.github.io/promptshield/PRIVACY.md';

document.getElementById('privacyLink').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: PRIVACY_URL }, () => {
    // Opening a tab can close the popup; if the callback reports an error,
    // fall back to a normal navigation so the link is never dead.
    if (chrome.runtime.lastError) window.open(PRIVACY_URL, '_blank', 'noopener');
  });
});

// ---- stats dashboard ----
// Only prompts the scanner actually flagged are counted, so these four numbers
// describe real detections rather than browsing volume. They reconcile:
//
//   detected == blocked + masked + anyway
//
// "Sent" deliberately means "sent anyway" — a prompt that was flagged and then
// transmitted unmodified. A clean prompt that passed through is never counted,
// because inflating the total with every safe message would bury the one
// number that actually matters.
const CARDS = [
  { id: 'Detected', key: 'detected' },
  { id: 'Blocked', key: 'blocked' },
  { id: 'Masked', key: 'masked' },
  { id: 'Sent', key: 'anyway' },
];

const sinceText = document.getElementById('since');
const hSent = document.getElementById('hSent');
const noteText = document.getElementById('noteText');

function plural(n, one, many) {
  return n + ' ' + (n === 1 ? one : many);
}

function render(s) {
  CARDS.forEach((c) => {
    const n = s[c.key] || 0;
    document.getElementById('n' + c.id).textContent = String(n);
    document.getElementById('c' + c.id).classList.toggle('zero', n === 0);
  });

  hSent.textContent = plural(s.anyway || 0, 'flagged prompt sent', 'flagged prompts sent') + ' anyway';

  if (s.since) {
    const d = new Date(s.since);
    const sameDay = new Date().toDateString() === d.toDateString();
    const when = sameDay
      ? 'today'
      : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    sinceText.textContent = 'Counting since ' + when;
  } else {
    sinceText.textContent = 'No sensitive prompts yet';
  }

  if ((s.anyway || 0) > 0) {
    noteText.textContent = plural(s.anyway, 'prompt was', 'prompts were') +
      ' sent as-is after a warning. Those reached the AI provider with the ' +
      'sensitive values still in them.';
  } else {
    noteText.textContent = 'Only these counts are stored on this device. Your ' +
      'prompt text and the sensitive values themselves are never saved.';
  }
}

PromptShieldStats.read().then(render);

document.getElementById('reset').addEventListener('click', () => {
  PromptShieldStats.reset().then(render);
});