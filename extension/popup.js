// promptshield popup — shows gateway status and lets you test text manually.

const GATEWAY = 'http://127.0.0.1:8080';
const dot = document.getElementById('dot');
const statusText = document.getElementById('statusText');
const verdict = document.getElementById('verdict');

function setStatus(ok) {
  dot.classList.toggle('ok', ok);
  statusText.textContent = ok ? 'gateway online' : 'gateway offline';
}

fetch(GATEWAY + '/healthz')
  .then((r) => setStatus(r.ok))
  .catch(() => setStatus(false));

function showVerdict(data) {
  verdict.className = '';
  verdict.innerHTML = '';

  const title = document.createElement('div');
  title.className = 'title';

  if (data.verdict === 'pass') {
    title.textContent = 'Safe - nothing sensitive detected';
    verdict.className = 'pass';
  } else {
    const crit = (data.detections || []).filter((d) => d.severity === 'critical').length;
    const names = (data.blocked_names && data.blocked_names.length)
      ? data.blocked_names
      : (data.detections || []).map((d) => d.name);

    if (data.verdict === 'block') {
      title.textContent = crit + ' critical finding' + (crit === 1 ? '' : 's') + ' - blocked';
      verdict.className = 'block';
    } else if (data.verdict === 'redact') {
      title.textContent = 'Sensitive data - would be masked';
      verdict.className = 'redact';
    } else {
      title.textContent = (names.length || 'sensitive') + ' finding(s) - logged';
      verdict.className = 'log';
    }

    if (names && names.length) {
      const wrap = document.createElement('div');
      wrap.className = 'names';
      names.forEach((n) => {
        const chip = document.createElement('span');
        chip.textContent = n;
        wrap.appendChild(chip);
      });
      verdict.appendChild(wrap);
    }
  }

  verdict.appendChild(title);
}

// Show the masked version of the text — what "Mask & send" would send.
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

document.getElementById('scan').addEventListener('click', async () => {
  const text = document.getElementById('text').value.trim();
  if (!text) {
    maskedBox.classList.remove('show');
    return;
  }
  verdict.className = '';
  verdict.innerHTML = '<div class="title" style="color:var(--muted)">scanning...</div>';
  maskedBox.classList.remove('show');
  try {
    const res = await fetch(GATEWAY + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) throw new Error('bad status ' + res.status);
    const data = await res.json();
    showVerdict(data);
    showMasked(data.safe_text);
  } catch (_e) {
    setStatus(false);
    verdict.className = 'block';
    verdict.innerHTML = '<div class="title">Cannot reach gateway</div>';
  }
});