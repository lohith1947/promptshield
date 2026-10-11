// promptshield stats — counters for what the extension did on chat sites.
// Shared by content.js (writes) and popup.js (reads).
//
// Only counts are stored. No prompt text, no detection names, no secret values
// ever reach chrome.storage — just four integers and the time counting began.
//
// Counting rule: a prompt is counted ONLY when the scanner flagged it and the
// user then chose an action. Clean prompts that pass straight through are not
// counted at all, so the dashboard reflects real detections and not overall
// browsing volume. This keeps the invariant:
//
//     detected == blocked + masked + anyway
//
// SCHEMA is bumped whenever the field set or meaning changes. Stored data from
// an older schema is discarded rather than migrated, because the old "sent"
// counter mixed clean passthroughs with "send it anyway" and its value is
// meaningless under the new semantics.

var PromptShieldStats = (function () {
  var KEY = 'ps-stats';
  var SCHEMA = 2;
  var FIELDS = ['detected', 'blocked', 'masked', 'anyway'];

  // In-memory mirror so a failed storage write (or an unavailable storage API)
  // degrades to "counts reset on reload" instead of throwing.
  var cache = null;

  function normalize(raw) {
    var out = { since: 0 };
    FIELDS.forEach(function (f) {
      var n = raw && Number(raw[f]);
      out[f] = isFinite(n) && n > 0 ? Math.floor(n) : 0;
    });
    out.since = raw && Number(raw.since) > 0 ? Number(raw.since) : 0;
    return out;
  }

  function api() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return chrome.storage.local;
      }
    } catch (_e) { /* no storage API */ }
    return null;
  }

  function read() {
    if (cache) return Promise.resolve(cache);
    var store = api();
    if (!store) return Promise.resolve(normalize(null));
    return new Promise(function (resolve) {
      try {
        store.get(KEY, function (items) {
          if (chrome.runtime.lastError) return resolve(normalize(null));
          var raw = items && items[KEY];
          // Drop data written by an older schema rather than showing counts
          // whose meaning no longer matches the UI.
          if (!raw || raw.v !== SCHEMA) return resolve(normalize(null));
          cache = normalize(raw);
          resolve(cache);
        });
      } catch (_e) {
        resolve(normalize(null));
      }
    });
  }

  // Bump one or more counters by 1 each. Never rejects.
  function bump(field) {
    var fields = Array.isArray(field) ? field : [field];
    return read().then(function (cur) {
      var next = {
        v: SCHEMA,
        detected: cur.detected,
        blocked: cur.blocked,
        masked: cur.masked,
        anyway: cur.anyway,
        since: cur.since || Date.now(),
      };
      fields.forEach(function (f) {
        if (FIELDS.indexOf(f) !== -1) next[f] += 1;
      });
      cache = next;
      var store = api();
      if (!store) return next;
      return new Promise(function (resolve) {
        try {
          var obj = {};
          obj[KEY] = next;
          store.set(obj, function () { resolve(next); });
        } catch (_e) {
          resolve(next);
        }
      });
    }).catch(function () { /* never let telemetry break a send */ });
  }

  function reset() {
    cache = normalize(null);
    cache.v = SCHEMA;
    cache.since = Date.now();
    var store = api();
    if (!store) return Promise.resolve(cache);
    return new Promise(function (resolve) {
      try {
        var obj = {};
        obj[KEY] = cache;
        store.set(obj, function () { resolve(cache); });
      } catch (_e) {
        resolve(cache);
      }
    });
  }

  return { read: read, bump: bump, reset: reset, FIELDS: FIELDS };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = PromptShieldStats;