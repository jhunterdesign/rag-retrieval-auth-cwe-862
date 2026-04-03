/* ============================================================================
 HunterCloudSec — Big's BBQ Honeypot
 security-logger.js
 Purpose: Lightweight client-side telemetry + detection signals for a demo site.
 Notes:
  - Logs to console by default (safe for static hosting).
  - Optional: POST events to an endpoint if you add one later.
============================================================================ */

/* -------------------------------
   Canonical Persistent Session ID
--------------------------------*/

if (!localStorage.getItem("HCS_SESSION_ID")) {
  localStorage.setItem(
    "HCS_SESSION_ID",
    Math.random().toString(36).substring(2, 10)
  );
}

window.HCS_SESSION_ID = localStorage.getItem("HCS_SESSION_ID");


/* ---------------------------
   INPUT NORMALIZATION + SCORING
---------------------------- */

// Decode URL encoding safely
function normalizeInput(input) {
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

// Heuristic anomaly scoring
function anomalyScore(input) {
  let score = 0;

  if (input.length > 120) score += 1;              // unusually long
  if (/[<>{};]/.test(input)) score += 1;          // suspicious symbols
  if (/\b(system|admin|ignore|override)\b/i.test(input)) score += 1; // prompt-style words

  return score;
}

  /* ---------------------------
     Config
  ---------------------------- */
  const CFG = {
    app: "bigs-bbq-honeypot",
    env: "dev", // change to "prod" for your export build
    version: "0.1.0",

    // If you later add an API endpoint, set this to something like "/api/log"
    // Keep null for static-only mode.
    endpoint: null,

    // Basic rate limiting (client-side only)
    maxEventsPerMinute: 120,

    // Heuristics thresholds
    longInputLen: 220,
    suspiciousScoreThreshold: 2, // >=2 => flag
  };

  /* ---------------------------
     Session + helpers
  ---------------------------- */
  

  const nowIso = () => new Date().toISOString();

  const safeString = (v) => {
    if (v == null) return "";
    return String(v);
  };

  // Lightweight hash (non-crypto) to avoid storing raw PII; good enough for demo signals
  const hash32 = (str) => {
    let h = 2166136261;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    // unsigned
    return (h >>> 0).toString(16);
  };

  const redactValue = (name, value) => {
    const n = safeString(name).toLowerCase();
    const v = safeString(value);

    // Keep minimal info: length + hash; never store raw value by default
    // For non-sensitive fields you can allow raw by whitelisting.
    const sensitiveNameHints = ["ssn", "social", "dob", "birth", "phone", "email", "address", "card", "cc", "bank"];
    const looksSensitive = sensitiveNameHints.some((k) => n.includes(k));

    // Heuristic: emails/phones/cc-ish
    const looksEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(v);
    const looksPhone = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(v);
    const looksSSN = /\b\d{3}-\d{2}-\d{4}\b/.test(v);
    const looksCC = /\b(?:\d[ -]*?){13,16}\b/.test(v);

    const isSensitive = looksSensitive || looksEmail || looksPhone || looksSSN || looksCC;

    if (isSensitive) {
      return {
        redacted: true,
        len: v.length,
        hash: hash32(v),
      };
    }

    // For non-sensitive, still avoid raw; keep len + hash.
    return {
      redacted: false,
      len: v.length,
      hash: hash32(v),
    };
  };

  /* ---------------------------
     Detection rules
  ---------------------------- */
  const RULES = [
    // XSS-ish
    { id: "xss_script_tag", sev: "high", re: /<\s*script\b/i, note: "Possible XSS: <script>" },
    { id: "xss_event_handler", sev: "med", re: /\bon\w+\s*=\s*['"]/i, note: "Possible XSS: inline event handler" },
    { id: "xss_js_proto", sev: "med", re: /\bjavascript\s*:/i, note: "Possible XSS: javascript: URL" },

    // SQLi-ish
    { id: "sqli_union", sev: "high", re: /\bunion\b\s+\bselect\b/i, note: "Possible SQLi: UNION SELECT" },
    { id: "sqli_boolean", sev: "med", re: /(\bor\b|\band\b)\s+1\s*=\s*1/i, note: "Possible SQLi: boolean tautology" },
    { id: "sqli_comment", sev: "med", re: /(--|#|\/\*)\s*\w*/i, note: "Possible SQLi: comment tokens" },

    // Command injection-ish
    { id: "cmdi_shell_ops", sev: "high", re: /(;|\|\||&&)\s*(cat|whoami|id|curl|wget|bash|sh|powershell)\b/i, note: "Possible cmd injection" },

    // Path traversal
    { id: "path_traversal", sev: "high", re: /(\.\.\/|\.\.\\)+/i, note: "Possible path traversal" },

    // SSRF-ish
    { id: "ssrf_localhost", sev: "high", re: /\b(127\.0\.0\.1|localhost|169\.254\.169\.254)\b/i, note: "Possible SSRF target" },

    // Generic probing
    { id: "probe_admin", sev: "low", re: /\b(admin|wp-admin|phpmyadmin|\/etc\/passwd)\b/i, note: "Common probe keywords" },
  ];

  const analyzeText = (text) => {
    const t = safeString(text);
    if (!t) return { score: 0, hits: [] };

    const hits = [];
    let score = 0;

    // Rule matches
    for (const r of RULES) {
      if (r.re.test(t)) {
        hits.push({ rule_id: r.id, severity: r.sev, note: r.note });
        score += (r.sev === "high" ? 3 : r.sev === "med" ? 2 : 1);
      }
    }

    // Heuristics
    if (t.length >= CFG.longInputLen) {
      hits.push({ rule_id: "heur_long_input", severity: "low", note: `Unusually long input (${t.length})` });
      score += 1;
    }

    // Excessive special chars (often payload-y)
    const specialCount = (t.match(/[<>{}\[\]$'"`;|\\]/g) || []).length;
    if (specialCount >= 12) {
      hits.push({ rule_id: "heur_special_char_burst", severity: "low", note: "High special-character density" });
      score += 1;
    }

    return { score, hits };
  };

  const uaSignals = () => {
    const ua = navigator.userAgent || "";
    const low = ua.toLowerCase();

    const flags = [];
    if (!ua) flags.push("ua_missing");
    if (low.includes("headless")) flags.push("ua_headless");
    if (low.includes("selenium") || low.includes("webdriver")) flags.push("ua_automation");
    if (low.includes("python-requests") || low.includes("curl") || low.includes("wget")) flags.push("ua_scripted");
    if (navigator.webdriver) flags.push("webdriver_true");

    return { ua, flags };
  };

  /* ---------------------------
     Rate limiting (client-side)
  ---------------------------- */
  const rate = (() => {
    const bucket = { ts: Date.now(), count: 0 };
    return {
      allow() {
        const now = Date.now();
        if (now - bucket.ts > 60_000) {
          bucket.ts = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        return bucket.count <= CFG.maxEventsPerMinute;
      },
      count() {
        return bucket.count;
      }
    };
  })();

  /* ---------------------------
     Event builder + sink
  ---------------------------- */
  const buildBaseEvent = (type) => {
    const { ua, flags } = uaSignals();
    return {
      schema: "hcs.web_event.v1",
      app: CFG.app,
      env: CFG.env,
      version: CFG.version,

      event_type: type,
      ts: nowIso(),
      session_id: window.HCS_SESSION_ID,


      page: {
        url: location.href,
        path: location.pathname,
        referrer: document.referrer || null,
      },

      client: {
        ua,
        ua_flags: flags,
        language: navigator.language || null,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
      },
    };
  };

  const sendEvent = async (evt) => {
    if (!rate.allow()) return;

    // Always console-log for local dev/portfolio evidence
    // Keep it structured so you can screenshot and later map to Cloud Logging fields.
    console.log("%c[HCS EVENT]", "color:#7b1212;font-weight:700", evt);

    if (!CFG.endpoint) return;

    try {
      await fetch(CFG.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(evt),
        keepalive: true,
      });
    } catch (e) {
      // Silent fail (don’t break UX)
      console.warn("[HCS] Telemetry send failed:", e);
    }
  };

  /* ---------------------------
     Instrumentation
  ---------------------------- */
  const instrumentQueryParams = () => {
    const params = new URLSearchParams(location.search);
    if (!params || [...params.keys()].length === 0) return;

    const qp = {};
    let maxScore = 0;
    let allHits = [];

    for (const [k, v] of params.entries()) {
      const analysis = analyzeText(v);
      qp[k] = { ...redactValue(k, v), score: analysis.score };
      maxScore = Math.max(maxScore, analysis.score);
      allHits = allHits.concat(analysis.hits.map((h) => ({ ...h, field: `query.${k}` })));
    }

    const flagged = maxScore >= CFG.suspiciousScoreThreshold;

    sendEvent({
      ...buildBaseEvent("query_params"),
      query: qp,
      detection: {
        flagged,
        score: maxScore,
        hits: allHits,
      }
    });
  };

  const instrumentForms = () => {
    document.addEventListener("submit", (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;

      const fd = new FormData(form);
      const fields = {};
      let maxScore = 0;
      let hits = [];

      for (const [name, val] of fd.entries()) {
        const v = safeString(val);
        const analysis = analyzeText(v);
        fields[name] = { ...redactValue(name, v), score: analysis.score };
        maxScore = Math.max(maxScore, analysis.score);
        hits = hits.concat(analysis.hits.map((h) => ({ ...h, field: `form.${name}` })));
      }

      const flagged = maxScore >= CFG.suspiciousScoreThreshold;

      sendEvent({
        ...buildBaseEvent("form_submit"),
        form: {
          id: form.id || null,
          name: form.getAttribute("name") || null,
          action: form.getAttribute("action") || null,
          method: (form.getAttribute("method") || "GET").toUpperCase(),
          fields,
        },
        detection: { flagged, score: maxScore, hits },
      });

      // IMPORTANT: You can keep real submit behavior.
      // For your demo "mock apply", you probably preventDefault elsewhere already.
    }, true);
  };

  const instrumentInputs = () => {
  const handler = (e) => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) return;

    const name = el.name || el.id || "field";
    const raw = safeString(el.value);
    if (!raw) return;

    const normalized = normalizeInput(raw);
    const analysis = analyzeText(normalized);

    const flagged = analysis.score >= CFG.suspiciousScoreThreshold;

    // Only log suspicious or very long inputs
    if (!flagged && raw.length < CFG.longInputLen) return;

    sendEvent({
      ...buildBaseEvent("input_blur"),
      input: {
        field: name,
        value: {
          redacted: false,
          len: raw.length,
          hash: hash32(raw)
        },
        score: analysis.score
      },
      detection: {
        flagged,
        score: analysis.score,
        hits: analysis.hits.map((h) => ({ ...h, field: `input.${name}` })),
      }
    });
  };

  document.addEventListener("change", handler, true);
  document.addEventListener("blur", handler, true);
};


  const instrumentClicks = () => {
    // Lightweight: capture clicks to suspicious paths or repeated rapid clicking (bot-ish)
    let lastClickTs = 0;
    let rapidClicks = 0;

    document.addEventListener("click", (e) => {
      const a = e.target && (e.target.closest ? e.target.closest("a") : null);
      const now = Date.now();

      if (now - lastClickTs < 250) rapidClicks += 1;
      else rapidClicks = 0;

      lastClickTs = now;

      if (!a) {
        if (rapidClicks >= 8) {
          sendEvent({
            ...buildBaseEvent("behavior"),
            behavior: { type: "rapid_clicking", count: rapidClicks },
            detection: { flagged: true, score: 2, hits: [{ rule_id: "heur_rapid_clicks", severity: "low", note: "Rapid clicking burst" }] }
          });
        }
        return;
      }

      const href = a.getAttribute("href") || "";
      const analysis = analyzeText(href);
      const flagged = analysis.score >= CFG.suspiciousScoreThreshold;

      if (flagged) {
        sendEvent({
          ...buildBaseEvent("link_click"),
          link: { href },
          detection: { flagged, score: analysis.score, hits: analysis.hits.map((h) => ({ ...h, field: "link.href" })) }
        });
      }
    }, true);
  };

  /* ---------------------------
     Public hook (optional)
     Use this to log from your chatbot or custom flows.
  ---------------------------- */
  window.HCS = window.HCS || {};
  window.HCS.log = (eventType, payload = {}, detectionText = "") => {
    const analysis = analyzeText(detectionText);
    const flagged = analysis.score >= CFG.suspiciousScoreThreshold;

    sendEvent({
      ...buildBaseEvent(eventType),
      payload,
      detection: {
        flagged,
        score: analysis.score,
        hits: analysis.hits.map((h) => ({ ...h, field: "custom" })),
      }
    });
  };

  /* ---------------------------
     Boot
  ---------------------------- */
  const boot = () => {
    instrumentQueryParams();
    instrumentForms();
    instrumentInputs();
    instrumentClicks();

    sendEvent({
      ...buildBaseEvent("page_view"),
      detection: { flagged: false, score: 0, hits: [] }
    });
  };

  // Run after DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

