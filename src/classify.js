// Deterministic data-class classifier for outbound payloads.
//
// This is a faithful, dependency-free extraction of the classifier used by the
// ScopeZero engine (src/sensitiveData.js). It exists to answer one question the
// egress monitor needs: given some bytes, what is the highest data class we can
// POSITIVELY establish from them — and if we can't establish anything, is the
// payload nonetheless shaped like a dump (so "looks public" is absence of
// evidence, not evidence of absence)?
//
// It is intentionally a floor, not a ceiling: it never claims content is more
// benign than the bytes prove. Semantic / non-English / model-graded coverage is
// meant to be layered on top via mergeClassification().

const LEVELS = { public: 1, internal: 2, confidential: 4, restricted: 5 };
const LABELS = { 1: "public", 2: "internal", 4: "confidential", 5: "restricted" };

// A gateway must never run regex detectors over unbounded agent-supplied input —
// a multi-megabyte payload would pin a CPU. Scan a bounded prefix; anything larger
// is treated as an "oversized" (non-public) shape and routed to review.
const MAX_CLASSIFY_BYTES = 256 * 1024;

// Topic-keyword finders. A hit positively establishes sensitivity.
const FINDERS = [
  { code: "api_secret", level: 5, pattern: /\b(api[_-]?key|secret|token|private[_-]?key)\b/i },
  { code: "payment_or_bank", level: 5, pattern: /\b(iban|swift|routing number|bank account|credit card)\b/i },
  { code: "payroll", level: 5, pattern: /\b(payroll|salary|compensation|bonus)\b/i },
  { code: "customer_revenue", level: 5, pattern: /\b(customer revenue|revenue by customer|arr|mrr|invoice total)\b/i },
  { code: "confidential_marker", level: 4, pattern: /\b(confidential|restricted|privileged|attorney-client)\b/i },
  { code: "personal_data", level: 4, pattern: /\b(ssn|passport|date of birth|medical record|patient)\b/i },
  { code: "email_address", level: 2, pattern: /[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\.[A-Z]{2,24}/i }
];

// Value-shape detectors: fire on the STRUCTURE of a sensitive value with no topic
// keyword nearby. This is what catches a secret / card / SSN dropped into
// otherwise-benign prose — the keyword finders above are blind to it.
const SECRET_PREFIX_PATTERNS = [
  /\bAKIA[0-9A-Z]{16}\b/,                                    // AWS access key id
  /\bASIA[0-9A-Z]{16}\b/,                                    // AWS temporary access key id
  /\bghp_[A-Za-z0-9]{36}\b/,                                 // GitHub personal access token
  /\bgho_[A-Za-z0-9]{36}\b/,                                 // GitHub OAuth token
  /\bghs_[A-Za-z0-9]{36}\b/,                                 // GitHub server-to-server token
  /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,                        // GitHub fine-grained PAT
  /\bglpat-[A-Za-z0-9_-]{20,}\b/,                            // GitLab personal access token
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,                        // Slack token
  /\bsk-[A-Za-z0-9]{20,}\b/,                                 // OpenAI-style secret key
  /\bsk_live_[A-Za-z0-9]{16,}\b/,                            // Stripe live secret key
  /\brk_live_[A-Za-z0-9]{16,}\b/,                            // Stripe live restricted key
  /\bAIza[0-9A-Za-z_-]{35}\b/,                               // Google API key
  /\bya29\.[0-9A-Za-z_-]{20,}\b/,                            // Google OAuth access token
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, // JWT
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/                // PEM private key
];

const VALUE_FINDERS = [
  { code: "api_secret", level: 5, detect: (t) => SECRET_PREFIX_PATTERNS.some((re) => re.test(t)) || hasHighEntropyToken(t) },
  { code: "payment_or_bank", level: 5, detect: (t) => hasLuhnCardNumber(t) || /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/.test(t) },
  { code: "personal_data", level: 4, detect: (t) => /\b\d{3}-\d{2}-\d{4}\b/.test(t) }
];

// Classify a payload (string or JSON-serialisable object).
// Returns { level, label, findings, egress_shape, established }.
//  - level:       1|2|4|5 highest class positively found (default 1 = public)
//  - established: was the class POSITIVELY established? At level 1, true only when
//                 the payload has no bulk/tabular/encoded/oversized shape.
export function classifyPayload(payload = {}) {
  const rawFull = typeof payload === "string" ? payload : safeStringify(payload);
  const oversized = rawFull.length > MAX_CLASSIFY_BYTES;
  const raw = oversized ? rawFull.slice(0, MAX_CLASSIFY_BYTES) : rawFull;
  // Scan the raw bytes AND anything trivially decoded out of them, so a base64/hex
  // wrapped credential does not classify as opaque "public".
  const decoded = decodeEmbeddedPayloads(raw);
  const text = decoded.length ? `${raw}\n${decoded.join("\n")}` : raw;

  const explicit = String(
    (payload && (payload.classification || payload.data_classification)) || ""
  ).toLowerCase();
  let level = LEVELS[explicit] || 1;
  const findings = [];

  for (const finder of FINDERS) {
    if (finder.pattern.test(text)) { findings.push(finder.code); level = Math.max(level, finder.level); }
  }
  for (const finder of VALUE_FINDERS) {
    if (finder.detect(text)) { findings.push(finder.code); level = Math.max(level, finder.level); }
  }

  const egressShape = oversized ? "oversized_payload" : analyzeEgressShape(payload);
  const established = level >= 2 ? true : egressShape === null;

  return { level, label: LABELS[level] || "public", findings: [...new Set(findings)], egress_shape: egressShape, established };
}

// Merge the deterministic classifier with an optional external classifier
// (embedding / model-graded / commercial DLP). Takes the higher class and unions
// findings; the external verdict can only RAISE establishment, never lower it.
export function mergeClassification(base, external) {
  if (!external || typeof external.level !== "number") return base;
  const level = Math.max(base.level, external.level);
  return {
    level,
    label: LABELS[level] || "public",
    findings: [...new Set([...(base.findings || []), ...(external.findings || [])])],
    egress_shape: base.egress_shape,
    established: base.established === true || external.established === true || external.level >= 2,
    classifier_sources: [...new Set(["deterministic", external.source || "external"])]
  };
}

export function labelForLevel(level) { return LABELS[level] || "public"; }
export function rankForLabel(label) { return LEVELS[String(label).toLowerCase()] || 1; }

// ── value detectors ──────────────────────────────────────────────────────────

function hasLuhnCardNumber(text) {
  const candidates = String(text).match(/\d(?:[ .-]?\d){12,18}/g) || [];
  return candidates.some((c) => {
    const digits = c.replace(/[ .-]/g, "");
    return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
  });
}

function luhnValid(digits) {
  let sum = 0, double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let v = digits.charCodeAt(i) - 48;
    if (v < 0 || v > 9) return false;
    if (double) { v *= 2; if (v > 9) v -= 9; }
    sum += v; double = !double;
  }
  return sum % 10 === 0;
}

// The boundary between a secret TOKEN and an encoded BLOB. A leaked API key /
// session token is bounded (tens of chars); a run past this length is a data dump
// (a base64 attachment, an image, a hash stream), not a single credential.
const SECRET_TOKEN_MAX = 100;
const UUID_RE = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;

// A bounded, near-random token (high Shannon entropy) that is not a UUID — an opaque
// API key / session token with no recognizable prefix. Bounded on length so a benign
// encoded attachment is not misclassified as a proven secret and BLOCKED; long runs
// are routed to the encoded-blob shape below (HELD for review) instead.
function hasHighEntropyToken(text) {
  const tokens = String(text).match(/[A-Za-z0-9+/_-]{40,}/g) || [];
  return tokens.some((t) => t.length < SECRET_TOKEN_MAX && !UUID_RE.test(t) && shannonEntropy(t) >= 4.6);
}

// A long, near-random run — an opaque encoded blob. Class cannot be established from
// it, so it is HELD for review, not blocked as if it were a proven secret.
function hasLongHighEntropyRun(s) {
  const tokens = String(s).match(/[A-Za-z0-9+/_-]{100,}/g) || [];
  return tokens.some((t) => shannonEntropy(t) >= 4.6);
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) { const p = count / value.length; entropy -= p * Math.log2(p); }
  return entropy;
}

// ── outbound-shape analysis ───────────────────────────────────────────────────
// Shape detection, NOT classification: "could this be a data dump?", not "what
// class is it?". Content with a bulk/tabular/encoded shape is treated as
// class-not-established, because a "public" verdict on such bytes is an absence of
// evidence. Thresholds are conservative so short status strings stay autonomous.
function analyzeEgressShape(payload) {
  if (payload == null) return null;

  if (Array.isArray(payload)) {
    if (payload.length >= 5) return "bulk_records";
  } else if (typeof payload === "object") {
    for (const value of Object.values(payload)) {
      if (Array.isArray(value) && value.length >= 5) return "bulk_records";
    }
  }

  const strings = typeof payload === "string" ? [payload] : collectStrings(payload);
  if (strings.some(isTabularDump)) return "tabular_dump";
  if (strings.some(isEncodedBlob) || strings.some(hasLongHighEntropyRun)) return "encoded_blob";
  return null;
}

// 3+ delimited lines with a uniform, >1 field count — columns, not prose.
function isTabularDump(s) {
  const lines = String(s).split(/\r?\n/).filter((l) => l.trim().length);
  if (lines.length < 3) return false;
  for (const delim of [",", "\t", "|"]) {
    const counts = lines.map((l) => l.split(delim).length);
    if (counts[0] > 1 && counts.every((c) => c === counts[0])) return true;
  }
  return false;
}

// A single long base64/hex run — an opaque encoded blob.
function isEncodedBlob(s) {
  const t = String(s).trim();
  return (/^[A-Za-z0-9+/=]{512,}$/.test(t) || /^[0-9a-fA-F]{512,}$/.test(t));
}

function collectStrings(value, acc = [], depth = 0) {
  if (depth > 6 || acc.length > 500) return acc;
  if (typeof value === "string") acc.push(value);
  else if (Array.isArray(value)) for (const v of value) collectStrings(v, acc, depth + 1);
  else if (value && typeof value === "object") for (const v of Object.values(value)) collectStrings(v, acc, depth + 1);
  return acc;
}

// Decode base64 / hex runs embedded in the text so an encoded credential is still
// scanned by the finders above.
function decodeEmbeddedPayloads(raw) {
  const out = [];
  const b64 = raw.match(/[A-Za-z0-9+/]{24,}={0,2}/g) || [];
  for (const token of b64.slice(0, 20)) {
    try {
      const decoded = Buffer.from(token, "base64").toString("utf8");
      if (/[\x20-\x7e]/.test(decoded) && !/�/.test(decoded)) out.push(decoded);
    } catch { /* ignore */ }
  }
  const hex = raw.match(/\b[0-9a-fA-F]{32,}\b/g) || [];
  for (const token of hex.slice(0, 20)) {
    if (token.length % 2 === 0) {
      try {
        const decoded = Buffer.from(token, "hex").toString("utf8");
        if (/[\x20-\x7e]/.test(decoded) && !/�/.test(decoded)) out.push(decoded);
      } catch { /* ignore */ }
    }
  }
  return out;
}

function safeStringify(payload) {
  try { return JSON.stringify(payload ?? {}); }
  catch { return String(payload); }
}
