// A model-graded classifier adapter for TaintGate's ingest seam.
//
// The deterministic floor in classify.js is blind to confidential prose that
// carries no keyword and no value shape — the exact laundering source the taint
// guard exists to catch. This adapter closes that gap: it asks a Claude model to
// grade the highest data-sensitivity class of a payload and returns a verdict in
// the shape mergeClassification() expects, so the class can only ever be RAISED,
// never lowered.
//
// Wire it into the ingest path:
//
//   import { TaintGate } from "taintgate";
//   import { anthropicClassifier } from "taintgate/classifiers/anthropic";
//
//   const gate = new TaintGate({ classifier: anthropicClassifier() });
//   await gate.ingestAsync(sessionId, payload);   // async — awaits the grader
//
// Zero-dependency: it uses the global fetch (Node >= 20) to call the Anthropic
// Messages API directly. Structured outputs pin the response to a JSON schema so
// the verdict parses deterministically.
//
// Model default is claude-haiku-4-5: this classifier runs on every witnessed read,
// so it must be fast and cheap — classification is Haiku's canonical use case. Pass
// `model` to override (e.g. a stronger model for higher-assurance sessions).

import { rankForLabel } from "../classify.js";

const API_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const DEFAULT_MODEL = "claude-haiku-4-5";
const DEFAULT_MAX_CHARS = 20000; // bound the input a per-read grader will see
const DEFAULT_CACHE_MAX = 500;

const SYSTEM_PROMPT = [
  "You are a data-loss-prevention classifier for an AI-agent egress monitor.",
  "Given a payload an agent has read, return the HIGHEST data-sensitivity class the",
  "content would carry for a business, judging by meaning — not by keywords alone.",
  "",
  "Classes:",
  "- public:       safe to publish; no harm if disclosed.",
  "- internal:     not secret but not for outsiders (internal notes, employee emails).",
  "- confidential: real business harm if disclosed (financials, M&A, layoffs, strategy,",
  "                unannounced plans, customer/personnel details, legal matters).",
  "- restricted:   credentials, secrets, keys, raw regulated data (SSN, cards, health).",
  "",
  "Grade on substance: a sentence with no trigger word can still be confidential.",
  "Return only the JSON object required by the schema."
].join("\n");

const OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    label: { type: "string", enum: ["public", "internal", "confidential", "restricted"] },
    findings: { type: "array", items: { type: "string" } }
  },
  required: ["label", "findings"],
  additionalProperties: false
};

// Build a classifier function suitable for `new TaintGate({ classifier })` and
// `gate.ingestAsync(...)`. Returns async (payload) => external | null, where a
// `null` (public / no signal / any failure) leaves the deterministic floor to
// stand — the external verdict can only raise class, never lower it.
//
// Options:
//   apiKey     Anthropic API key. Default: process.env.ANTHROPIC_API_KEY.
//   model      Model id. Default: claude-haiku-4-5.
//   maxChars   Truncate the payload to this many chars before grading. Default 20000.
//   timeoutMs  Abort the request after this long. Default 10000.
//   cache      Cache verdicts by payload to avoid re-grading identical reads. Default true.
//   cacheMax   Bounded cache size. Default 500.
//   onError    Called as (error) => void on any failure (the call still resolves null).
//              Failure is fail-open on taint by design: pair with sealExternalEgress
//              for a fail-closed posture. Default: no-op.
//   fetchImpl  fetch implementation (for testing). Default: global fetch.
export function anthropicClassifier(options = {}) {
  const {
    apiKey = typeof process !== "undefined" ? process.env.ANTHROPIC_API_KEY : undefined,
    model = DEFAULT_MODEL,
    maxChars = DEFAULT_MAX_CHARS,
    timeoutMs = 10000,
    cache = true,
    cacheMax = DEFAULT_CACHE_MAX,
    onError = () => {},
    fetchImpl = typeof fetch !== "undefined" ? fetch : undefined
  } = options;

  if (!fetchImpl) throw new Error("no fetch available; pass options.fetchImpl on Node < 18");

  const seen = cache ? new Map() : null;

  return async function classify(payload) {
    const text = stringify(payload).slice(0, maxChars);
    if (!text.trim()) return null;

    if (seen && seen.has(text)) return seen.get(text);

    let verdict = null;
    try {
      verdict = await grade(text);
    } catch (err) {
      onError(err);
      verdict = null; // fail open on taint; the floor stands
    }

    if (seen) {
      if (seen.size >= cacheMax) seen.delete(seen.keys().next().value);
      seen.set(text, verdict);
    }
    return verdict;
  };

  async function grade(text) {
    if (!apiKey) throw new Error("missing Anthropic API key (set ANTHROPIC_API_KEY or pass options.apiKey)");

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl(API_URL, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "content-type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": ANTHROPIC_VERSION
        },
        body: JSON.stringify({
          model,
          max_tokens: 256,
          temperature: 0,
          system: SYSTEM_PROMPT,
          output_config: { format: { type: "json_schema", schema: OUTPUT_SCHEMA } },
          messages: [{ role: "user", content: `<payload>\n${text}\n</payload>` }]
        })
      });
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${await safeBody(res)}`);
    const data = await res.json();
    if (data.stop_reason === "refusal") return null; // could not grade; floor stands

    const block = Array.isArray(data.content) ? data.content.find((b) => b.type === "text") : null;
    if (!block) return null;

    const parsed = JSON.parse(block.text);
    const level = rankForLabel(parsed.label);
    if (level < 2) return null; // public / no signal — do not disturb the floor

    return {
      level,
      established: true,
      findings: Array.isArray(parsed.findings) ? parsed.findings : [],
      source: `anthropic:${model}`
    };
  }
}

function stringify(payload) {
  if (typeof payload === "string") return payload;
  try { return JSON.stringify(payload ?? ""); }
  catch { return String(payload); }
}

async function safeBody(res) {
  try { return (await res.text()).slice(0, 200); }
  catch { return "<unreadable>"; }
}
