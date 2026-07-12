import { test } from "node:test";
import assert from "node:assert/strict";
import { anthropicClassifier } from "../src/classifiers/anthropic.js";
import { TaintGate } from "../src/monitor.js";

// A canned Anthropic Messages API response with a structured-output text block.
function apiResponse({ label, findings = [], stop_reason = "end_turn" } = {}) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      stop_reason,
      content: [{ type: "text", text: JSON.stringify({ label, findings }) }]
    }),
    text: async () => ""
  };
}

// A fake fetch that records calls and returns a queued response.
function fakeFetch(response) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return typeof response === "function" ? response(calls.length) : response;
  };
  impl.calls = calls;
  return impl;
}

test("maps a confidential verdict to a raise-only external classification", async () => {
  const fetchImpl = fakeFetch(apiResponse({ label: "confidential", findings: ["m&a"] }));
  const classify = anthropicClassifier({ apiKey: "k", fetchImpl });
  const verdict = await classify("We are acquiring Acme; do not disclose.");
  assert.equal(verdict.level, 4);
  assert.equal(verdict.established, true);
  assert.deepEqual(verdict.findings, ["m&a"]);
  assert.equal(verdict.source, "anthropic:claude-haiku-4-5");
});

test("a public verdict returns null so the deterministic floor stands", async () => {
  const fetchImpl = fakeFetch(apiResponse({ label: "public" }));
  const classify = anthropicClassifier({ apiKey: "k", fetchImpl });
  assert.equal(await classify("The build passed."), null);
});

test("caching: an identical payload is graded once", async () => {
  const fetchImpl = fakeFetch(apiResponse({ label: "confidential" }));
  const classify = anthropicClassifier({ apiKey: "k", fetchImpl });
  await classify("same bytes");
  await classify("same bytes");
  assert.equal(fetchImpl.calls.length, 1);
});

test("a refusal returns null (could not grade)", async () => {
  const fetchImpl = fakeFetch(apiResponse({ label: "confidential", stop_reason: "refusal" }));
  const classify = anthropicClassifier({ apiKey: "k", fetchImpl });
  assert.equal(await classify("something"), null);
});

test("failure is fail-open on taint: onError fires and the call resolves null", async () => {
  let captured = null;
  const fetchImpl = async () => { throw new Error("network down"); };
  const classify = anthropicClassifier({ apiKey: "k", fetchImpl, onError: (e) => { captured = e; } });
  assert.equal(await classify("x"), null);
  assert.match(captured.message, /network down/);
});

test("sends the required Anthropic headers and a structured-output request", async () => {
  const fetchImpl = fakeFetch(apiResponse({ label: "public" }));
  const classify = anthropicClassifier({ apiKey: "secret", fetchImpl });
  await classify("hello");
  const { init } = fetchImpl.calls[0];
  assert.equal(init.headers["x-api-key"], "secret");
  assert.equal(init.headers["anthropic-version"], "2023-06-01");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "claude-haiku-4-5");
  assert.equal(body.output_config.format.type, "json_schema");
});

test("end to end: the adapter raises taint and the laundering egress is held", async () => {
  const fetchImpl = fakeFetch(apiResponse({ label: "confidential", findings: ["financials"] }));
  const gate = new TaintGate({ taintBlockLevel: 4, classifier: anthropicClassifier({ apiKey: "k", fetchImpl }) });
  const { ingestedRank } = await gate.ingestAsync("s1", "Q3 revenue was 4.2M, up from 3.1M.");
  assert.equal(ingestedRank, 4);
  const r = gate.egress("s1", "The quarterly review went well.", { external: true });
  assert.equal(r.decision, "hold");
  assert.equal(r.reasons[0].code, "tainted-session-egress");
});
