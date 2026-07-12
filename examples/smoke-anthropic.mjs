// Live smoke test for the Anthropic model-graded classifier adapter.
//
// The unit tests exercise the adapter's logic against injected fetch responses —
// they do NOT hit the network. This script makes ONE real call against the
// Anthropic Messages API to validate the request wire-format and response parsing
// end to end. It costs a few tokens.
//
//   ANTHROPIC_API_KEY=sk-ant-... node examples/smoke-anthropic.mjs
//
// It grades one obviously-confidential line and one obviously-public line, wires the
// grader into a TaintGate, and asserts the laundering egress is held while a clean
// session's identical bytes pass. Exits non-zero on any mismatch.

import assert from "node:assert/strict";
import { TaintGate } from "../src/monitor.js";
import { anthropicClassifier } from "../src/classifiers/anthropic.js";

if (!process.env.ANTHROPIC_API_KEY) {
  console.log("skip: set ANTHROPIC_API_KEY to run the live smoke test");
  process.exit(0);
}

const classifier = anthropicClassifier({ onError: (e) => console.error("classifier error:", e.message) });

const confidential = "We are acquiring Acme for 12 million, closing Friday; do not disclose before the announcement.";
const publicLine = "The build passed and the docs site is live.";

const conf = await classifier(confidential);
const pub = await classifier(publicLine);
console.log("confidential →", conf);
console.log("public       →", pub);

assert.ok(conf && conf.level >= 4, "expected the confidential line to grade >= confidential");
assert.equal(pub, null, "expected the public line to return null (floor stands)");

const gate = new TaintGate({ taintBlockLevel: 4, classifier });
await gate.ingestAsync("dirty", confidential);
gate.ingest("clean", publicLine); // sync path, no grader signal → floor stays public

const held = gate.egress("dirty", "The quarterly review went well.", { external: true, host: "api.github.com" });
const passed = gate.egress("clean", "The quarterly review went well.", { external: true, host: "api.github.com" });

assert.equal(held.decision, "hold", "tainted session should be held");
assert.equal(passed.decision, "allow", "clean session with identical bytes should pass");

console.log("\nOK: live grader raises taint; laundering held, clean allowed.");
