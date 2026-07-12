import { test } from "node:test";
import assert from "node:assert/strict";
import { TaintGate } from "../src/monitor.js";

const CONFIDENTIAL = { classification: "confidential", note: "internal board memo" };
const BENIGN = "The quarterly review went well and the team is aligned.";

test("clean session posting benign prose externally is allowed", () => {
  const g = new TaintGate();
  g.ingest("s1", "public getting-started docs");
  assert.equal(g.egress("s1", BENIGN, { external: true }).decision, "allow");
});

test("laundering: tainted session posting benign prose externally is held", () => {
  const g = new TaintGate();
  g.ingest("s1", CONFIDENTIAL);
  const r = g.egress("s1", BENIGN, { external: true });
  assert.equal(r.decision, "hold");
  assert.equal(r.reasons[0].code, "tainted-session-egress");
});

test("the discriminating property: identical bytes, opposite verdicts by session history", () => {
  const g = new TaintGate();
  g.ingest("clean", "public docs");
  g.ingest("dirty", CONFIDENTIAL);
  assert.equal(g.egress("clean", BENIGN, { external: true }).decision, "allow");
  assert.equal(g.egress("dirty", BENIGN, { external: true }).decision, "hold");
});

test("taint high-water mark is monotonic — reading a benign page does not clear it", () => {
  const g = new TaintGate();
  g.ingest("s1", CONFIDENTIAL);
  g.ingest("s1", "totally public marketing copy");
  assert.equal(g.getIngestedRank("s1"), 4);
  assert.equal(g.egress("s1", BENIGN, { external: true }).decision, "hold");
});

test("a different session id does not inherit — but taint cannot be reset within a session", () => {
  const g = new TaintGate();
  g.ingest("s1", CONFIDENTIAL);
  // A fresh session is genuinely clean; the point is you cannot LOWER s1's mark.
  assert.equal(g.getIngestedRank("s2"), 0);
  assert.equal(g.egress("s1", BENIGN, { external: true }).decision, "hold");
});

test("internal egress is not this control's concern", () => {
  const g = new TaintGate();
  g.ingest("s1", CONFIDENTIAL);
  assert.equal(g.egress("s1", BENIGN, { external: false }).decision, "allow");
});

test("a declared public-broadcast sink keeps the lane autonomous even when tainted", () => {
  const g = new TaintGate();
  g.ingest("s1", CONFIDENTIAL);
  assert.equal(g.egress("s1", BENIGN, { external: true, publicSink: true }).decision, "allow");
});

test("opaque egress with no taint is still held — looks-public is absence of evidence", () => {
  const g = new TaintGate();
  const r = g.egress("s1", "Q".repeat(600), { external: true });
  assert.equal(r.decision, "hold");
  assert.equal(r.reasons[0].code, "unverified-egress-class");
});

test("raw restricted content to any external destination is blocked outright", () => {
  const g = new TaintGate();
  const r = g.egress("s1", "AKIAIOSFODNN7EXAMPLE api_key", { external: true, publicSink: true });
  assert.equal(r.decision, "block");
});

test("default seal (opt-in) holds all non-public-sink external egress", () => {
  const g = new TaintGate({ sealExternalEgress: true });
  g.ingest("s1", "public docs");
  assert.equal(g.egress("s1", BENIGN, { external: true }).decision, "hold");
  assert.equal(g.egress("s1", BENIGN, { external: true, publicSink: true }).decision, "allow");
});

// The ingest seam: a model-graded classifier is what makes taint fire on
// confidential prose the deterministic floor is blind to (no keyword, no shape).
const KEYWORDLESS_CONFIDENTIAL =
  "We are acquiring Acme for 12 million, closing Friday; do not disclose before the announcement.";

test("without a classifier, keyword-less confidential prose sets no taint and launders through", () => {
  const g = new TaintGate({ taintBlockLevel: 4 });
  const { ingestedRank } = g.ingest("s1", KEYWORDLESS_CONFIDENTIAL);
  assert.equal(ingestedRank, 1); // deterministic floor is blind to it
  assert.equal(g.egress("s1", BENIGN, { external: true }).decision, "allow");
});

test("a model-graded classifier at ingest raises taint and the laundering egress is then held", () => {
  const modelGraded = (payload) =>
    /acquir|acquisition|do not disclose|confidential|layoff/i.test(String(payload))
      ? { level: 4, established: true, source: "model-graded" }
      : null;
  const g = new TaintGate({ taintBlockLevel: 4, classifier: modelGraded });
  const { ingestedRank, classification } = g.ingest("s1", KEYWORDLESS_CONFIDENTIAL);
  assert.equal(ingestedRank, 4);
  assert.ok(classification.classifier_sources.includes("model-graded"));
  const r = g.egress("s1", BENIGN, { external: true });
  assert.equal(r.decision, "hold");
  assert.equal(r.reasons[0].code, "tainted-session-egress");
});

test("the classifier can only RAISE class, never lower an established sensitive floor", () => {
  const underGrader = () => ({ level: 1, established: true, source: "under-grader" });
  const g = new TaintGate({ classifier: underGrader });
  // deterministic floor already establishes confidential from the keyword
  const { ingestedRank } = g.ingest("s1", "This memo is attorney-client privileged.");
  assert.equal(ingestedRank, 4);
});

test("ingest throws a directed error if a sync classifier returns a Promise", () => {
  const asyncGrader = async () => ({ level: 4, established: true });
  const g = new TaintGate({ classifier: asyncGrader });
  assert.throws(() => g.ingest("s1", KEYWORDLESS_CONFIDENTIAL), /ingestAsync/);
});

test("ingestAsync awaits a model-graded classifier and raises taint accordingly", async () => {
  const asyncGrader = async (payload) =>
    /acquir/i.test(String(payload)) ? { level: 4, established: true, source: "llm-judge" } : null;
  const g = new TaintGate({ taintBlockLevel: 4, classifier: asyncGrader });
  const { ingestedRank } = await g.ingestAsync("s1", KEYWORDLESS_CONFIDENTIAL);
  assert.equal(ingestedRank, 4);
  assert.equal(g.egress("s1", BENIGN, { external: true }).decision, "hold");
});

// Destination awareness: host resolves external / public-sink when the caller
// does not override with an explicit boolean, and is recorded for the ledger.
test("a host in publicSinkHosts stands the taint guard down and is recorded on the verdict", () => {
  const g = new TaintGate({ publicSinkHosts: ["status.example.com"] });
  g.ingest("s1", CONFIDENTIAL);
  const r = g.egress("s1", BENIGN, { host: "status.example.com" });
  assert.equal(r.decision, "allow");
  assert.equal(r.host, "status.example.com");
});

test("a host not declared public is treated external and the laundering egress is held", () => {
  const g = new TaintGate({ publicSinkHosts: ["status.example.com"] });
  g.ingest("s1", CONFIDENTIAL);
  assert.equal(g.egress("s1", BENIGN, { host: "api.github.com" }).decision, "hold");
});

test("a host in internalHosts does not leave the trust boundary", () => {
  const g = new TaintGate({ internalHosts: ["svc.internal"] });
  g.ingest("s1", CONFIDENTIAL);
  assert.equal(g.egress("s1", BENIGN, { host: "svc.internal" }).decision, "allow");
});

test("an explicit external/publicSink boolean overrides host resolution", () => {
  const g = new TaintGate({ publicSinkHosts: ["status.example.com"] });
  g.ingest("s1", CONFIDENTIAL);
  // host says public sink, but the caller forces publicSink:false → held
  assert.equal(g.egress("s1", BENIGN, { host: "status.example.com", publicSink: false }).decision, "hold");
});
