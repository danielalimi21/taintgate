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
