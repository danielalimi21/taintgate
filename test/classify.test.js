import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyPayload, mergeClassification } from "../src/classify.js";

test("benign short prose is established public", () => {
  const c = classifyPayload("The build passed and the docs are live.");
  assert.equal(c.level, 1);
  assert.equal(c.established, true);
});

test("keyword hit establishes a sensitive class", () => {
  const c = classifyPayload("This document is CONFIDENTIAL and attorney-client privileged.");
  assert.ok(c.level >= 4);
  assert.equal(c.established, true);
});

test("a Luhn-valid card with no keyword is caught by value shape", () => {
  const c = classifyPayload("ref 4012 8888 8888 1881 for the order");
  assert.equal(c.level, 5);
});

test("a Luhn-invalid number is not a card", () => {
  const c = classifyPayload("order number 4012 8888 8888 1882");
  assert.ok(c.level < 5);
});

test("a base64-wrapped secret does not classify as opaque public", () => {
  const wrapped = Buffer.from("aws key AKIAIOSFODNN7EXAMPLE").toString("base64");
  const c = classifyPayload(wrapped);
  assert.ok(c.level >= 5);
});

test("an opaque encoded blob is class-not-established, not trusted public", () => {
  const blob = "Z".repeat(600);
  const c = classifyPayload(blob);
  assert.equal(c.level, 1);
  assert.equal(c.established, false);
  assert.equal(c.egress_shape, "encoded_blob");
});

test("a bulk record array is class-not-established", () => {
  const c = classifyPayload({ rows: [1, 2, 3, 4, 5, 6] });
  assert.equal(c.established, false);
  assert.equal(c.egress_shape, "bulk_records");
});

test("a tabular dump is class-not-established", () => {
  const c = classifyPayload("a,b,c\n1,2,3\n4,5,6\n7,8,9");
  assert.equal(c.established, false);
  assert.equal(c.egress_shape, "tabular_dump");
});

test("an external classifier can raise class and establishment, never lower", () => {
  const base = classifyPayload("some perfectly ordinary sentence");
  assert.equal(base.level, 1);
  const merged = mergeClassification(base, { level: 4, established: true, source: "model-graded" });
  assert.equal(merged.level, 4);
  assert.equal(merged.established, true);
});
