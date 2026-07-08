// The two defenses TaintGate is measured against. Both are faithful to how the
// real products in this space behave, reduced to their egress-decision essence so
// the comparison is apples-to-apples on the same corpus.

import { classifyPayload } from "../src/classify.js";

// Host allowlisting — the AI-gateway / egress-firewall posture (Cloudflare-style
// managed egress, a forward proxy allowlisting CONNECT targets, a NetworkPolicy).
// Authorizes by destination host and is blind to the payload: TLS is opaque, so
// once a host is approved anything may flow to it.
export function hostAllowlistDefense(allowlist) {
  const allow = new Set(allowlist.map((h) => h.toLowerCase()));
  return {
    name: "host-allowlist",
    // ingest is a no-op: this defense has no session state.
    ingest() {},
    egress(_sessionId, _payload, { host = "", external = true } = {}) {
      if (!external) return "allow";
      return allow.has(String(host).toLowerCase()) ? "allow" : "block";
    }
  };
}

// Outbound content scanning — single-message DLP / guardrails. Classifies the
// bytes of THIS request and holds if they read as sensitive. Stateless across the
// session: it never connects the outbound message to what was read earlier.
export function contentScanDefense(blockLevel = 4) {
  return {
    name: "content-scan",
    ingest() {},
    egress(_sessionId, payload, { external = true } = {}) {
      if (!external) return "allow";
      return classifyPayload(payload).level >= blockLevel ? "hold" : "allow";
    }
  };
}
