// TaintGate — a session-taint egress reference monitor for AI agents.
//
// The problem it exists for: an agent reads confidential data, the model rewrites
// it into benign-looking prose, and the agent posts that prose to a destination
// that is on the allowlist (its own gist on api.github.com, an approved webhook).
// Two common defenses both wave it through:
//
//   • host allowlisting (the AI-gateway / egress-firewall posture) authorizes the
//     CONNECT because the host is approved, and is blind to the payload — TLS is
//     opaque by design.
//   • outbound content scanning (single-message DLP / guardrails) classifies the
//     bytes, and the laundered prose classifies as benign.
//
// TaintGate judges egress by what the SESSION has been exposed to, not only by the
// outbound bytes. Every read the agent makes raises a per-session ingest-taint
// high-water mark. When a tainted session then sends LOWER-classed content to an
// external destination — the signature of a downgrade / launder — the egress is
// held for human review. The high-water mark is monotonic: a prompt-injected agent
// cannot clear accrued taint by rotating its session id or reading a benign page.
//
// This is a floor control, not a detector. It does not try to prove intent; it
// makes the laundering egress non-autonomous. Faithful extraction of the
// `tainted-session-egress` + default-seal logic in ScopeZero's policy engine.

import { classifyPayload } from "./classify.js";

const CONFIDENTIAL = 4; // default taint threshold — see LEVELS in classify.js
const RESTRICTED = 5;

export class TaintGate {
  // taintBlockLevel:      ingest at/above this arms the laundering guard (default confidential).
  // sensitiveBlockLevel:  outbound at/above this to an external dest is blocked outright (default restricted).
  // sealExternalEgress:   fail-closed posture — hold ALL meaningful external egress
  //                       to a non-public-sink (default false; the precise control
  //                       is the taint guard, the seal is the belt-and-suspenders
  //                       posture, and it trades precision for safety honestly).
  constructor({ taintBlockLevel = CONFIDENTIAL, sensitiveBlockLevel = RESTRICTED, sealExternalEgress = false } = {}) {
    this.taintBlockLevel = taintBlockLevel;
    this.sensitiveBlockLevel = sensitiveBlockLevel;
    this.sealExternalEgress = sealExternalEgress;
    this.sessions = new Map(); // sessionId -> ingested-class high-water mark
  }

  // Record that a read / tool output exposed a session to some data. Monotonic:
  // the mark can only ever rise. Returns the new mark and the classification.
  ingest(sessionId, payload, { classification = null } = {}) {
    const c = classification || classifyPayload(payload);
    const prev = this.sessions.get(sessionId) || 0;
    const next = Math.max(prev, c.level);
    this.sessions.set(sessionId, next);
    return { ingestedRank: next, classification: c };
  }

  getIngestedRank(sessionId) { return this.sessions.get(sessionId) || 0; }

  // Decide an outbound request. `external` marks egress that leaves the trust
  // boundary; `publicSink` marks a destination explicitly declared a
  // public-broadcast sink (laundering there is an audited, accepted decision).
  // Returns { decision: "allow"|"hold"|"block", reasons, classification, ingestedRank }.
  egress(sessionId, payload, { external = true, publicSink = false, classification = null } = {}) {
    const c = classification || classifyPayload(payload);
    const ingested = this.getIngestedRank(sessionId);
    const reasons = [];

    if (!external) {
      return { decision: "allow", reasons, classification: c, ingestedRank: ingested };
    }

    // 1. Outbound content is itself sensitive at/above the block line → hard stop.
    //    (The easy case; a content scanner catches this too. Included so the
    //    monitor is complete, not to claim novelty here.)
    if (c.level >= this.sensitiveBlockLevel) {
      reasons.push({ code: "sensitive-egress", detail: `Outbound ${c.label} content crossing an external boundary.` });
      return { decision: "block", reasons, classification: c, ingestedRank: ingested };
    }

    // 2. Laundering guard — the core control. The session ingested data at/above
    //    the taint line, and is now sending LOWER-classed content out. That
    //    downgrade is the laundering signature; the bytes look benign precisely
    //    because they were rewritten. Egress at/above the ingested class is already
    //    handled by (1)/data-class gates, so this fires only on the downgrade.
    if (ingested >= this.taintBlockLevel && c.level < ingested && !publicSink) {
      reasons.push({
        code: "tainted-session-egress",
        detail: `Session ingested ${labelFor(ingested)} data; outbound ${c.label} content could be laundered. Held for review.`
      });
      return { decision: "hold", reasons, classification: c, ingestedRank: ingested };
    }

    // 3. Opaque egress — the outbound class could not be positively established as
    //    public (no keyword, and the bytes carry a bulk/tabular/encoded/oversized
    //    shape). "Looks public" here is absence of evidence; hold it.
    if (c.level <= 1 && c.established !== true) {
      reasons.push({
        code: "unverified-egress-class",
        detail: `Outbound class not established from the bytes (shape: ${c.egress_shape}). Held for review.`
      });
      return { decision: "hold", reasons, classification: c, ingestedRank: ingested };
    }

    // 4. Default seal (opt-in) — the honest fail-closed posture. A secret read
    //    out-of-band and laundered into benign prose is invisible to (2) and (3):
    //    those bytes classify as established-public and the gateway never saw the
    //    read. Once you accept benign-looking bytes may be laundered, the only
    //    sound posture is to hold ALL meaningful external egress that is not to a
    //    declared public sink. Off by default because it trades precision for
    //    safety; turn it on for high-assurance sessions.
    if (this.sealExternalEgress && !publicSink) {
      reasons.push({
        code: "external-egress-sealed",
        detail: "External egress sealed to review by default. Declare a public-broadcast sink to keep this lane autonomous."
      });
      return { decision: "hold", reasons, classification: c, ingestedRank: ingested };
    }

    return { decision: "allow", reasons, classification: c, ingestedRank: ingested };
  }
}

function labelFor(level) {
  return level >= 5 ? "restricted" : level >= 4 ? "confidential" : level >= 2 ? "internal" : "public";
}
