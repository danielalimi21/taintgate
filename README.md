# TaintGate

*In plain terms: it stops an AI agent from sneaking confidential data out disguised as harmless text.*

**A session-taint egress reference monitor for AI agents.** It stops one specific,
under-covered attack: an agent reads confidential data, the model rewrites it into
benign-looking prose, and the agent posts that prose to a destination that is *on
the allowlist*. Host allowlisting and single-message content scanning both wave
this through. TaintGate holds it.

```
Laundering caught — 124-case adversarial benchmark (of 56 in-scope attacks)
──────────────────────────────────────────────────────────────────────────────
  host allowlisting     0 / 56
  content scanning      8 / 56
  taintgate            56 / 56      at 0 false holds on clean traffic
──────────────────────────────────────────────────────────────────────────────
```

TaintGate **also misses 20 / 20 out-of-scope attacks** (cross-session, out-of-band,
classifier-blind) — by design; that is what the fail-closed seal and the
[Known gaps](#known-gaps) section are for. The two stateless defenses stay
near-blind to laundering regardless of corpus size — the blindness is *structural*,
not a small-sample artifact.

Reproduce: `npm run bench` (124-case adversarial benchmark) · `npm test`.
No dependencies, Node ≥ 20.

---

## The gap

Agent-egress security in 2026 is converged on two controls, and a laundering
exfiltration slips between them:

- **Host allowlisting** — the AI-gateway / egress-firewall posture (managed egress,
  a forward proxy allowlisting `CONNECT` targets, a Kubernetes `NetworkPolicy`).
  It authorizes by destination and is **blind to the payload** — TLS is opaque by
  design. Once `api.github.com` is approved, anything can flow to a gist there.
- **Outbound content scanning** — single-message DLP / guardrails. It classifies
  the bytes of *this* request. After the model has paraphrased a confidential
  table into "the quarterly review went well," **the bytes read as benign.**

Neither control can see the laundering, because the signal is in neither place.
It is not in the destination (approved) and not in the outbound bytes (benign). It
is in **what the session already read.**

## The control

TaintGate judges egress by what the *session* has been exposed to, not only by the
outbound bytes.

1. Every read the agent makes raises a per-session **ingest-taint high-water mark**
   (the highest data class the session has touched).
2. When a tainted session then sends **lower-classed** content to an external
   destination — the signature of a downgrade / launder — the egress is **held for
   human review**.
3. The high-water mark is **monotonic**: reading a benign page afterward, or
   rotating the session id, cannot clear accrued taint.

The discriminating property, which no stateless control can reproduce:

> The `clean-same-bytes` and `launder` cases in the corpus send the **identical
> outbound bytes** to the **same allowed host** — the only difference is that the
> laundering session read confidential data first. TaintGate *allows the clean one
> and holds the laundering one*. A destination check and a byte check must give both
> the same verdict — necessarily wrong for one of them.

```js
import { TaintGate } from "taintgate";

const gate = new TaintGate({ taintBlockLevel: 4 });   // 4 = confidential

gate.ingest("session-42", confidentialCustomerTable); // agent reads sensitive data
// ... model rewrites it into a benign-looking summary ...
gate.egress("session-42", "The quarterly review went well.", {
  external: true, host: "api.github.com"
});
// → { decision: "hold", reasons: [{ code: "tainted-session-egress", ... }] }
```

This is a **floor control, not a detector.** It does not try to prove intent or
classify the laundered bytes (it can't — that's the point). It makes the
laundering egress non-autonomous: allowed, held, or blocked, with a reason on the
record.

<a name="known-gaps"></a>
## Known gaps — what it honestly does *not* catch

Measured, not hand-waved: in the red-team run above these are the `gap` categories,
and TaintGate catches **0/20** of them on purpose. Three failure modes:

- **Cross-session** — the agent reads under one session id and exfiltrates under
  another. Taint is per-session, so a fresh id carries no mark.
- **Out-of-band read** — the monitor never saw the read (another tool supplied the
  data), so no taint is set.
- **Classifier-blind source** — the sensitive material carries no keyword and no
  value shape, so the deterministic floor rates it public and no taint is set.

All three collapse to the same root: the taint guard only sees laundering the
monitor **witnessed the ingest for**. A secret the model read
*out of band* — through a channel the monitor doesn't sit on — leaves no taint, and
the laundered bytes classify as established-public. Nothing byte-level or
taint-level catches that.

For that residual there is one sound posture, and it isn't clever: **fail closed.**
`sealExternalEgress: true` holds *all* meaningful external egress that isn't to a
destination you've explicitly declared a public-broadcast sink. It trades precision
for safety and is off by default. The benchmark reports the taint guard alone (seal
off) so the precision numbers are honest.

Consequences of the design, stated plainly:

- TaintGate must sit where **both the agent's reads and its egress pass through
  it** (an SDK tool-call wrapper, a gateway, an MCP shim). It is an application-
  layer control; it does not inspect TLS and does not replace network egress
  control — it complements it.
- Data-class classification is a floor. The bundled classifier is deterministic
  (keyword + value-shape + entropy + decode) and is blind to confidential prose
  carrying no keyword or value shape — that is why the seam below exists.
  `mergeClassification()` fuses a model-graded or commercial classifier onto the
  floor, and the constructor `classifier` hook wires it into **ingest** (where it
  matters — taint has to be set at read time). The external verdict can only raise
  class, never lower it. Use `ingestAsync()` for a classifier that returns a Promise.
- Taint is coarse (a single high-water rank per session), not field-level lineage.
  That is deliberate — it is cheap, it cannot be gamed downward, and it is the
  right granularity for an allow/hold gate. Fine-grained provenance is a different,
  heavier tool.

## Where this sits relative to the field

The adjacent work, and the specific strip this occupies:

- **AI gateways / managed egress** (Cloudflare's Claude-agent egress policies,
  forward-proxy allowlisting, K8s NetworkPolicy) own the *host* decision and say so
  — they are payload-blind by design. TaintGate is the payload/session-aware layer
  that rides *behind* an allowlist, not a replacement for it.
- **Data-lineage DLP** (Cyberhaven, Nightfall) tracks data source→destination for
  human/SaaS/endpoint flows. TaintGate applies the same intuition — provenance
  gates egress — at the **agent tool-call boundary**, as a session high-water mark
  fused with a fail-closed default, rather than at the endpoint. It is small enough
  to embed in an agent loop.
- **Academic reference monitors for LLM-agent egress** (e.g. application-layer
  covert-channel monitors, 2026) formalize the same threat. TaintGate is a
  minimal, runnable, test-covered instance of that idea, not a novel theory.

The honest claim is narrow: **the session-taint-to-tool-gate binding with a
fail-closed default is not something the shipping agent-egress controls do**, and
this repo demonstrates the gap with a reproducible benchmark. It is a control worth
embedding, not a category.

## Provenance

The classifier and the `tainted-session-egress` / default-seal logic are a faithful
extraction from a larger agent-authorization engine (ScopeZero), reduced to the one
control that stands on its own, with an added benchmark that isolates its effect.

## API

```
new TaintGate({ taintBlockLevel = 4, sensitiveBlockLevel = 5,
  sealExternalEgress = false, classifier = null })    // classifier: model-graded verdict fused at ingest

gate.ingest(sessionId, payload)                    → { ingestedRank, classification }
gate.ingestAsync(sessionId, payload)               → Promise<{ ingestedRank, classification }>  // async classifier
gate.egress(sessionId, payload, {                  → { decision, reasons, classification, ingestedRank }
  external = true, publicSink = false })              decision ∈ "allow" | "hold" | "block"
gate.getIngestedRank(sessionId)                    → number

classifyPayload(payload)   // "taintgate/classify" → { level, label, findings, egress_shape, established }
mergeClassification(base, external)                // layer a model-graded/commercial classifier on top
```

MIT licensed.
