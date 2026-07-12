# TaintGate

*In plain terms: it stops an AI agent from sneaking confidential data out disguised as harmless text.*

**A session-taint egress reference monitor for AI agents.** It stops one specific,
under-covered attack: an agent reads confidential data, the model rewrites it into
benign-looking prose, and the agent posts that prose to a destination that is *on
the allowlist*. Host allowlisting and single-message content scanning both wave
this through. TaintGate holds it.

```
Laundering caught — 130-case adversarial benchmark (of 56 in-scope attacks)
──────────────────────────────────────────────────────────────────────────────
  host allowlisting     0 / 56
  content scanning      8 / 56
  taintgate            56 / 56      at 0 false holds on clean prose
──────────────────────────────────────────────────────────────────────────────
```

One precision cost, stated up front and not hidden in that 0%: clean **structured
or encoded** egress (a CSV, a bulk record array, an opaque blob) is held for review
even from an untainted session — its class can't be positively established from the
bytes, and "looks public" there is absence of evidence. The benchmark reports that
as its own line (`clean STRUCTURED egress held: 6/6`), separate from false holds.

TaintGate **also misses 20 / 20 out-of-scope attacks** (cross-session, out-of-band,
classifier-blind) — by design; that is what the fail-closed seal and the
[Known gaps](#known-gaps) section are for. The two stateless defenses stay
near-blind to laundering regardless of corpus size — the blindness is *structural*,
not a small-sample artifact.

The benchmark runs the **deterministic floor only** — no network — so the numbers
stay reproducible offline. The 6 `classifier-blind` gaps in that 20 are the slice a
model-graded classifier at ingest is built to close; wiring the bundled
[Anthropic adapter](#model-graded-classifier) into `ingestAsync` catches them (the
cross-session and out-of-band gaps are structural and remain the seal's job).

Reproduce: `npm run bench` (130-case adversarial benchmark) · `npm test`.
Core is dependency-free, Node ≥ 20; the model-graded adapter is opt-in and also
dependency-free (global `fetch`).

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

const gate = new TaintGate({
  taintBlockLevel: 4,                     // 4 = confidential
  publicSinkHosts: ["status.example.com"], // declared public-broadcast sinks
  internalHosts: ["svc.internal"]          // hosts inside the trust boundary
});

gate.ingest("session-42", confidentialCustomerTable); // agent reads sensitive data
// ... model rewrites it into a benign-looking summary ...
gate.egress("session-42", "The quarterly review went well.", {
  host: "api.github.com"                  // resolved external → held; recorded on the verdict
});
// → { decision: "hold", reasons: [{ code: "tainted-session-egress", ... }], host: "api.github.com" }
```

`host` drives the destination decision: it resolves to a public sink or an internal
host against the sets above, and is recorded on every verdict for the audit ledger.
An explicit `external` / `publicSink` boolean still overrides it. TaintGate rides
*behind* a host allowlist — this is a trust declaration layered on the payload/session
signal, not a replacement for network egress control.

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
  A ready-to-use model-graded adapter ships in
  [`taintgate/classifiers/anthropic`](#model-graded-classifier) — see below.

<a name="model-graded-classifier"></a>
### Model-graded classifier (bundled)

`taintgate/classifiers/anthropic` is a zero-dependency adapter that grades each
read with a Claude model, so taint fires on keyword-less confidential prose the
deterministic floor rates public.

```js
import { TaintGate } from "taintgate";
import { anthropicClassifier } from "taintgate/classifiers/anthropic";

const gate = new TaintGate({ classifier: anthropicClassifier() });  // reads ANTHROPIC_API_KEY
await gate.ingestAsync("session-42", confidentialFinancialMemo);    // async — awaits the grader
```

- Uses the global `fetch` (Node ≥ 20) to call the Anthropic Messages API directly;
  structured outputs pin the verdict to a JSON schema. No SDK, no dependencies.
- Defaults to `claude-haiku-4-5` — this runs on **every** witnessed read, so it must
  be fast and cheap (classification is Haiku's canonical use case). Pass `model` to
  override for higher-assurance sessions.
- Verdicts are cached by payload (bounded) so identical reads are graded once.
- Raise-only: a `public` verdict returns `null` and leaves the floor untouched. A
  grading failure also returns `null` — fail-open on taint by design; pair with
  `sealExternalEgress: true` for a fail-closed posture.
- Options: `apiKey`, `model`, `maxChars`, `timeoutMs`, `cache`, `cacheMax`, `onError`,
  `fetchImpl`.

The unit tests exercise the adapter against injected fetch responses (no network).
To validate the request wire-format and parsing against the live API:

```
ANTHROPIC_API_KEY=sk-ant-... npm run verify:anthropic
```

It grades one confidential and one public line, wires the grader into a `TaintGate`,
and asserts the laundering egress is held while a clean session's identical bytes
pass. Without the key it skips.
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
  sealExternalEgress = false, classifier = null,      // classifier: model-graded verdict fused at ingest
  publicSinkHosts = [], internalHosts = [] })         // hosts that resolve the destination decision

gate.ingest(sessionId, payload)                    → { ingestedRank, classification }
gate.ingestAsync(sessionId, payload)               → Promise<{ ingestedRank, classification }>  // async classifier
gate.egress(sessionId, payload, {                  → { decision, reasons, classification, ingestedRank, host }
  host, external, publicSink })                       decision ∈ "allow" | "hold" | "block"
                                                       // host resolves external/publicSink; an explicit
                                                       // boolean overrides it
gate.getIngestedRank(sessionId)                    → number

classifyPayload(payload)   // "taintgate/classify" → { level, label, findings, egress_shape, established }
mergeClassification(base, external)                // layer a model-graded/commercial classifier on top
anthropicClassifier(opts)  // "taintgate/classifiers/anthropic" → async (payload) => external | null
```

MIT licensed.
