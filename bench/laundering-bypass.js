// Benchmark: the confidential-data laundering bypass.
//
// Runs the same corpus of agent sessions through three egress defenses and reports
// how many laundering/exfil attempts each one stops, and how many legitimate
// egresses each one wrongly holds. The headline: host allowlisting and single-
// message content scanning cannot see laundering to an allowed host, because the
// signal is not in the destination or in the outbound bytes — it is in what the
// session already read. TaintGate reads that signal.

import { TaintGate } from "../src/monitor.js";
import { hostAllowlistDefense, contentScanDefense } from "./defenses.js";
import { CORPUS } from "./corpus.js";

const ALLOWLIST = ["api.github.com", "hooks.slack.com", "api.openai.com"];

// Adapt TaintGate to the same {ingest, egress->decision} shape as the baselines.
function taintGateDefense() {
  const gate = new TaintGate({ taintBlockLevel: 4, sensitiveBlockLevel: 5, sealExternalEgress: false });
  return {
    name: "taintgate",
    ingest(sessionId, payload) { gate.ingest(sessionId, payload); },
    egress(sessionId, payload, opts) { return gate.egress(sessionId, payload, opts).decision; }
  };
}

function runDefense(make) {
  const defense = make();
  let attacksCaught = 0, attacksTotal = 0, benignHeld = 0, benignTotal = 0;
  const misses = [];
  for (const scenario of CORPUS) {
    const sessionId = scenario.id;
    for (const read of scenario.reads) defense.ingest(sessionId, read);
    const decision = defense.egress(sessionId, scenario.egress.payload, scenario.egress);
    const stopped = decision === "hold" || decision === "block";
    if (scenario.attack) {
      attacksTotal += 1;
      if (stopped) attacksCaught += 1; else misses.push(scenario.id);
    } else {
      benignTotal += 1;
      if (stopped) benignHeld += 1;
    }
  }
  return { name: defense.name, attacksCaught, attacksTotal, benignHeld, benignTotal, misses };
}

const results = [
  runDefense(() => hostAllowlistDefense(ALLOWLIST)),
  runDefense(() => contentScanDefense(4)),
  runDefense(taintGateDefense)
];

const pct = (n, d) => (d === 0 ? "—" : `${Math.round((n / d) * 100)}%`);

console.log("\nConfidential-data laundering to an allowed host — defense comparison");
console.log("─".repeat(78));
console.log(
  "defense".padEnd(18) +
  "laundering caught".padEnd(22) +
  "false holds".padEnd(16) +
  "misses"
);
console.log("─".repeat(78));
for (const r of results) {
  const caught = `${r.attacksCaught}/${r.attacksTotal} (${pct(r.attacksCaught, r.attacksTotal)})`;
  const fp = `${r.benignHeld}/${r.benignTotal} (${pct(r.benignHeld, r.benignTotal)})`;
  console.log(r.name.padEnd(18) + caught.padEnd(22) + fp.padEnd(16) + (r.misses.join(", ") || "none"));
}
console.log("─".repeat(78));
console.log(
  "\nThe discriminating case: `benign-clean-summary` and `launder-customer-table`\n" +
  "send the IDENTICAL outbound bytes to the SAME allowed host. Only a session-\n" +
  "stateful control allows the first and holds the second. Host allowlisting and\n" +
  "content scanning give both the same verdict — necessarily the wrong one for one\n" +
  "of them.\n"
);

// Non-zero exit if the core invariant regresses, so this doubles as a CI check.
const taint = results.find((r) => r.name === "taintgate");
if (taint.attacksCaught !== taint.attacksTotal || taint.benignHeld !== 0) {
  console.error("INVARIANT REGRESSED: taintgate must catch every attack with zero false holds.");
  process.exit(1);
}
