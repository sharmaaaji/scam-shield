/**
 * Evaluates ONLY the Tier-0 fast path against the full 100-message dataset.
 *
 * Runs with no model and no network, so it is free and instant. It answers the
 * two questions that decide whether tiering is safe to ship:
 *
 *   1. What fraction of messages skip the model entirely?
 *   2. How many actual scams would the fast path wrongly wave through?
 *
 * (2) must be zero. Anything else means the fast path is dangerous and its
 * rules need tightening.
 *
 * Run:  osascript -l JavaScript eval/triage_eval.js
 */

function readFile(path) {
  return ObjC.unwrap(
    $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, null)
  );
}

const ROOT = ObjC.unwrap($.NSString.stringWithString("./").stringByExpandingTildeInPath);

eval(readFile("extension/shared/triage.js"));
const dataset = JSON.parse(readFile("eval/dataset.json"));

const { triage } = globalThis.ScamShieldTriage;

let bypassed = 0;
let escalated = 0;
const wronglyCleared = [];   // scams the fast path called safe  <- must be empty
const correctlyCleared = []; // legit messages resolved with no model call

for (const c of dataset) {
  // The dataset carries text only, so no sender metadata is simulated here.
  // That is the conservative case: real usage supplies extra risk context
  // (unknown sender, brand/domain mismatch) which can only cause MORE
  // escalation, never less.
  const result = triage(c.text, {});

  if (result.escalate) {
    escalated++;
  } else {
    bypassed++;
    if (c.label === "scam") wronglyCleared.push(c);
    else correctlyCleared.push(c);
  }
}

const total = dataset.length;
const scams = dataset.filter(c => c.label === "scam").length;
const legit = total - scams;

console.log("=".repeat(64));
console.log("TIER-0 FAST PATH  (deterministic, no model, no network)");
console.log("=".repeat(64));
console.log(`Dataset: ${total} messages (${scams} scam / ${legit} legit)`);
console.log("");
console.log(`  Resolved without a model call : ${bypassed}  (${(100 * bypassed / total).toFixed(1)}%)`);
console.log(`  Escalated to the model        : ${escalated}  (${(100 * escalated / total).toFixed(1)}%)`);
console.log("");
console.log(`  Legit messages fast-passed    : ${correctlyCleared.length} / ${legit}  <- inference saved`);
console.log(`  SCAMS wrongly fast-passed     : ${wronglyCleared.length} / ${scams}  <- MUST BE 0`);
console.log("");

if (wronglyCleared.length > 0) {
  console.log("!!! FAST PATH IS UNSAFE - these scams bypassed the model:");
  for (const c of wronglyCleared) {
    console.log(`  id=${c.id} [${c.category}]`);
    console.log(`     ${c.text.slice(0, 120)}`);
  }
  console.log("");
}

console.log("Legit messages that still cost a model call (escalated):");
const legitEscalated = dataset.filter(
  c => c.label === "legit" && triage(c.text, {}).escalate
);
for (const c of legitEscalated) {
  console.log(`  id=${c.id} [${c.category}]`);
}
console.log("");
console.log(`Model calls needed for full eval: ${escalated} instead of ${total}`);
