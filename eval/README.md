# Evaluation

Measuring whether the classifier can actually be trusted — because a scam
detector that cries wolf on real bank alerts is worse than no detector at all
(users learn to dismiss the badge, including the one time it's right).

## The dataset

`dataset.json` — 100 hand-written labeled messages, 50 scam / 50 legitimate,
spanning both Gmail-style and WhatsApp-style phrasing.

The scam half covers 50 distinct scam types (fake KYC, delivery-fee, lottery,
UPI refund tricks, sextortion, CEO fraud, task scams, romance, tech support,
advance-fee, and more) rather than 50 variations of one pattern.

**25 of the 50 legitimate messages are deliberate "hard negatives"** — real
messages that carry every surface signal of a scam: genuine bank OTPs, real
transaction alerts, real delivery notifications with links, real password-reset
emails, promotional offers with countdown urgency, real KYC reminders, a real
family medical emergency. These are tagged with a `HARD-` category prefix.

They're the actual point of the test set. Catching an obvious lottery scam is
easy; staying silent on a legitimate `Rs.12,500 debited` alert is the hard part,
and it's the one that determines whether this is usable day to day.

## Metrics

Ground truth is binary (scam / legit); the classifier returns three verdicts
(scam / suspicious / safe). Since the extension shows a badge for **both**
`scam` and `suspicious`, the primary metrics treat "badge shown" as the positive
prediction — that's what a user actually experiences.

Reported: accuracy, precision, recall, F1, false-positive rate, miss rate, plus
a separate false-positive rate over the hard-negative slice, and every individual
misclassification printed in full for inspection.

## Running it

```bash
# with the API running on localhost:5090
python3 eval/run_eval.py
```

Results stream to `eval/results.json` after every message and the script resumes
from wherever it left off, so an interrupted run never loses completed work.

## Known limitation of this methodology

The test set is **author-written, not sampled from real-world traffic**. That
introduces a bias worth naming: messages written by one author to test a
classifier can encode the same assumptions about "what a scam looks like" that
the classifier is being tested for. The hard negatives mitigate this — they're
constructed specifically to punish naive signal-matching (urgency + a link + a
rupee amount appears in both halves of the set) — but a genuinely rigorous
evaluation would use a public labeled corpus or real reported-scam data.

## Measured baseline — full pipeline on Gemini Nano, 4 Aug 2026

First complete end-to-end run: Tier 0 → on-device Gemini Nano → display
thresholds, 104 of 105 scored (1 model error).

| | |
|---|---|
| Accuracy | 0.923 |
| Precision | 0.887 |
| Recall (catch rate) | 0.959 — 47 of 49 scams |
| False-positive rate | 10.9% |
| Hard-negative FP rate | **20.0% — 6 of 30** |
| Resolved by Tier 0, no model | 26.0% |

Recall was good. The false-positive rate was not, and every one of the six false
alarms was a **bank or security notification** — the category scams imitate, and
the mail real users receive most often.

### What the failures showed

The two "missed" scams were not model failures. Both (a task scam and a fake
court summons) were correctly judged `suspicious` at 0.70 and hidden by the 0.75
display threshold — the model was right, the threshold was wrong.

The false alarms split in two. Four were **confidently wrong** and beyond any
threshold fix:

- a delivered OTP called a scam at 0.90, reasoned as *"the message asks for an OTP"* — it does not, the code is being delivered
- a routine debit alert at 0.95
- a bank fraud alert saying *"call the number printed on the back of your card"* at 0.85 — the safest possible instruction
- a payment receipt at 0.85, described as *"asks you to pay again"*

The delivered-vs-requested rule was stated explicitly in the prompt, twice, and
the model still inverted it. **A model this small does not reliably hold a
conditional distinction**, and restating it a third time was not going to work.

### The fix, and why it is in code rather than the prompt

Genuine notices carry anti-phishing markers a scammer has no reason to write:
*"do not share this OTP"*, *"we will never ask for your PIN"*, *"call the number
printed on your card"*. Combined with the absence of any request for a secret or
demand for payment, that is a reliable deterministic signal — and unlike a
prompt, it cannot drift. Those messages now resolve at Tier 0 and never reach
the model.

Two bugs surfaced while building that rule, both worth recording:

1. `"Tell me the 3 digit number behind the card"` matched the *"number printed on
   the back of your card"* marker. The scam and the reassurance share vocabulary,
   so the rule now requires an explicit call verb.
2. `"Do not share this OTP"` contains the substring *"share this OTP"*, so the
   secret-request guard fired on every genuine OTP notice — regex cannot see
   negation. Negated clauses are now stripped before the test.

Tier 0 now resolves 31.4% with **0 of 50 scams leaked**. The end-to-end numbers
above predate this change and need re-measuring.

## Earlier status (superseded)

**14 of 100 messages scored. The result is not yet meaningful, and the catch
rate below should not be quoted as an accuracy figure.**

Of the 14 completed, all 14 were scams and all 14 were correctly flagged
(confidence 0.98–0.99). That sounds strong and isn't: a classifier hardcoded to
answer `"scam"` for every input would score identically. **Zero legitimate
messages have been evaluated**, so the false-positive rate — the number that
decides whether this is usable — remains entirely unmeasured.

### Why it stalled

The Gemini free tier's **daily** request cap
(`GenerateRequestsPerDayPerProjectPerModel-FreeTier`) is far below what a
100-message evaluation needs, and its per-minute cap is under 30 RPM, so most
wall-clock time went into 429 backoff rather than useful calls. Completing this
evaluation requires the paid tier; the free tier cannot support it.

### Three harness bugs found and fixed along the way

1. **Results were only persisted at completion** — the first run lost ~33
   finished classifications when it was interrupted. Now written after every
   message, with resume-on-restart.
2. **`maxOutputTokens` was 512** — `gemini-flash-latest` is a thinking model
   whose internal reasoning counts against that budget, so responses came back
   truncated mid-JSON and every verdict silently degraded to the `unknown`
   fallback. Raised to 2048.
3. **The dataset was evaluated in authored order** (scams 1–50, legitimate
   51–100), meaning any interrupted run measured recall only and produced no
   false-positive signal at all. Evaluation order is now deterministically
   shuffled so a partial run stays label-balanced.
