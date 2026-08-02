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

## Status

Not yet completed. The first full run reached ~33 of 100 messages before
exhausting the Gemini free tier's **daily** request quota
(`GenerateRequestsPerDayPerProjectPerModel-FreeTier`), and those partial results
were lost to a harness that only persisted output at completion. That flaw is
fixed (incremental writes + resume), but no accuracy numbers have been produced
yet, and none should be claimed until a full run lands.
