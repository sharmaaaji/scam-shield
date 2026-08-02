#!/usr/bin/env python3
"""
Evaluation harness for the ScamShield classifier.

Ground truth is binary (scam / legit); the classifier returns three verdicts
(scam / suspicious / safe). Since the extension shows a badge for BOTH "scam"
and "suspicious", the primary metrics treat "badge shown" as the positive
prediction - that is what a user actually experiences.
"""

import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from collections import defaultdict

API_URL = "http://localhost:5090/api/analyze"
DELAY_SECONDS = 2.0          # pacing for the Gemini free tier
MAX_RETRIES = 5

HERE = Path(__file__).parent


def classify(text: str, source: str) -> dict:
    payload = json.dumps({"text": text, "source": source}).encode()
    req = urllib.request.Request(
        API_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 503) and attempt < MAX_RETRIES:
                backoff = min(60, 5 * (2 ** attempt))
                print(f"    (HTTP {e.code}, retrying in {backoff}s)")
                time.sleep(backoff)
                continue
            raise
        except Exception:
            if attempt < MAX_RETRIES:
                time.sleep(5 * attempt)
                continue
            raise
    raise RuntimeError("exhausted retries")


def main():
    dataset = json.loads((HERE / "dataset.json").read_text())
    results_path = HERE / "results.json"

    # Resume support: a run that dies partway (rate limits, Ctrl-C) keeps every
    # result it already paid for. Re-running picks up where it left off.
    results = []
    done_ids = set()
    if results_path.exists():
        results = json.loads(results_path.read_text())
        done_ids = {r["id"] for r in results if r.get("verdict") not in (None, "error")}
        if done_ids:
            print(f"Resuming: {len(done_ids)} messages already classified.\n")

    todo = [c for c in dataset if c["id"] not in done_ids]
    print(f"Classifying {len(todo)} of {len(dataset)} messages...\n", flush=True)

    consecutive_quota_errors = 0

    for i, case in enumerate(todo, 1):
        try:
            out = classify(case["text"], case["source"])
            verdict = out.get("verdict", "error")
            confidence = out.get("confidence", 0.0)
            reasoning = out.get("reasoning", "")
            red_flags = out.get("redFlags", [])
            consecutive_quota_errors = 0
        except Exception as e:
            verdict, confidence, reasoning, red_flags = "error", 0.0, str(e), []
            if "429" in str(e):
                consecutive_quota_errors += 1

        results = [r for r in results if r["id"] != case["id"]]
        results.append({**case, "verdict": verdict, "confidence": confidence,
                        "reasoning": reasoning, "redFlags": red_flags})

        # Write after EVERY message - a killed run must never lose completed work.
        results_path.write_text(json.dumps(results, indent=2))

        flagged = verdict in ("scam", "suspicious")
        mark = "ok " if flagged == (case["label"] == "scam") else "MISS"
        print(f"[{i:3}/{len(todo)}] {mark} id={case['id']:3} "
              f"truth={case['label']:5} pred={verdict:10} conf={confidence:.2f}",
              flush=True)

        # Daily quota exhaustion is not something backoff can fix - stop early
        # and keep what we have rather than burning an hour on doomed retries.
        if consecutive_quota_errors >= 3:
            print("\nAborting: 3 consecutive quota failures (daily cap likely "
                  "exhausted). Completed results are saved; re-run to resume.",
                  flush=True)
            break

        if i < len(todo):
            time.sleep(DELAY_SECONDS)

    report([r for r in results if r.get("verdict") != "error"])


def report(results):
    total = len(results)
    errors = [r for r in results if r["verdict"] == "error"]
    scored = [r for r in results if r["verdict"] != "error"]

    # Primary framing: a badge is shown for scam OR suspicious.
    tp = [r for r in scored if r["label"] == "scam" and r["verdict"] in ("scam", "suspicious")]
    fn = [r for r in scored if r["label"] == "scam" and r["verdict"] == "safe"]
    fp = [r for r in scored if r["label"] == "legit" and r["verdict"] in ("scam", "suspicious")]
    tn = [r for r in scored if r["label"] == "legit" and r["verdict"] == "safe"]

    def pct(n, d):
        return f"{(100.0 * n / d):.1f}%" if d else "n/a"

    print("\n" + "=" * 66)
    print("RESULTS  (positive = badge shown, i.e. verdict scam OR suspicious)")
    print("=" * 66)
    print(f"Scored: {len(scored)}/{total}   Errors: {len(errors)}")
    print()
    print(f"  True positives  (scam  -> flagged): {len(tp):3}")
    print(f"  False negatives (scam  -> safe)   : {len(fn):3}   <- missed scams")
    print(f"  False positives (legit -> flagged): {len(fp):3}   <- false alarms")
    print(f"  True negatives  (legit -> safe)   : {len(tn):3}")
    print()

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (len(tp) + len(tn)) / len(scored) if scored else 0

    print(f"  Accuracy            : {accuracy:.3f}")
    print(f"  Precision           : {precision:.3f}")
    print(f"  Recall (catch rate) : {recall:.3f}")
    print(f"  F1                  : {f1:.3f}")
    print(f"  False positive rate : {pct(len(fp), len(fp) + len(tn))}")
    print(f"  Miss rate           : {pct(len(fn), len(tp) + len(fn))}")

    # Hard negatives are the trust-critical slice: legitimate messages that
    # deliberately look scammy (real bank alerts, OTPs, urgent promos).
    hard = [r for r in scored if r["category"].startswith("HARD-")]
    hard_fp = [r for r in hard if r["verdict"] in ("scam", "suspicious")]
    print()
    print(f"  HARD negatives (realistic scam-lookalikes): {len(hard)}")
    print(f"    falsely flagged: {len(hard_fp)}  ({pct(len(hard_fp), len(hard))})")

    # Stricter framing: only a "scam" verdict counts as an accusation.
    strict_fp = [r for r in scored if r["label"] == "legit" and r["verdict"] == "scam"]
    print(f"\n  Legit messages called outright 'scam': {len(strict_fp)}")

    if fn:
        print("\n--- MISSED SCAMS ---")
        for r in fn:
            print(f"  id={r['id']} [{r['category']}] conf={r['confidence']:.2f}")
            print(f"     {r['text'][:110]}...")
            print(f"     reasoning: {r['reasoning'][:150]}")

    if fp:
        print("\n--- FALSE ALARMS ---")
        for r in fp:
            print(f"  id={r['id']} [{r['category']}] pred={r['verdict']} conf={r['confidence']:.2f}")
            print(f"     {r['text'][:110]}...")
            print(f"     reasoning: {r['reasoning'][:150]}")

    if errors:
        print("\n--- ERRORS ---")
        for r in errors:
            print(f"  id={r['id']}: {r['reasoning'][:120]}")

    by_cat = defaultdict(lambda: [0, 0])
    for r in scored:
        flagged = r["verdict"] in ("scam", "suspicious")
        correct = flagged == (r["label"] == "scam")
        by_cat[r["category"]][1] += 1
        if correct:
            by_cat[r["category"]][0] += 1
    wrong_cats = {k: v for k, v in by_cat.items() if v[0] < v[1]}
    if wrong_cats:
        print("\n--- CATEGORIES WITH FAILURES ---")
        for cat, (ok, tot) in sorted(wrong_cats.items()):
            print(f"  {cat}: {ok}/{tot}")

    print("\nFull per-message output written to eval/results.json")


if __name__ == "__main__":
    main()
