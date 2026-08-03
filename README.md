# ScamShield

A Chrome extension that flags likely scam and phishing messages in **Gmail** and
**WhatsApp Web** as they render — no copy-pasting, no manual checking.

**The extension makes no network requests at all.** Analysis runs entirely on-device
using Chrome's built-in Gemini Nano, and the manifest requests **zero permissions** —
no storage, no host permissions, nothing beyond running on the two supported sites.
There is nothing to configure and no API key to supply.

## Why it works this way

A tool that requires you to paste a message you're already suspicious of only helps
people who are already suspicious. The people most at risk are the ones who don't
get suspicious in time — so the check has to happen before you'd read the message
closely, not after you've decided to investigate it.

## Architecture

Two tiers, because most messages don't need a language model at all.

```
message renders in Gmail / WhatsApp Web
        │
        ▼
  MutationObserver (debounced) picks it up
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ TIER 0 — shared/triage.js   deterministic, no model     │
│                                                          │
│ Extracts: URLs · phone numbers · money · urgency ·      │
│ credential/OTP requests · payment actions · link        │
│ references · chain mechanics · identity claims ·        │
│ threats · reward framing · sender metadata              │
│                                                          │
│ No signal at all  →  "safe", done. No model call.       │
│ Any signal        →  escalate                            │
└─────────────────────────────────────────────────────────┘
        │ escalated only
        ▼
┌─────────────────────────────────────────────────────────┐
│ TIER 1 — shared/classifier.js                            │
│ Chrome's built-in Gemini Nano, on-device                 │
│ JSON-schema-constrained verdict. No network.             │
└─────────────────────────────────────────────────────────┘
        │
        ▼
  warning rendered — only for non-safe verdicts
```

### Where the warning actually appears

Designed for someone non-technical, possibly elderly — the person most likely to
be targeted and least likely to decode a security warning.

- **Gmail inbox list** — flagged rows are tinted with a coloured marker, so the
  warning arrives *before* the message is opened. That's the moment that matters;
  a warning shown only after opening arrives after they've started engaging.
- **Opened message / WhatsApp chat** — a full-width panel above the message,
  leading with the action in large type: *"Do not click the link. Do not pay."*
  followed by a plain reason and up to four plain-English red flags.

Nothing important is hidden behind a hover — older users don't discover tooltips.
The model is instructed to avoid all security jargon ("phishing", "credential",
"domain", "spoofed") and to give a safe alternative that doesn't depend on
anything inside the message: open your bank's own app, call the number printed on
your card, ring your uncle on the number you already have.

The advice must be sound **whether or not** the message is really a scam, so being
wrong still leaves the reader safe.

**The fast path may only ever return "safe".** It can never call something a scam on
its own — every warning you see came from the model, never from Tier 0. Being wrong
by escalating costs one inference call; being wrong by clearing a scam costs the user
money.

Messages are only classified once they scroll into view. An inbox may hold 50+ rows
while a screen shows a dozen, and on a single on-device model every off-screen row
would cost an inference the reader never benefits from. Tier-1 calls are also queued
and run one at a time, because firing dozens concurrently at one local model starves
them all.

### Measured on the 100-message test set

| | |
|---|---|
| Resolved with no model call | **27%** |
| Scams wrongly cleared by the fast path | **0 / 50** |

The first implementation leaked **2 of 50 scams**. Both shared one root cause:
messages that *refer* to a link without containing a parseable URL — *"download the
APK from this link"*, *"the migration portal below"* — because in real mail the URL
lives in an anchor's `href`, not in `innerText`. Adding link-reference detection
brought leakage to zero, costing 4 points of bypass rate. That trade is correct.

Reproduce it offline, free, in about a second:

```bash
osascript -l JavaScript eval/triage_eval.js
```

## Gmail and WhatsApp are handled differently

Both are supported, but the useful metadata differs, so each has its own adapter.

**Gmail** — the sender is rendered as `<span email="..." name="...">`, which exposes
the real address even when the UI shows only a friendly name. That enables
**brand/domain mismatch** detection: a display name of *"HDFC Bank Support"* arriving
from `gmail.com` is the single strongest cheap phishing tell available in the DOM.
A matching domain (`hdfcbank.com`) produces no signal.

**WhatsApp Web** — there are no domains, so the equivalent signal is whether the chat
header shows a **name or a raw phone number**. An unsaved number is how
family-impersonation scams announce themselves, and combined with an identity claim
(*"this is your uncle, I've changed my number"*) it's the only thing that catches
them — those messages contain no link, no amount, and no urgency.

## The `unverified-identity` verdict

Some messages genuinely cannot be classified from their text. *"Hi beta, this is your
uncle, I've changed my number"* is either your uncle or the opening move of a scam,
and nothing in the sentence distinguishes them.

Rather than guess, these get a fourth verdict and advice that is **correct either
way**: verify through a channel you already trust before acting on any request. If
it's really your uncle, that costs a phone call. If it isn't, it defeats the entire
attack.

## Setup

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select `extension/`.
2. Click the extension icon — it reports whether the on-device model is ready.
3. Open Gmail or WhatsApp Web. That's the whole setup.

Requires **Chrome 138+** on desktop, ~22 GB free disk, and either >4 GB VRAM or
16 GB RAM with 4+ cores. If the device can't meet that, the extension says so in its
popup and does nothing — rather than silently appearing to protect you.

## Limitations — stated rather than hidden

- **DOM selectors are unofficial.** Neither Gmail nor WhatsApp Web offers an extension
  API for reading messages. `div.a3s` and `div.message-in` have been stable a long
  time but are not contracts. Each is isolated to one adapter file so a redesign
  breaks one small thing.
- **Desktop only, with a hardware floor.** Chrome for Android and iOS don't support
  the built-in model, and WhatsApp is overwhelmingly a phone app — so this covers
  WhatsApp *Web*, a minority of the real attack surface. There is an uncomfortable
  irony in the hardware requirement too: the people most exposed to scams often run
  the cheapest machines, which are exactly the ones that can't run a local model.
  Choosing on-device buys absolute privacy and pays for it in reach.
- **Nano is a small model.** Its accuracy versus cloud Gemini on this task has not yet
  been measured; see [`eval/`](eval/) for the harness and the current status.
- **It advises, never acts.** No auto-delete, no auto-block, no auto-reply. Deliberate.
- **It fails quiet, never reassuring.** If classification errors out, no badge appears.
  Showing "safe" because the classifier broke would be worse than showing nothing.
- **Some scams are structurally uncatchable here** — a spoofed saved contact, or a
  message that just says "hey, call me".

## Repository layout

```
extension/
├── shared/triage.js      Tier 0 — deterministic, measured, no model
├── shared/classifier.js  Tier 1 — on-device Gemini Nano only
├── shared/scanner.js     shared pipeline: observe → triage → classify → badge
├── content-gmail.js      Gmail adapter (brand/domain mismatch)
├── content-whatsapp.js   WhatsApp adapter (unsaved sender, first contact)
└── popup.html/js         status only — there is nothing to configure

eval/
├── dataset.json          100 labeled messages, 25 deliberate scam-lookalikes
├── triage_eval.js        Tier-0 evaluation — offline, free, instant
└── run_eval.py           full pipeline evaluation (needs a model)

Api/                      optional self-hosted backend; NOT used by the extension
```

`Api/` remains for local development and self-hosting. The published extension never
calls it — that's what keeps user messages out of anyone else's hands.
