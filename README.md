# ScamShield

A browser extension that automatically flags likely scam/phishing messages in
**Gmail** and **WhatsApp Web** — no copy-pasting into an app, no manually checking
a message you're already suspicious of. It scans messages as they render and
overlays a warning badge directly on the ones worth a second look.

## Why this exists

Real scam-detection tools (Google Messages' spam protection, Truecaller, Apple's
Message Filtering extension) all work the same way: the message is classified
*before* you'd naturally read it closely, not after you've already decided to
investigate it yourself. A tool that requires you to copy-paste a message you're
suspicious of is solving the problem for people who are already suspicious — the
people who most need this are the ones who *aren't* suspicious yet.

## How it works

```
Gmail / WhatsApp Web page
        │
        │  MutationObserver detects a new message rendering
        ▼
Content script extracts the message text
        │
        ▼
Background service worker calls the backend API
        │
        ▼
Api/  →  MessageSignalExtractor (deterministic regex: URLs, phone numbers,
         money mentions, urgency phrases — plain code, no LLM)
        │
        ▼
      ScamAnalysisService → Gemini (LLM judges the message using the raw text
      AND the extracted signals together, returns structured JSON: verdict,
      confidence, red flags, reasoning, recommended action)
        │
        ▼
Content script overlays a badge on the message (only for "suspicious"/"scam" -
stays silent on "safe" messages to avoid alert fatigue)
```

Same split used in [IncidentIQ](https://github.com/sharmaaaji/incident-iq):
deterministic code does what deterministic code is good at (extracting URLs,
phone numbers, urgency phrases), and the LLM is reserved for the actual judgment
call — a URL or urgent tone alone doesn't prove a scam, so the model reasons over
the message as a whole rather than triggering off any single signal.

## Project layout

```
Api/                          ASP.NET Core backend (the classifier)
├── Controllers/AnalyzeController.cs   POST /api/analyze
├── Services/
│   ├── MessageSignalExtractor.cs      regex-based URL/phone/money/urgency extraction
│   ├── ILlmClient.cs / GeminiClient.cs  Gemini API client
│   └── ScamAnalysisService.cs         builds the prompt, parses structured JSON
└── Models/Dtos.cs

extension/                    Chrome extension (Manifest V3)
├── manifest.json
├── background.js             calls the API, caches results by message-text hash
├── content-gmail.js          watches Gmail's message body DOM
├── content-whatsapp.js       watches WhatsApp Web's incoming-message DOM
├── styles.css                badge styling
└── popup.html / popup.js     lets you point the extension at a different API URL

eval/                         accuracy evaluation (see eval/README.md)
├── dataset.json              100 labeled messages, incl. 25 scam-lookalike negatives
└── run_eval.py               harness: precision/recall/false-positive breakdown
```

## Accuracy

A 100-message labeled test set lives in [`eval/`](eval/), built so that 25 of the
50 legitimate messages are deliberate scam-lookalikes (real bank OTPs, transaction
alerts, delivery links, urgent promos) — because the number that decides whether
this is usable isn't the catch rate, it's the false-alarm rate on legitimate mail.

**No accuracy numbers are claimed yet.** The first run exhausted the Gemini free
tier's daily quota partway through; see [`eval/README.md`](eval/README.md) for
methodology, the known bias in an author-written test set, and current status.

## Setup

### 1. Run the backend

```bash
cd Api
dotnet user-secrets set "Gemini:ApiKey" "your-gemini-api-key"
dotnet run --urls http://localhost:5090
```

Get a free Gemini key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey).

### 2. Load the extension

1. Open `chrome://extensions` in Chrome.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `extension/` folder.
4. Open Gmail or WhatsApp Web — the extension calls `http://localhost:5090` by
   default. If you deploy the backend elsewhere, click the extension icon and
   update the API URL in the popup.

## Known limitations (worth knowing, not hiding)

- **DOM scraping is inherently fragile.** Neither Gmail nor WhatsApp Web offers
  an official way for a browser extension to read message content — this relies
  on unofficial, undocumented CSS classes (`div.a3s` for Gmail, `div.message-in`
  for WhatsApp Web) that have been stable for a long time but could break if
  either product changes its markup. A production version of this for Gmail
  specifically could move to the official Gmail API (OAuth, readonly scope)
  for a more robust integration; WhatsApp has no equivalent official API for
  personal accounts.
- **No verdict is ever certain.** The tool flags *likely* scams for a human to
  weigh, it doesn't auto-delete or block anything.
- **Every message sent to the backend goes to a third-party LLM (Gemini).**
  Fine for personal use on your own messages; not something to point at
  anyone else's inbox without their knowledge.
