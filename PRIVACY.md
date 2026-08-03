# ScamShield Privacy Policy

_Last updated: 4 August 2026_

## The short version

ScamShield operates no server. Your messages are never transmitted to the developer,
and no analytics, telemetry, or usage data is collected.

## What the extension reads

On `mail.google.com` and `web.whatsapp.com` only, it reads the text of messages
displayed on screen, plus limited sender metadata (the sender's email domain on
Gmail; whether a chat is with a saved contact on WhatsApp Web). It reads nothing on
any other site.

## Where that text goes

Most messages are analysed entirely locally by pattern matching and never leave your
device at all.

Messages that show a potential risk signal are analysed by a language model, using
whichever mode you selected:

**On-device (default).** Chrome's built-in Gemini Nano runs the analysis locally.
The message does not leave your computer and no network request is made.

**Your own API key (optional).** If you supply a Gemini API key, the message is sent
from your browser directly to Google's Gemini API using your key. It does not pass
through any server operated by the developer. That request is governed by
[Google's Gemini API terms](https://ai.google.dev/gemini-api/terms) and your own
account's data settings. Note that Google's *unpaid* tier permits Google to use
submitted content to improve its products and to have it reviewed by humans; the paid
tier does not. Choose accordingly.

## What is stored

Only your own settings — the selected mode and, if you entered one, your API key —
held in Chrome's local extension storage on your device. Your API key is never
transmitted anywhere except to Google, in requests you initiate.

## What is not done

No message content is stored, logged, or retained after analysis. Nothing is sent to
the developer. No third-party analytics, trackers, or advertising SDKs are included.
No data is sold or shared with anyone.

## Removing your data

Uninstalling the extension deletes all stored settings. Clearing them without
uninstalling is possible from the extension's popup.

## Limitations you should know about

ScamShield is an advisory tool. It can be wrong in both directions — flagging
legitimate messages and missing real scams. It never deletes, blocks, moves, or
replies to anything. All decisions remain yours.

## Contact

Issues and questions: https://github.com/sharmaaaji/scam-shield/issues
