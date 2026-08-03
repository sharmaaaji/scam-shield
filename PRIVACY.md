# ScamShield Privacy Policy

_Last updated: 4 August 2026_

## The short version

ScamShield makes no network requests. Nothing you read is transmitted anywhere —
not to the developer, not to Google, not to anyone. All analysis happens on your
own device.

The extension requests **no Chrome permissions at all** beyond running on the two
sites it supports.

## What it reads

On `mail.google.com` and `web.whatsapp.com` only, it reads the text of messages
displayed on screen, plus limited sender metadata (the sender's email domain on
Gmail; whether a chat is with a saved contact on WhatsApp Web). It reads nothing on
any other website.

## What happens to that text

Most messages are resolved by local pattern matching alone.

The rest are analysed by Chrome's built-in on-device AI model (Gemini Nano), which
runs locally on your computer. No network request is made, and the message never
leaves your device.

If your device cannot run the on-device model, no analysis happens and no badges
appear. The extension's popup states this plainly rather than appearing to work.

## What is stored

Nothing. There are no settings, no accounts, no API keys, and no stored message
content or history.

## What is not done

No data is collected, logged, retained, transmitted, sold, or shared. There are no
analytics, no telemetry, no trackers, and no third-party SDKs of any kind.

## Removing your data

There is no data to remove. Uninstalling the extension removes it completely.

## Limitations you should know about

ScamShield is advisory. It can be wrong in both directions — flagging legitimate
messages, and missing real scams. It never deletes, blocks, moves, or replies to
anything. Every decision remains yours.

## Contact

Issues and questions: https://github.com/sharmaaaji/scam-shield/issues
