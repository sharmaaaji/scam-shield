/**
 * Tier-1 classifier: the model call, for messages Tier 0 could not resolve.
 *
 * Two providers, in preference order:
 *   1. on-device  - Chrome's built-in Gemini Nano (Prompt API). No key, no cost,
 *                   no network, and the message never leaves the machine.
 *   2. byok-cloud - the user's own Gemini API key, called directly from the
 *                   extension. Still no server of ours in the path.
 *
 * There is deliberately no hosted-backend option. Routing other people's private
 * mail through a server we operate would make us a data processor for their
 * messages, which is the thing this design exists to avoid.
 */
(function (root) {
  "use strict";

  const SYSTEM_PROMPT = [
    "You judge whether a single personal message (email or chat) is a scam.",
    "",
    "You are given the message text plus signals already extracted by deterministic code.",
    "Weigh the message as a whole. A link, an urgent tone, a rupee amount, or an OTP",
    "does NOT by itself make something a scam - legitimate banks, couriers and services",
    "send all of those every day.",
    "",
    "The distinction that matters most:",
    "- An OTP or code being DELIVERED TO the recipient is normal and legitimate.",
    "- An OTP, PIN, CVV or password being REQUESTED FROM the recipient is always a scam.",
    "  No real bank, company or government body ever asks for these.",
    "",
    "Verdicts:",
    '  "scam"       - clear fraud indicators; recommend not engaging.',
    '  "suspicious" - genuinely ambiguous, or pressure tactics without proof of fraud.',
    '  "unverified-identity" - the sender CLAIMS a relationship or authority',
    "                 (family member, bank, HR, government) that cannot be verified from",
    "                 the message, typically with a new/unknown number. Use this instead",
    "                 of \"scam\" when the message asks for nothing yet: it may well be",
    "                 genuine, and the right advice - verify through a previously known",
    "                 channel - is correct either way.",
    '  "safe"       - ordinary legitimate message.',
    "",
    "recommendedAction must be useful whether or not the message turns out to be a scam.",
    "Never tell the user to click a link or call a number taken from the message itself."
  ].join("\n");

  const RESPONSE_SCHEMA = {
    type: "object",
    properties: {
      verdict: { type: "string", enum: ["scam", "suspicious", "unverified-identity", "safe"] },
      confidence: { type: "number", minimum: 0, maximum: 1 },
      redFlags: { type: "array", items: { type: "string" } },
      reasoning: { type: "string" },
      recommendedAction: { type: "string" }
    },
    required: ["verdict", "confidence", "redFlags", "reasoning", "recommendedAction"]
  };

  function buildUserPrompt(text, signals, source) {
    const list = (arr) => (arr && arr.length ? arr.join(", ") : "none");
    return [
      `SOURCE: ${source || "unknown"}`,
      "MESSAGE:",
      text,
      "",
      "DETERMINISTIC SIGNALS:",
      `- URLs: ${list(signals.urls)}`,
      `- Phone numbers: ${list(signals.phoneNumbers)}`,
      `- Money mentions: ${list(signals.monetaryMentions)}`,
      `- Urgency language: ${signals.hasUrgency}`,
      `- Requests a credential/OTP/remote access: ${signals.hasCredentialRequest}`,
      `- Requests a payment action: ${signals.hasPaymentAction}`,
      `- Refers to a link: ${signals.hasLinkReference}`,
      `- Chain-message mechanics: ${signals.hasChainRequest}`,
      `- Claims an identity or relationship: ${signals.hasIdentityClaim}`,
      `- Threats/legal pressure: ${signals.hasThreat}`,
      `- Prize/reward framing: ${signals.hasReward}`,
      `- Sender not in contacts: ${signals.senderIsUnknown}`,
      `- First message from this sender: ${signals.isFirstMessage}`,
      `- Display name claims a brand its domain does not match: ${signals.brandDomainMismatch}`
    ].join("\n");
  }

  function parseResponse(raw) {
    const start = raw.indexOf("{");
    const end = raw.lastIndexOf("}");
    const json = start >= 0 && end > start ? raw.slice(start, end + 1) : raw;
    const parsed = JSON.parse(json);
    return {
      verdict: parsed.verdict || "unknown",
      confidence: typeof parsed.confidence === "number" ? parsed.confidence : 0.5,
      redFlags: Array.isArray(parsed.redFlags) ? parsed.redFlags : [],
      reasoning: parsed.reasoning || "",
      recommendedAction: parsed.recommendedAction || ""
    };
  }

  /** Is Chrome's built-in model usable right now? */
  async function onDeviceAvailability() {
    if (typeof LanguageModel === "undefined") return "unsupported";
    try {
      return await LanguageModel.availability();
    } catch (_) {
      return "unsupported";
    }
  }

  async function classifyOnDevice(text, signals, source) {
    const session = await LanguageModel.create({
      initialPrompts: [{ role: "system", content: SYSTEM_PROMPT }],
      temperature: 0.1,
      topK: 3
    });
    try {
      const raw = await session.prompt(buildUserPrompt(text, signals, source), {
        responseConstraint: RESPONSE_SCHEMA
      });
      return { ...parseResponse(raw), provider: "on-device" };
    } finally {
      session.destroy();
    }
  }

  async function classifyByokCloud(text, signals, source, apiKey, model) {
    const url =
      "https://generativelanguage.googleapis.com/v1beta/models/" +
      (model || "gemini-flash-latest") +
      ":generateContent?key=" + encodeURIComponent(apiKey);

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents: [{ role: "user", parts: [{ text: buildUserPrompt(text, signals, source) }] }],
        // Flash models reason internally and those tokens count against this
        // budget; too low a value truncates the JSON mid-object.
        generationConfig: {
          maxOutputTokens: 2048,
          responseMimeType: "application/json",
          responseSchema: RESPONSE_SCHEMA
        }
      })
    });

    if (!response.ok) throw new Error("Gemini API error " + response.status);
    const body = await response.json();
    const raw = body?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    return { ...parseResponse(raw), provider: "byok-cloud" };
  }

  root.ScamShieldClassifier = {
    SYSTEM_PROMPT,
    RESPONSE_SCHEMA,
    buildUserPrompt,
    parseResponse,
    onDeviceAvailability,
    classifyOnDevice,
    classifyByokCloud
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
