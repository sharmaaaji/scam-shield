/**
 * Tier-1 classifier: the model call, for messages Tier 0 could not resolve.
 *
 * On-device only, via Chrome's built-in Gemini Nano (Prompt API). There is
 * deliberately no cloud provider and no API-key option:
 *
 *   - the message physically cannot leave the machine, so there is nothing to
 *     disclose, nothing to breach, and no data-processor role to take on;
 *   - the extension makes no network requests at all, so it needs no host
 *     permissions;
 *   - there is nothing for the user to configure or get wrong.
 *
 * The cost of that choice is real: a device that cannot run the model gets no
 * Tier-1 analysis whatsoever. We report that plainly rather than degrading into
 * something that looks like it is working when it is not.
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

  // Chrome has relocated this API more than once (window.ai.languageModel ->
  // self.ai.languageModel -> a top-level LanguageModel global), so resolve
  // whichever surface this build exposes rather than assuming one.
  function findLanguageModel() {
    if (typeof LanguageModel !== "undefined") return LanguageModel;
    if (typeof self !== "undefined" && self.ai && self.ai.languageModel) return self.ai.languageModel;
    if (typeof window !== "undefined" && window.ai && window.ai.languageModel) return window.ai.languageModel;
    return null;
  }

  /** Is Chrome's built-in model usable right now? */
  async function onDeviceAvailability() {
    const api = findLanguageModel();
    if (!api || typeof api.availability !== "function") return "unsupported";
    try {
      const state = await api.availability();
      // Older builds answered "readily"; normalise to the current vocabulary.
      return state === "readily" ? "available" : state;
    } catch (_) {
      return "unsupported";
    }
  }

  async function classifyOnDevice(text, signals, source) {
    const api = findLanguageModel();
    if (!api) throw new Error("Chrome's built-in AI is not available in this browser.");

    const session = await api.create({
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

  root.ScamShieldClassifier = {
    SYSTEM_PROMPT,
    RESPONSE_SCHEMA,
    buildUserPrompt,
    parseResponse,
    findLanguageModel,
    onDeviceAvailability,
    classifyOnDevice
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
