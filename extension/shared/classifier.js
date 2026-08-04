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

  // Two prompts, because the on-device context window is not knowable in advance
  // and differs by Chrome build and hardware. The full prompt is used whenever it
  // fits; if the model rejects it with QuotaExceededError we fall back to this
  // compressed one rather than failing the message outright.
  //
  // The compact version keeps only the rules that actually change verdicts, and
  // deliberately does not describe the JSON shape - that is enforced by
  // responseConstraint, so restating it would waste scarce budget.
  const SYSTEM_PROMPT_COMPACT = [
    "Decide if this message is a scam. Most are legitimate: answer safe unless there is",
    "clear fraud evidence. Missing context is not evidence.",
    "Safe: receipts for payments already made, order and delivery confirmations, password",
    "resets, account activation, email verification, recruiter mail, newsletters -",
    "especially when the sender domain matches the company named.",
    "Scam: asks you for an OTP, PIN, CVV or password; demands payment to avoid a",
    "consequence; prize or refund needing a fee; brand whose sender domain does not match;",
    "stranger asking for money.",
    "A code sent TO you is normal; asked FROM you is fraud. A completed payment is a",
    "receipt, not a demand. Use unverified-identity only for a person claiming a",
    "relationship you cannot check, never for company mail. Plain words, no jargon."
  ].join(" ");

  const SYSTEM_PROMPT_FULL = [
    "You judge whether a single personal message (email or chat) is a scam.",
    "",
    "You are given the message text plus signals already extracted by deterministic code.",
    "Weigh the message as a whole. A link, an urgent tone, a rupee amount, or an OTP",
    "does NOT by itself make something a scam - legitimate banks, couriers and services",
    "send all of those every day.",
    "",
    "Two distinctions matter more than anything else. Get these right:",
    "",
    "1. DELIVERED vs REQUESTED.",
    "   An OTP or code being DELIVERED TO the recipient is normal and legitimate.",
    "   An OTP, PIN, CVV or password being REQUESTED FROM the recipient is always a scam.",
    "   No real bank, company or government body ever asks for these.",
    "",
    "2. A RECEIPT vs A DEMAND.",
    "   A message reporting that a payment ALREADY HAPPENED - \"your payment was",
    "   successfully processed\", \"INR 2000 paid\", \"here is your invoice\", \"your order is",
    "   confirmed\" - is a receipt. Receipts are among the most common legitimate emails",
    "   there are, and they are SAFE. Past tense and a completed amount are not a request.",
    "   Only a message telling the recipient they must PAY, or must act to avoid a",
    "   consequence, is a demand - and only demands can be scams of this kind.",
    "   Do not describe a receipt as \"asking you to confirm a payment\". It is not.",
    "",
    "SENDER DOMAIN IS YOUR STRONGEST EVIDENCE:",
    "If 'sender domain matches the organisation it claims to be' is true, the mail really",
    "was sent from that company's own domain. Faking that requires controlling the real",
    "domain, so treat it as strong evidence of legitimacy. Routine transactional mail from",
    "an aligned domain - activating an account, verifying an email address, resetting a",
    "password, receipts, security notifications - is SAFE. Asking someone to confirm their",
    "email address is a normal part of signing up for a service, not a scam.",
    "Only when the domain does NOT match the claimed organisation does a request to click,",
    "verify or pay become a real warning sign.",
    "",
    "DEFAULT TO SAFE. Most mail is legitimate. Ordinary business correspondence is safe",
    "even when it mentions money, links, deadlines or accounts. All of the following are",
    "SAFE unless they contain a specific fraud indicator:",
    "  - payment receipts, invoices and order confirmations",
    "  - job application acknowledgements and recruiter mail",
    "  - newsletters, marketing offers and sale deadlines",
    "  - account/security notifications from a company's own domain",
    "  - delivery and booking confirmations",
    "",
    "Verdicts:",
    '  "scam"       - clear, specific fraud indicators. Not a hunch.',
    '  "suspicious" - real pressure tactics or a concrete inconsistency, but short of',
    "                 proof. Do NOT use this merely because context is missing or a",
    "                 message mentions money. Uncertainty alone is \"safe\".",
    '  "unverified-identity" - ONLY for a person claiming a personal relationship or',
    "                 authority that cannot be checked (a relative with a new number,",
    "                 someone claiming to be from your bank or the police), where the",
    "                 message asks for nothing yet. NEVER use this for automated mail",
    "                 from a company - no-reply addresses, notifications, receipts.",
    '  "safe"       - ordinary legitimate message. This should be your most common answer.',
    "",
    "WHO IS READING YOUR OUTPUT:",
    "Assume the reader is not technical and may be elderly. They are the person most",
    "likely to be targeted and least likely to recognise jargon. Therefore:",
    "",
    "- Write at the reading level of a short newspaper notice. Short, direct sentences.",
    "- Never use the words phishing, credential, domain, malicious, verify (as jargon),",
    "  legitimate, spoofed, or any security terminology. Say 'fake', 'not real',",
    "  'pretending to be', 'trying to steal your money'.",
    "- recommendedAction is the most important field. Lead with the concrete thing NOT",
    "  to do ('Do not click the link. Do not pay.'), then give a safe alternative that",
    "  does not depend on anything in the message ('Open your bank's own app', 'Call the",
    "  number printed on your card', 'Ring your uncle on the number you already have').",
    "  Never tell them to click a link or call a number taken from the message itself.",
    "- reasoning is one or two plain sentences explaining, in everyday words, what the",
    "  sender is trying to do.",
    "- redFlags: at most 4 items, each a short plain-English phrase a non-technical",
    "  person immediately understands, describing something you can actually point to in",
    "  THIS message. Never carry over a stock phrase about banks, accounts or passwords",
    "  that does not apply here. If the message has no real warning signs, return an",
    "  empty list rather than inventing one.",
    "",
    "recommendedAction must be sound advice whether or not the message turns out to be",
    "a scam - so that being wrong still leaves the reader safe."
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

  // Only true signals are sent. Listing a dozen "false" lines told the model
  // nothing while consuming a context window that cannot spare it.
  function buildUserPromptCompact(text, signals, source) {
    const notes = [];
    if (signals.urls && signals.urls.length) notes.push("links: " + signals.urls.join(" "));
    if (signals.hasCredentialRequest) notes.push("asks for a code/password/remote access");
    if (signals.hasPaymentAction) notes.push("payment action mentioned");
    if (signals.hasUrgency) notes.push("urgency language");
    if (signals.hasThreat) notes.push("threats or legal pressure");
    if (signals.hasReward) notes.push("prize/reward framing");
    if (signals.hasChainRequest) notes.push("asks to forward to others");
    if (signals.hasIdentityClaim) notes.push("claims an identity or relationship");
    if (signals.brandDomainMismatch) notes.push("SENDER DOMAIN DOES NOT MATCH THE BRAND CLAIMED");
    if (signals.senderDomainAligned === true) notes.push("sender domain matches the company named");
    if (signals.senderIsUnknown) notes.push("sender not in contacts");

    const preview = source === "gmail-inbox"
      ? "This is only a subject and truncated preview, not the full message. Judge safe unless the fragment itself shows fraud.\n"
      : "";

    // Nano's whole context is roughly 1800 characters, shared with the system
    // prompt and the response. Scam signals almost always appear near the top of
    // a message, so the opening is what gets kept.
    const body = text.length > 600 ? text.slice(0, 600) + " […]" : text;

    return preview + "MESSAGE:\n" + body +
      (notes.length ? "\n\nNOTED: " + notes.join("; ") : "");
  }

  function buildUserPromptFull(text, signals, source) {
    const list = (arr) => (arr && arr.length ? arr.join(", ") : "none");

    // A list row is a sender line, a subject and a truncated snippet - far less
    // than a full message. Without saying so, the model treats missing context
    // as suspicious and flags ordinary receipts and confirmations.
    const preview = source === "gmail-inbox";
    const framing = preview
      ? [
          "INPUT TYPE: inbox list preview - sender, subject and a TRUNCATED snippet only.",
          "You are seeing a fragment, not the whole message. Absence of detail is NOT",
          "evidence of anything. Answer \"safe\" unless the fragment itself contains clear",
          "evidence of fraud. A false alarm here is worse than a miss: it appears next to",
          "ordinary mail and teaches the reader to ignore all warnings, including real ones."
        ]
      : ["INPUT TYPE: full message body."];

    return [
      `SOURCE: ${source || "unknown"}`,
      ...framing,
      "",
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
      `- Display name claims a brand its domain does NOT match: ${signals.brandDomainMismatch}`,
      `- Sender domain matches the organisation it claims to be: ` +
        (signals.senderDomainAligned === null
          ? "unknown (generic sender name - do NOT hold this against the message)"
          : String(signals.senderDomainAligned))
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

  // Creating a session per message is expensive - it re-primes the system
  // prompt every time. Build one base session and clone it per classification,
  // which is the documented pattern and keeps each request's context isolated
  // so one message can never influence the verdict on the next.
  // One base session per prompt variant, cloned per classification.
  const baseSessions = { full: null, compact: null };

  function getBaseSession(variant) {
    if (!baseSessions[variant]) {
      const api = findLanguageModel();
      if (!api) return Promise.reject(new Error("Chrome's built-in AI is not available."));
      const system = variant === "full" ? SYSTEM_PROMPT_FULL : SYSTEM_PROMPT_COMPACT;
      baseSessions[variant] = api
        .create({
          initialPrompts: [{ role: "system", content: system }],
          // Chrome warns that omitting this degrades output quality and skips
          // its output-safety attestation.
          outputLanguage: "en",
          temperature: 0.1,
          topK: 3
        })
        .catch((err) => {
          baseSessions[variant] = null; // allow a later retry
          throw err;
        });
    }
    return baseSessions[variant];
  }

  function isQuotaError(err) {
    return err && (err.name === "QuotaExceededError" || /too large/i.test(err.message || ""));
  }

  // Once the full prompt has been rejected on this device, stop paying the cost
  // of trying it on every subsequent message.
  let fullPromptFits = true;

  async function attempt(variant, text, signals, source) {
    const base = await getBaseSession(variant);
    const session = typeof base.clone === "function" ? await base.clone() : base;
    const build = variant === "full" ? buildUserPromptFull : buildUserPromptCompact;
    try {
      const raw = await session.prompt(build(text, signals, source), {
        responseConstraint: RESPONSE_SCHEMA
      });
      return { ...parseResponse(raw), provider: "on-device", promptVariant: variant };
    } finally {
      if (session !== base && typeof session.destroy === "function") session.destroy();
    }
  }

  async function classifyOnDevice(text, signals, source) {
    if (fullPromptFits) {
      try {
        return await attempt("full", text, signals, source);
      } catch (err) {
        if (!isQuotaError(err)) throw err;
        // The device's context window cannot hold the detailed prompt. Note it
        // once and use the compressed one from here on.
        fullPromptFits = false;
        console.warn(
          "[ScamShield] full prompt exceeds this device's context window; " +
            "falling back to the compact prompt for all messages."
        );
      }
    }
    return attempt("compact", text, signals, source);
  }

  root.ScamShieldClassifier = {
    SYSTEM_PROMPT_FULL,
    SYSTEM_PROMPT_COMPACT,
    RESPONSE_SCHEMA,
    buildUserPromptFull,
    buildUserPromptCompact,
    parseResponse,
    findLanguageModel,
    onDeviceAvailability,
    classifyOnDevice
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
