/**
 * Tier 0 triage - deterministic, no model involved.
 *
 * Purpose: resolve the obviously-benign majority of messages without paying for
 * inference, and escalate anything that carries a risk signal to the model.
 *
 * Safety rule, and it is not negotiable: the fast path may only ever return
 * "safe". It must never declare something a scam on its own. Being wrong by
 * escalating costs one inference call; being wrong by clearing a scam costs the
 * user money. When in doubt, escalate.
 */
(function (root) {
  "use strict";

  const URL_RE =
    /(https?:\/\/[^\s]+|www\.[^\s]+|\b[a-z0-9-]+\.(?:com|net|org|xyz|info|biz|top|club|link|online|site|shop|in)\b[^\s]*)/gi;

  const MONEY_RE = /(₹|rs\.?|inr|usd|\$|bitcoin|btc|eth)\s?[\d,]*\d/gi;

  const PHONE_RE = /(\+?\d{1,3}[-.\s]?)?\(?\d{3,5}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g;

  const URGENCY_RE = new RegExp(
    [
      "urgent", "immediately", "act now", "right now", "within \\d+ ?(hours?|hrs?|minutes?|days?)",
      "before (tonight|midnight|today)", "expires? (today|tonight|soon|in)", "last chance",
      "final notice", "limited time", "only \\d+ (left|slots?|hours?)", "hurry",
      "before \\d{1,2} ?(am|pm)", "\\btonight\\b", "taken down", "before the deadline",
      "avoid (disconnection|suspension|penalty|arrest|closure|losing)", "will be (disconnected|suspended|blocked|deactivated|frozen|closed)",
      "failure to", "every (second|minute) (counts|matters)", "do not (delay|ignore)"
    ].join("|"),
    "i"
  );

  // Requests that only a scammer makes - asking the recipient to hand over a
  // secret, or to install remote-access tooling.
  const CREDENTIAL_RE = new RegExp(
    [
      "share (the |your )?otp", "send (the |your )?otp", "tell me (the |your )?otp",
      "your (upi )?pin", "enter (your )?(upi )?pin", "cvv", "card number", "expiry date",
      "net ?banking (username|password)", "\\bpassword\\b", "confirm your (identity|password)",
      "re-?authenticat", "(log|sign) ?in with", "credentials",
      "update (your )?kyc", "kyc (update|verification|pending|non-compliance)",
      "verify your account", "re-?verify", "aadhaar", "bank (account|passbook) (number|photo|details)",
      "anydesk", "teamviewer", "remote access", "screen ?share", "install (this |the )?app",
      "share the (code|access code)"
    ].join("|"),
    "i"
  );

  // Being asked to move money, or to perform a UPI action that actually sends it.
  const PAYMENT_ACTION_RE = new RegExp(
    [
      "pay (now|here|immediately|the|rs|₹)", "make (a )?payment", "transfer (rs|₹|the|to|money|\\d)",
      "send (me |the )?(rs|₹|money|\\d)", "scan (the |this )?qr", "accept (the |my )?request",
      "processing (fee|charge)", "registration fee", "security deposit", "token advance",
      "refundable", "wire transfer", "gift cards?", "recharge"
    ].join("|"),
    "i"
  );

  // Stage-one social engineering: assert an identity, justify a new number,
  // ask to be saved. Carries no URL, no money, no urgency - invisible to every
  // other rule here, which is exactly why it needs its own detector.
  const IDENTITY_CLAIM_RE = new RegExp(
    [
      "this is your (uncle|aunt|aunty|mother|father|mom|mum|dad|papa|son|daughter|brother|sister|cousin|nephew|niece|beta)",
      "hi (mum|mom|dad|papa|beta)\\b",
      "it'?s me\\b",
      "i (have )?(lost|changed) my (phone|number|sim)",
      "this is my new number",
      "save this (number|contact)",
      "i am (from|calling from) (the )?(bank|electricity|police|cyber|income tax|gst)",
      "i'?m (hr|from hr) (at|from)",
      "this is (hdfc|sbi|icici|axis|microsoft|amazon|google|apple) (bank )?(support|security|team)"
    ].join("|"),
    "i"
  );

  // A message can point at a link without the link text ever appearing in
  // innerText - in real mail the URL lives in an anchor's href. Phrases that
  // *refer* to a link are therefore a signal in their own right, and missing
  // this is what let two scams through the fast path on the first measurement.
  const LINK_REFERENCE_RE = new RegExp(
    [
      "(this|the|below|following) link", "link (below|here|provided)", "click (here|below|the|to)",
      "(portal|form|button|address|account) below", "download the", "\\.apk\\b",
      "install (this|the)", "use the (link|form|portal)", "secure (link|payment link)"
    ].join("|"),
    "i"
  );

  // Chain-message mechanics: legitimate senders do not ask you to forward a
  // message to N contacts to unlock something.
  const CHAIN_RE = new RegExp(
    ["forward (this )?to \\d+", "share (this )?with \\d+", "send to \\d+ (friends|contacts|people)"].join("|"),
    "i"
  );

  const THREAT_RE = new RegExp(
    [
      "arrest", "warrant", "legal (action|proceedings)", "court", "police (case|complaint)",
      "fir\\b", "case (has been )?registered", "penalty", "prosecut", "blackmail",
      "send the video", "your contacts", "webcam"
    ].join("|"),
    "i"
  );

  const REWARD_RE = new RegExp(
    [
      "congratulations", "you have won", "winner", "lottery", "lucky draw", "prize",
      "cashback", "free (gift|voucher|rs)", "claim (your|now)", "pre-?approved",
      "you (have been|are) (selected|shortlisted)", "guaranteed (profit|return)",
      "free (upgrade|version|premium|voucher)", "hidden features",
      "double the amount", "\\d+% (returns?|profit)", "inheritance", "next of kin"
    ].join("|"),
    "i"
  );

  function unique(list) {
    return Array.from(new Set(list));
  }

  /**
   * @param {string} text
   * @param {object} [context]
   * @param {boolean} [context.senderIsUnknown]  WhatsApp: number not in contacts.
   * @param {string}  [context.senderDisplayName] Gmail: the "From" display name.
   * @param {string}  [context.senderDomain]      Gmail: actual domain of the From address.
   * @param {boolean} [context.isFirstMessage]    First message ever from this sender.
   */
  function extractSignals(text, context) {
    context = context || {};
    const t = String(text || "");

    const signals = {
      urls: unique(t.match(URL_RE) || []),
      phoneNumbers: unique((t.match(PHONE_RE) || []).map(s => s.trim()).filter(s => s.length >= 7)),
      monetaryMentions: unique(t.match(MONEY_RE) || []),
      hasUrgency: URGENCY_RE.test(t),
      hasCredentialRequest: CREDENTIAL_RE.test(t),
      hasPaymentAction: PAYMENT_ACTION_RE.test(t),
      hasLinkReference: LINK_REFERENCE_RE.test(t),
      hasChainRequest: CHAIN_RE.test(t),
      hasIdentityClaim: IDENTITY_CLAIM_RE.test(t),
      hasThreat: THREAT_RE.test(t),
      hasReward: REWARD_RE.test(t),
      senderIsUnknown: Boolean(context.senderIsUnknown),
      isFirstMessage: Boolean(context.isFirstMessage)
    };

    // Gmail's counterpart to WhatsApp's "unsaved number": a From display name
    // that claims a brand while the actual sending domain is unrelated. This is
    // the single strongest cheap phishing tell available in the DOM.
    signals.brandDomainMismatch = detectBrandDomainMismatch(
      context.senderDisplayName, context.senderDomain
    );

    // The inverse, and just as important: the sender's domain genuinely matching
    // the organisation it claims to be. Faking this requires controlling the
    // real domain, so alignment is strong evidence of legitimacy - without it
    // ordinary transactional mail ("Activate your Render account" from
    // no-reply@render.com) reads as suspicious for want of any positive signal.
    signals.senderDomainAligned = detectDomainAlignment(
      context.senderDisplayName, context.senderDomain
    );

    return signals;
  }

  // "email.claude.com" -> "claude";  "render.com" -> "render"
  function registrableName(domain) {
    const parts = String(domain || "").toLowerCase().split(".").filter(Boolean);
    if (parts.length < 2) return "";
    // Handle co.uk / co.in style suffixes by stepping back one more label.
    const secondLast = parts[parts.length - 2];
    if (parts.length >= 3 && (secondLast === "co" || secondLast === "com")) {
      return parts[parts.length - 3];
    }
    return secondLast;
  }

  // Real transactional mail very often has a generic sender name - DoNotReply,
  // notifications, support, team. Those can never match a domain, so scoring
  // them as "not aligned" would penalise exactly the mail most likely to be
  // legitimate. They are reported as unknown (null) instead of false.
  const GENERIC_SENDER_NAMES = [
    "donotreply", "dontreply", "noreply", "nonreply", "notifications", "notification",
    "info", "support", "admin", "alerts", "alert", "team", "mailer", "mail",
    "service", "services", "updates", "update", "news", "newsletter", "hello",
    "contact", "help", "customercare", "care", "billing", "accounts", "automated"
  ];

  function detectDomainAlignment(displayName, domain) {
    if (!displayName || !domain) return null;

    const token = registrableName(domain);
    if (!token || token.length < 3) return null;
    if (FREEMAIL.includes(String(domain).toLowerCase())) return false;

    const normalised = String(displayName).toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!normalised) return null;

    // No organisation is being claimed, so there is nothing to contradict.
    if (GENERIC_SENDER_NAMES.includes(normalised)) return null;

    // Either the display name contains the domain's name ("Team BankBazaar" /
    // bankbazaar.com) or the domain contains the display name ("Render" /
    // render.com). Near-misses such as "rnder.com" correctly fail both.
    return normalised.includes(token) || token.includes(normalised);
  }

  const BRANDS = [
    "hdfc", "sbi", "icici", "axis", "kotak", "paytm", "phonepe", "gpay",
    "amazon", "flipkart", "netflix", "microsoft", "google", "apple", "paypal",
    "income tax", "gst", "irctc", "epfo", "uidai", "trai", "fastag"
  ];

  const FREEMAIL = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com", "rediffmail.com"];

  function detectBrandDomainMismatch(displayName, domain) {
    if (!displayName || !domain) return false;
    const name = String(displayName).toLowerCase();
    const dom = String(domain).toLowerCase();

    const claimed = BRANDS.find(b => name.includes(b));
    if (!claimed) return false;

    // A brand name in the display name is fine if the domain actually belongs
    // to that brand. It is a strong tell when the mail comes from free webmail
    // or from a domain with no relationship to the claimed brand.
    const token = claimed.replace(/\s+/g, "");
    if (dom.includes(token)) return false;
    if (FREEMAIL.includes(dom)) return true;
    return true;
  }

  /**
   * Decide whether this message can be resolved without the model.
   * Returns either a terminal { verdict: "safe" } or { escalate: true }.
   */
  function triage(text, context) {
    const signals = extractSignals(text, context);

    const riskFlags = [
      signals.urls.length > 0,
      signals.monetaryMentions.length > 0,
      signals.hasUrgency,
      signals.hasCredentialRequest,
      signals.hasPaymentAction,
      signals.hasLinkReference,
      signals.hasChainRequest,
      signals.hasIdentityClaim,
      signals.hasThreat,
      signals.hasReward,
      signals.brandDomainMismatch,
      // An unknown sender is not itself alarming, but combined with a first
      // contact it is enough to warrant real judgment rather than a fast pass.
      signals.senderIsUnknown && signals.isFirstMessage
    ];

    const triggered = riskFlags.filter(Boolean).length;

    if (triggered === 0) {
      return {
        tier: "fast-path",
        escalate: false,
        verdict: "safe",
        confidence: 0.9,
        redFlags: [],
        reasoning:
          "No scam indicators present: no links, no payment or credential requests, " +
          "no urgency or threats, and no identity claims.",
        recommendedAction: "No action needed.",
        signals
      };
    }

    return { tier: "model", escalate: true, signals, triggeredCount: triggered };
  }

  root.ScamShieldTriage = { extractSignals, triage, detectBrandDomainMismatch };
})(typeof globalThis !== "undefined" ? globalThis : this);
