/**
 * WhatsApp Web adapter.
 *
 * As with Gmail these selectors are unofficial. WhatsApp offers no API for
 * personal-account message access, so DOM reading is the only route available
 * to an extension.
 */
(function () {
  "use strict";

  const INCOMING_SELECTOR = "div.message-in";
  const TEXT_SELECTOR = "span.selectable-text";

  // A chat header showing a raw phone number instead of a name means the
  // sender is not in the user's contacts. Combined with an identity claim
  // ("this is your uncle, I changed my number") that is the core signal for
  // family-impersonation scams, which carry no link, no amount and no urgency
  // and are otherwise invisible to every other rule.
  const PHONE_LIKE = /^\+?[\d\s\-()]{7,}$/;

  function readChatTitle() {
    const header = document.querySelector("#main header");
    if (!header) return "";
    const titled = header.querySelector("span[title]");
    return titled ? titled.getAttribute("title") || "" : header.innerText || "";
  }

  function getContext(bubble) {
    const context = {};
    try {
      const title = readChatTitle().trim();
      context.senderIsUnknown = Boolean(title) && PHONE_LIKE.test(title);

      // data-pre-plain-text looks like "[10:04, 2/8/2026] Name: ". In a group
      // chat this identifies the individual sender rather than the chat.
      const meta = bubble.querySelector("[data-pre-plain-text]");
      if (meta) {
        const raw = meta.getAttribute("data-pre-plain-text") || "";
        const name = (raw.split("]").pop() || "").replace(/:\s*$/, "").trim();
        if (name && PHONE_LIKE.test(name)) context.senderIsUnknown = true;
      }

      // Treat the first incoming bubble in the thread as a first contact.
      const all = document.querySelectorAll(INCOMING_SELECTOR);
      context.isFirstMessage = all.length > 0 && all[0] === bubble;
    } catch (_) {
      /* best-effort metadata only */
    }
    return context;
  }

  window.ScamShieldScanner.createScanner({
    source: "whatsapp",
    style: "alert",
    minLength: 8,
    findMessages: () => Array.from(document.querySelectorAll(INCOMING_SELECTOR)),
    getText: (el) => {
      const node = el.querySelector(TEXT_SELECTOR);
      return node ? node.innerText : "";
    },
    getContext,
    attachBadge: (bubble, alert) => {
      // Insert as a sibling BEFORE the bubble rather than inside it. A chat
      // bubble is narrow and right-aligned; a warning stuffed inside one is
      // cramped and easy to scroll past. As a full-width block directly above
      // the message, it is read before the message it refers to.
      alert.classList.add("scamshield-wa");
      const parent = bubble.parentElement;
      if (parent) parent.insertBefore(alert, bubble);
      else bubble.appendChild(alert);
    }
  });
})();
