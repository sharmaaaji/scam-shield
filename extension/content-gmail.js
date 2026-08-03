/**
 * Gmail adapter.
 *
 * Gmail's web client exposes no official DOM contract, so these selectors are
 * unofficial and long-standing rather than guaranteed. They are isolated here
 * precisely so a Gmail redesign breaks one small file and nothing else.
 */
(function () {
  "use strict";

  // div.a3s is the rendered message body. Gmail appends variant classes
  // (a3s aiL, a3s aXjCH) so match on the stable part only.
  const BODY_SELECTOR = "div.a3s";

  // Gmail renders the sender as <span email="..." name="...">, which gives us
  // the real address even when the UI only displays a friendly name. This is
  // Gmail's counterpart to WhatsApp's "is this number saved" signal - and a
  // display name claiming a brand its domain doesn't match is the single
  // strongest cheap phishing tell available here.
  const SENDER_SELECTOR = "span[email]";

  function closestMessageContainer(bodyEl) {
    return bodyEl.closest("div[role='listitem']") || bodyEl.closest(".gs") || bodyEl.parentElement;
  }

  function getContext(bodyEl) {
    const context = {};
    try {
      const container = closestMessageContainer(bodyEl);
      const sender = container && container.querySelector(SENDER_SELECTOR);
      if (sender) {
        const address = sender.getAttribute("email") || "";
        context.senderDisplayName = sender.getAttribute("name") || sender.textContent || "";
        context.senderDomain = address.includes("@") ? address.split("@").pop().toLowerCase() : "";
      }
    } catch (_) {
      /* selectors are best-effort; absent metadata just means less context */
    }
    return context;
  }

  window.ScamShieldScanner.createScanner({
    source: "gmail",
    minLength: 20,
    findMessages: () => Array.from(document.querySelectorAll(BODY_SELECTOR)),
    getText: (el) => el.innerText,
    getContext,
    attachBadge: (el, badge) => {
      const parent = el.parentElement;
      if (parent) parent.insertBefore(badge, el);
    }
  });
})();
