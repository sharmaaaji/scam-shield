/**
 * Gmail adapter — two passes.
 *
 *   1. Inbox rows   : flag suspicious mail in the LIST, before it is opened.
 *                     This is the moment that actually matters; a warning shown
 *                     only after opening arrives after the reader has begun to
 *                     engage with the message.
 *   2. Opened message: the full alert panel above the message body.
 *
 * Gmail's web client exposes no official DOM contract, so these selectors are
 * unofficial and long-standing rather than guaranteed. They are isolated here
 * so that a Gmail redesign breaks one small file and nothing else.
 */
(function () {
  "use strict";

  // --- opened message ------------------------------------------------------
  const BODY_SELECTOR = "div.a3s";

  // Gmail renders the sender as <span email="..." name="...">, exposing the
  // real address even when the UI shows only a friendly name. That powers
  // brand/domain mismatch detection: "HDFC Bank Support" arriving from
  // gmail.com is the strongest cheap scam tell available in this DOM.
  const SENDER_SELECTOR = "span[email]";

  function senderContext(scope) {
    const context = {};
    try {
      const sender = scope && scope.querySelector(SENDER_SELECTOR);
      if (sender) {
        const address = sender.getAttribute("email") || "";
        context.senderDisplayName = sender.getAttribute("name") || sender.textContent || "";
        context.senderDomain = address.includes("@") ? address.split("@").pop().toLowerCase() : "";
      }
    } catch (_) {
      /* absent metadata just means less context, never an error */
    }
    return context;
  }

  window.ScamShieldScanner.createScanner({
    source: "gmail",
    style: "alert",
    // A message body only exists while an email is open, so matching nothing on
    // the list view is expected rather than a sign of a broken selector.
    expectEmptyViews: true,
    minLength: 20,
    findMessages: () => Array.from(document.querySelectorAll(BODY_SELECTOR)),
    getText: (el) => el.innerText,
    getContext: (el) =>
      senderContext(
        el.closest("div[role='listitem']") || el.closest(".gs") || el.parentElement
      ),
    attachBadge: (el, badge) => {
      const parent = el.parentElement;
      if (parent) parent.insertBefore(badge, el);
    }
  });

  // --- inbox list ----------------------------------------------------------
  // tr.zA is a message row in the list view. Subject lives in span.bog and the
  // preview snippet in span.y2; together with the sender they carry enough to
  // judge a message without opening it.
  const ROW_SELECTOR = "tr.zA";
  const SUBJECT_SELECTOR = "span.bog";
  const SNIPPET_SELECTOR = "span.y2";

  function rowText(row) {
    const subject = row.querySelector(SUBJECT_SELECTOR);
    const snippet = row.querySelector(SNIPPET_SELECTOR);
    const sender = row.querySelector(SENDER_SELECTOR);

    const parts = [];
    if (sender) {
      const name = sender.getAttribute("name") || sender.textContent || "";
      const address = sender.getAttribute("email") || "";
      if (name || address) parts.push(`From: ${name} <${address}>`);
    }
    if (subject) parts.push(subject.innerText);
    if (snippet) parts.push(snippet.innerText.replace(/^\s*-\s*/, ""));
    return parts.join("\n");
  }

  window.ScamShieldScanner.createScanner({
    source: "gmail-inbox",
    style: "pill",
    // A row only carries a subject plus a truncated snippet, so the useful
    // threshold is lower than for a full message body.
    minLength: 12,
    findMessages: () => Array.from(document.querySelectorAll(ROW_SELECTOR)),
    getText: rowText,
    getContext: (row) => senderContext(row),
    attachBadge: (row, pill) => {
      // Place the marker at the start of the row and tint the row itself, so it
      // is visible while scanning the list rather than only on close reading.
      const cell = row.querySelector("td.xY") || row.firstElementChild;
      if (cell) cell.appendChild(pill);
      else row.insertBefore(pill, row.firstChild);
      row.classList.add("scamshield-row-flagged");
    }
  });
})();
