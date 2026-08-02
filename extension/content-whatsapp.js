(function () {
  const PROCESSED_ATTR = "data-scamshield-processed";

  function createBadge(result) {
    const badge = document.createElement("div");
    badge.className = `scamshield-badge scamshield-${result.verdict}`;
    const icon = result.verdict === "scam" ? "⛔" : "⚠️";
    const label = result.verdict === "scam" ? "Likely Scam" : "Suspicious";
    badge.textContent = `${icon} ${label}`;
    const flags = result.redFlags && result.redFlags.length
      ? `\n\nRed flags:\n- ${result.redFlags.join("\n- ")}`
      : "";
    badge.title = `${result.reasoning}${flags}`;
    return badge;
  }

  function analyzeBubble(bubble) {
    if (bubble.getAttribute(PROCESSED_ATTR)) return;

    const textEl = bubble.querySelector("span.selectable-text");
    const text = textEl ? textEl.innerText.trim() : "";
    if (!text || text.length < 8) {
      bubble.setAttribute(PROCESSED_ATTR, "skipped");
      return;
    }

    bubble.setAttribute(PROCESSED_ATTR, "pending");
    chrome.runtime.sendMessage({ type: "ANALYZE", text, source: "whatsapp" }, (response) => {
      if (!response || !response.ok) {
        bubble.setAttribute(PROCESSED_ATTR, "error");
        return;
      }
      bubble.setAttribute(PROCESSED_ATTR, "done");
      if (response.result.verdict === "safe") return;
      const badge = createBadge(response.result);
      bubble.appendChild(badge);
    });
  }

  function scan() {
    // WhatsApp Web has no official API for personal-account message access -
    // "message-in" is an undocumented class WhatsApp uses for incoming bubbles
    // and has for years, but it's not a guarantee against future breakage.
    document.querySelectorAll("div.message-in").forEach(analyzeBubble);
  }

  const observer = new MutationObserver(() => scan());
  observer.observe(document.body, { childList: true, subtree: true });

  scan();
})();
