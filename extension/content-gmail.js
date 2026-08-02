(function () {
  const PROCESSED_ATTR = "data-scamshield-processed";

  function createBadge(result) {
    const badge = document.createElement("div");
    badge.className = `scamshield-badge scamshield-${result.verdict}`;
    const icon = result.verdict === "scam" ? "⛔" : "⚠️";
    const label = result.verdict === "scam" ? "Likely Scam" : "Suspicious";
    badge.textContent = `${icon} ScamShield: ${label}`;
    const flags = result.redFlags && result.redFlags.length
      ? `\n\nRed flags:\n- ${result.redFlags.join("\n- ")}`
      : "";
    badge.title = `${result.reasoning}${flags}`;
    return badge;
  }

  function analyzeElement(el) {
    if (el.getAttribute(PROCESSED_ATTR)) return;
    el.setAttribute(PROCESSED_ATTR, "pending");

    const text = el.innerText.trim();
    if (!text || text.length < 20) {
      el.setAttribute(PROCESSED_ATTR, "skipped");
      return;
    }

    chrome.runtime.sendMessage({ type: "ANALYZE", text, source: "gmail" }, (response) => {
      if (!response || !response.ok) {
        el.setAttribute(PROCESSED_ATTR, "error");
        return;
      }
      el.setAttribute(PROCESSED_ATTR, "done");
      // Only surface a badge for suspicious/scam - staying quiet on "safe" keeps
      // the UI from turning into noise on every ordinary email.
      if (response.result.verdict === "safe") return;
      const badge = createBadge(response.result);
      el.parentElement?.insertBefore(badge, el);
    });
  }

  function scan() {
    // Gmail ships no official DOM API for the web client. div.a3s is a
    // long-standing (undocumented) class Gmail uses for rendered message
    // bodies - the same anchor several long-running third-party Gmail
    // extensions rely on. It can break if Google changes their markup.
    document.querySelectorAll("div.a3s.aiL, div.a3s").forEach(analyzeElement);
  }

  const observer = new MutationObserver(() => scan());
  observer.observe(document.body, { childList: true, subtree: true });

  scan();
})();
