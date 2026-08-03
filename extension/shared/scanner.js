/**
 * Shared scanning pipeline used by both the Gmail and WhatsApp content scripts.
 * Platform-specific code supplies a small adapter describing how to find
 * messages, pull their text, read sender metadata, and attach a badge.
 */
(function (root) {
  "use strict";

  const PROCESSED = "data-scamshield";

  const LABELS = {
    scam: { icon: "⛔", text: "Likely scam" },
    suspicious: { icon: "⚠️", text: "Suspicious" },
    "unverified-identity": { icon: "ℹ️", text: "Unverified sender identity" }
  };

  function renderBadge(result) {
    const meta = LABELS[result.verdict];
    if (!meta) return null;

    const badge = document.createElement("div");
    badge.className = "scamshield-badge scamshield-" + result.verdict;

    const label = document.createElement("span");
    label.className = "scamshield-label";
    label.textContent = meta.icon + " " + meta.text;
    badge.appendChild(label);

    if (result.recommendedAction) {
      const action = document.createElement("span");
      action.className = "scamshield-action";
      action.textContent = result.recommendedAction;
      badge.appendChild(action);
    }

    const detail = [
      result.reasoning,
      result.redFlags && result.redFlags.length ? "\n\nRed flags:\n- " + result.redFlags.join("\n- ") : "",
      "\n\n(" + (result.provider || result.tier || "local") +
        ", confidence " + Number(result.confidence || 0).toFixed(2) + ")"
    ].join("");
    badge.title = detail;

    return badge;
  }

  async function classify(text, signals, source, settings) {
    const C = root.ScamShieldClassifier;

    if (settings.provider !== "byok-cloud") {
      const availability = await C.onDeviceAvailability();
      if (availability === "available") {
        return await C.classifyOnDevice(text, signals, source);
      }
      // "downloadable"/"downloading" mean the model is not ready yet. Rather
      // than block on a multi-GB download, fall through to cloud if configured.
      if (!settings.apiKey) {
        const err = new Error("on-device model " + availability);
        err.code = "MODEL_UNAVAILABLE";
        throw err;
      }
    }

    if (!settings.apiKey) {
      const err = new Error("no API key configured");
      err.code = "NO_KEY";
      throw err;
    }
    return await C.classifyByokCloud(text, signals, source, settings.apiKey, settings.model);
  }

  function createScanner(adapter) {
    let settings = { provider: "auto", apiKey: "", model: "gemini-flash-latest" };

    chrome.storage.local.get(["provider", "apiKey", "model"], (stored) => {
      settings = Object.assign(settings, stored || {});
    });
    chrome.storage.onChanged.addListener((changes) => {
      for (const key of Object.keys(changes)) settings[key] = changes[key].newValue;
    });

    async function handle(element) {
      if (element.getAttribute(PROCESSED)) return;
      element.setAttribute(PROCESSED, "pending");

      let text = "";
      try {
        text = (adapter.getText(element) || "").trim();
      } catch (_) {
        element.setAttribute(PROCESSED, "error");
        return;
      }

      if (!text || text.length < adapter.minLength) {
        element.setAttribute(PROCESSED, "skipped");
        return;
      }

      const context = adapter.getContext ? adapter.getContext(element) : {};

      // Tier 0: deterministic. Resolves the benign majority with no model call.
      const triaged = root.ScamShieldTriage.triage(text, context);
      if (!triaged.escalate) {
        element.setAttribute(PROCESSED, "safe-fastpath");
        return; // stay silent on safe messages - badges only for real signals
      }

      // Tier 1: the model.
      let result;
      try {
        result = await classify(text, triaged.signals, adapter.source, settings);
      } catch (err) {
        // Fail quiet, never fail reassuring. Showing nothing is honest; showing
        // "safe" because the classifier broke would be actively harmful.
        element.setAttribute(PROCESSED, "error");
        if (err.code === "NO_KEY" || err.code === "MODEL_UNAVAILABLE") {
          root.__scamshieldNeedsSetup = true;
        }
        return;
      }

      element.setAttribute(PROCESSED, "done");
      if (result.verdict === "safe") return;

      const badge = renderBadge(result);
      if (badge) adapter.attachBadge(element, badge);
    }

    function scan() {
      let nodes = [];
      try {
        nodes = adapter.findMessages();
      } catch (_) {
        return;
      }
      nodes.forEach(handle);
    }

    let pending = null;
    const observer = new MutationObserver(() => {
      // Gmail and WhatsApp both mutate the DOM constantly; debounce so a burst
      // of unrelated re-renders doesn't trigger a scan per mutation.
      clearTimeout(pending);
      pending = setTimeout(scan, 400);
    });

    observer.observe(document.body, { childList: true, subtree: true });
    scan();
  }

  root.ScamShieldScanner = { createScanner, renderBadge };
})(typeof globalThis !== "undefined" ? globalThis : this);
