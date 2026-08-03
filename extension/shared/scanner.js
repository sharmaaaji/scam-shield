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

  const log = (...args) => console.log("[ScamShield]", ...args);

  function createScanner(adapter) {
    // Checked once per page rather than per message; if the device cannot run
    // the model, Tier 1 is skipped entirely and no badges are ever shown.
    let modelState = null;

    async function ensureModelState() {
      if (modelState === null) {
        modelState = await root.ScamShieldClassifier.onDeviceAvailability();
        log("on-device model:", modelState);
        if (modelState !== "available") {
          log(
            "Tier 1 disabled - no badges will appear. Tier 0 can only mark messages " +
            "safe, never flag them. Check the extension popup for details."
          );
        }
      }
      return modelState;
    }

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
      const preview = text.slice(0, 50).replace(/\s+/g, " ");
      if (!triaged.escalate) {
        element.setAttribute(PROCESSED, "safe-fastpath");
        log(`tier0 safe (no model call) | "${preview}…"`);
        return; // stay silent on safe messages - badges only for real signals
      }
      log(`tier0 escalate (${triaged.triggeredCount} signals) | "${preview}…"`);

      // Tier 1: the on-device model.
      if ((await ensureModelState()) !== "available") {
        element.setAttribute(PROCESSED, "no-model");
        return;
      }

      let result;
      try {
        result = await root.ScamShieldClassifier.classifyOnDevice(
          text, triaged.signals, adapter.source
        );
      } catch (err) {
        // Fail quiet, never fail reassuring. Showing nothing is honest; showing
        // "safe" because the classifier broke would be actively harmful.
        element.setAttribute(PROCESSED, "error");
        console.warn("[ScamShield] classification failed:", err);
        return;
      }

      element.setAttribute(PROCESSED, "done");
      log(`tier1 verdict: ${result.verdict} (${Number(result.confidence || 0).toFixed(2)})`);
      if (result.verdict === "safe") return;

      const badge = renderBadge(result);
      if (badge) adapter.attachBadge(element, badge);
    }

    let lastReportedCount = -1;

    function scan() {
      let nodes = [];
      try {
        nodes = adapter.findMessages();
      } catch (err) {
        console.warn("[ScamShield] findMessages failed - selectors may be stale:", err);
        return;
      }

      // Only log when the candidate count changes, so a chatty MutationObserver
      // doesn't flood the console.
      if (nodes.length !== lastReportedCount) {
        lastReportedCount = nodes.length;
        log(`found ${nodes.length} message element(s) via adapter "${adapter.source}"`);
        if (nodes.length === 0) {
          log("no matches - the DOM selector is probably stale for this layout");
        }
      }

      nodes.forEach(handle);
    }

    log(`${adapter.source} adapter loaded on ${location.host}`);

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
