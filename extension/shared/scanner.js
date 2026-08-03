/**
 * Shared scanning pipeline used by both the Gmail and WhatsApp content scripts.
 * Platform-specific code supplies a small adapter describing how to find
 * messages, pull their text, read sender metadata, and attach a badge.
 */
(function (root) {
  "use strict";

  const PROCESSED = "data-scamshield";

  // Wording is deliberately plain and action-first. The intended reader is not
  // a developer - they should not have to hover anything, decode a confidence
  // score, or know what "phishing" means to understand what to do next.
  const LABELS = {
    scam: { icon: "⛔", headline: "This is probably a scam", short: "SCAM?" },
    suspicious: { icon: "⚠️", headline: "Be careful with this message", short: "CAREFUL" },
    "unverified-identity": { icon: "ℹ️", headline: "You can't be sure who sent this", short: "WHO?" }
  };

  const FOOTER =
    "Checked privately on your device. This can be wrong — if you're unsure, ask someone you trust.";

  /** Full alert panel, shown on an opened message. Nothing hidden behind hover. */
  function renderAlert(result) {
    const meta = LABELS[result.verdict];
    if (!meta) return null;

    const wrap = document.createElement("div");
    wrap.className = "scamshield-alert scamshield-" + result.verdict;

    const head = document.createElement("div");
    head.className = "ss-head";
    head.textContent = meta.icon + "  " + meta.headline;
    wrap.appendChild(head);

    const body = document.createElement("div");
    body.className = "ss-body";

    // The single most important line, so it comes first and largest.
    if (result.recommendedAction) {
      const action = document.createElement("div");
      action.className = "ss-action";
      action.textContent = result.recommendedAction;
      body.appendChild(action);
    }

    if (result.reasoning) {
      const why = document.createElement("div");
      why.className = "ss-why";
      why.textContent = result.reasoning;
      body.appendChild(why);
    }

    if (result.redFlags && result.redFlags.length) {
      const list = document.createElement("ul");
      list.className = "ss-flags";
      for (const flag of result.redFlags.slice(0, 4)) {
        const li = document.createElement("li");
        li.textContent = flag;
        list.appendChild(li);
      }
      body.appendChild(list);
    }

    wrap.appendChild(body);

    const foot = document.createElement("div");
    foot.className = "ss-foot";
    foot.textContent = FOOTER;
    wrap.appendChild(foot);

    return wrap;
  }

  /** Compact marker for a list row, where a full panel would not fit. */
  function renderPill(result) {
    const meta = LABELS[result.verdict];
    if (!meta) return null;

    const pill = document.createElement("span");
    pill.className = "scamshield-pill scamshield-" + result.verdict;
    pill.textContent = meta.icon + " " + meta.short;
    pill.title = meta.headline + (result.recommendedAction ? " — " + result.recommendedAction : "");
    return pill;
  }

  const log = (...args) => console.log("[ScamShield]", ...args);

  // Gmail recycles and rebuilds list rows constantly, so the same message text
  // would otherwise be re-classified every time it re-renders. Cache by content
  // so each distinct message costs at most one inference. In-memory only -
  // nothing about the user's mail is persisted anywhere.
  const resultCache = new Map();
  const CACHE_LIMIT = 400;

  function cacheKey(text) {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = (hash << 5) - hash + text.charCodeAt(i);
      hash |= 0;
    }
    return hash + ":" + text.length;
  }

  function cacheGet(text) {
    return resultCache.get(cacheKey(text));
  }

  function cacheSet(text, result) {
    if (resultCache.size >= CACHE_LIMIT) {
      resultCache.delete(resultCache.keys().next().value);
    }
    resultCache.set(cacheKey(text), result);
  }

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

      let result = cacheGet(text);
      if (result) {
        log("cache hit - no inference needed");
        element.setAttribute(PROCESSED, "done");
        if (result.verdict !== "safe") {
          const cached = adapter.style === "pill" ? renderPill(result) : renderAlert(result);
          if (cached) adapter.attachBadge(element, cached);
        }
        return;
      }

      try {
        result = await root.ScamShieldClassifier.classifyOnDevice(
          text, triaged.signals, adapter.source
        );
        cacheSet(text, result);
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

      const badge = adapter.style === "pill" ? renderPill(result) : renderAlert(result);
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

  root.ScamShieldScanner = { createScanner, renderAlert, renderPill };
})(typeof globalThis !== "undefined" ? globalThis : this);
