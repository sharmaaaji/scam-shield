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
    scam: { icon: "⛔", headline: "This is probably a scam", short: "LIKELY SCAM" },
    suspicious: { icon: "⚠️", headline: "Be careful with this message", short: "BE CAREFUL" },
    // "WHO?" was too cryptic to act on. The label has to say what to do about it.
    "unverified-identity": {
      icon: "ℹ️",
      headline: "You can't be sure who sent this",
      short: "CHECK WHO SENT THIS"
    }
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

  /**
   * Whether a verdict is strong enough to put in front of the user.
   *
   * A list row carries only a subject and a truncated snippet, so a hedged
   * "suspicious" there is usually the model reacting to missing context rather
   * than to evidence. Showing those turns the inbox into a wall of warnings and
   * teaches the reader to ignore all of them - including the real one. So rows
   * demand a confident "scam"; the full message view, which has the whole text
   * to reason over, keeps the lower bar.
   */
  function shouldWarn(result, adapter) {
    if (!result || result.verdict === "safe" || result.verdict === "unknown") return false;

    const confidence = Number(result.confidence || 0);

    if (adapter.strictThreshold) {
      return result.verdict === "scam" && confidence >= 0.7;
    }

    // Even with the full message in hand, a barely-past-the-middle "suspicious"
    // is the model hedging rather than seeing something. Showing a large red
    // panel on a 0.60 hunch is how a useful tool becomes background noise.
    if (result.verdict === "scam") return confidence >= 0.6;
    return confidence >= 0.75;
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

  // A single on-device model backs every request, so firing one inference per
  // message concurrently (an inbox can escalate 40+ at once) thrashes it and
  // starves everything behind it. Run them one at a time instead.
  let queueTail = Promise.resolve();

  function enqueue(job) {
    const result = queueTail.then(job, job);
    // Keep the chain alive even if a job rejects.
    queueTail = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  function createScanner(adapter) {
    // Cached so we don't re-query per message. "available" is terminal, but any
    // other state must be re-checked: the user may download the model while this
    // tab is already open, and caching "downloadable" forever would leave the
    // page permanently inert with no way back short of a reload.
    let modelState = null;
    let lastStateCheck = 0;
    let inFlightCheck = null;
    const RECHECK_MS = 20000;

    async function ensureModelState() {
      const stale = Date.now() - lastStateCheck > RECHECK_MS;
      if (modelState === null || (modelState !== "available" && stale)) {
        // Messages are handled concurrently, so without sharing the in-flight
        // promise every one of them kicks off its own availability check and
        // logs its own result - 40+ identical lines for one real question.
        if (inFlightCheck) return inFlightCheck;

        inFlightCheck = (async () => {
          const previous = modelState;
          modelState = await root.ScamShieldClassifier.onDeviceAvailability();
          lastStateCheck = Date.now();

          if (modelState !== previous) log("on-device model:", modelState);
          if (previous && previous !== "available" && modelState === "available") {
            log("model became available - re-scanning this page");
            document.querySelectorAll("[" + PROCESSED + "='no-model']").forEach((el) =>
              el.removeAttribute(PROCESSED)
            );
          }
          if (modelState === "downloadable" || modelState === "downloading") {
            log(
              "Model not ready yet (" + modelState + "). Open the ScamShield popup and " +
              "press Download - the download only starts from an explicit user action, " +
              "not from page activity. No messages are checked until it finishes."
            );
          } else if (modelState !== "available") {
            log(
              "Tier 1 disabled (" + modelState + ") - no warnings will appear. Tier 0 can " +
              "only mark messages safe, never flag them. See the extension popup."
            );
          }

          inFlightCheck = null;
          return modelState;
        })();

        return inFlightCheck;
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
        result = await enqueue(() =>
          root.ScamShieldClassifier.classifyOnDevice(text, triaged.signals, adapter.source)
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
      log(
        `tier1 verdict: ${result.verdict} (${Number(result.confidence || 0).toFixed(2)})` +
          ` | "${preview}…"`
      );

      if (!shouldWarn(result, adapter)) return;

      const badge = adapter.style === "pill" ? renderPill(result) : renderAlert(result);
      if (badge) adapter.attachBadge(element, badge);
    }

    let lastReportedCount = -1;
    const watched = new WeakSet();

    // Classify only what the user can actually see. An inbox can hold 50+ rows
    // while a screen shows maybe 12, and every off-screen row would otherwise
    // cost an on-device inference the user never benefits from. Messages are
    // analysed as they scroll into view instead.
    const visibility = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          visibility.unobserve(entry.target);
          handle(entry.target);
        }
      },
      // A little margin so a message is usually ready by the time it is read,
      // rather than resolving after the user has already looked at it.
      { rootMargin: "300px 0px" }
    );

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
        // Zero matches is normal and expected for the opened-message adapter
        // while the user is looking at a list, so don't cry stale-selector for
        // an adapter that simply has nothing to do on the current view.
        if (nodes.length === 0 && !adapter.expectEmptyViews) {
          log("no matches - the DOM selector may be stale for this layout");
        }
      }

      for (const node of nodes) {
        if (node.getAttribute(PROCESSED) || watched.has(node)) continue;
        watched.add(node);
        visibility.observe(node);
      }
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
