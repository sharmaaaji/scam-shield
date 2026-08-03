const statusEl = document.getElementById("status");
const requirementsEl = document.getElementById("requirements");

function render(cls, headline, detail, showRequirements) {
  if (!statusEl) return;
  statusEl.className = "status " + cls;
  statusEl.textContent = "";

  const h = document.createElement("span");
  h.className = "headline";
  h.textContent = headline;
  statusEl.appendChild(h);

  if (detail) statusEl.appendChild(document.createTextNode(detail));
  if (requirementsEl) requirementsEl.hidden = !showRequirements;
}

/**
 * Chrome has moved this API more than once (window.ai.languageModel ->
 * self.ai.languageModel -> a top-level LanguageModel global), so probe for
 * whichever surface this build actually exposes instead of assuming one.
 */
function findLanguageModel() {
  if (typeof LanguageModel !== "undefined") return { api: LanguageModel, via: "LanguageModel" };
  if (typeof self !== "undefined" && self.ai && self.ai.languageModel) {
    return { api: self.ai.languageModel, via: "self.ai.languageModel" };
  }
  if (typeof window !== "undefined" && window.ai && window.ai.languageModel) {
    return { api: window.ai.languageModel, via: "window.ai.languageModel" };
  }
  return null;
}

// availability() can sit pending while Chrome runs an eligibility check, and a
// popup that says "Checking..." forever is indistinguishable from a crash.
// Always resolve to something the user can act on.
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve("__timeout__"), ms))
  ]);
}

(async () => {
  try {
    const found = findLanguageModel();
    console.log("[ScamShield] built-in AI surface:", found ? found.via : "none found");

    if (!found) {
      render(
        "bad",
        "Not active",
        "Chrome's built-in AI isn't exposed in this browser. It needs Chrome 138+ " +
          "on desktop, and on some builds must be enabled at chrome://flags/#prompt-api-for-gemini-nano.",
        true
      );
      return;
    }

    if (typeof found.api.availability !== "function") {
      render(
        "warn",
        "Unrecognised API version",
        "Found " + found.via + ", but it has no availability() method. This Chrome " +
          "build exposes a different version of the API than the extension expects.",
        true
      );
      return;
    }

    const state = await withTimeout(found.api.availability(), 8000);
    console.log("[ScamShield] availability():", state);

    if (state === "__timeout__") {
      render(
        "warn",
        "Still checking",
        "Chrome didn't answer within 8 seconds. This usually means it's still " +
          "determining eligibility or downloading the model — reopen this popup shortly.",
        false
      );
      return;
    }

    switch (state) {
      case "available":
      case "readily":
        render("ok", "Active", "Analysis runs entirely on your device.", false);
        break;

      case "downloading":
        render(
          "warn",
          "Model downloading",
          "Chrome is downloading the on-device model. Scanning starts once it finishes.",
          false
        );
        break;

      case "downloadable":
      case "after-download":
        render(
          "warn",
          "Model not downloaded yet",
          "Your device supports on-device AI, but the model isn't downloaded. " +
            "Open Gmail or WhatsApp Web to trigger the download.",
          false
        );
        break;

      case "unavailable":
      case "no":
        render(
          "bad",
          "Not active",
          "This device can't run the on-device model, so no messages are analysed.",
          true
        );
        break;

      default:
        render("warn", "Unexpected status", 'Chrome reported "' + state + '".', true);
    }
  } catch (err) {
    // Never leave the popup sitting on "Checking..." - surface the real error.
    console.error("[ScamShield] popup failed:", err);
    render("bad", "Error", String((err && err.message) || err), true);
  }
})();
