const statusEl = document.getElementById("status");
const keyEl = document.getElementById("apiKey");
const availabilityEl = document.getElementById("availability");

const DEFAULTS = { provider: "auto", apiKey: "", model: "gemini-flash-latest" };

chrome.storage.local.get(Object.keys(DEFAULTS), (stored) => {
  const settings = Object.assign({}, DEFAULTS, stored || {});
  keyEl.value = settings.apiKey || "";
  const radio = document.querySelector(`input[name="provider"][value="${settings.provider}"]`);
  if (radio) radio.checked = true;
});

// The Prompt API is not exposed to the popup in every Chrome build, so report
// what we can determine and stay vague rather than claiming something false.
(async () => {
  try {
    if (typeof LanguageModel === "undefined") {
      availabilityEl.textContent =
        "On-device model not detected here. Needs Chrome 138+ on desktop with ~22 GB free disk.";
      return;
    }
    const state = await LanguageModel.availability();
    const messages = {
      available: "On-device model ready. Nothing leaves your machine.",
      downloadable: "On-device model available but not downloaded yet (a few GB).",
      downloading: "On-device model is downloading…",
      unavailable: "This device cannot run the on-device model. Use a cloud API key."
    };
    availabilityEl.textContent = messages[state] || ("On-device model: " + state);
  } catch (_) {
    availabilityEl.textContent = "Could not determine on-device model status.";
  }
})();

document.getElementById("save").addEventListener("click", () => {
  const selected = document.querySelector('input[name="provider"]:checked');
  const provider = selected ? selected.value : "auto";
  const apiKey = keyEl.value.trim();

  if (provider === "byok-cloud" && !apiKey) {
    statusEl.style.color = "#cf222e";
    statusEl.textContent = "Cloud mode needs an API key.";
    return;
  }

  chrome.storage.local.set({ provider, apiKey, model: DEFAULTS.model }, () => {
    statusEl.style.color = "#1a7f37";
    statusEl.textContent = "Saved. Reload Gmail or WhatsApp Web to apply.";
    setTimeout(() => (statusEl.textContent = ""), 2500);
  });
});
