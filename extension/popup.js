const statusEl = document.getElementById("status");
const requirementsEl = document.getElementById("requirements");

function render(cls, headline, detail, showRequirements) {
  statusEl.className = "status " + cls;
  statusEl.textContent = "";

  const h = document.createElement("span");
  h.className = "headline";
  h.textContent = headline;
  statusEl.appendChild(h);

  if (detail) statusEl.appendChild(document.createTextNode(detail));
  requirementsEl.hidden = !showRequirements;
}

(async () => {
  if (typeof LanguageModel === "undefined") {
    render(
      "bad",
      "Not active",
      "Chrome's built-in AI isn't available here, so messages can't be analysed.",
      true
    );
    return;
  }

  let state;
  try {
    state = await LanguageModel.availability();
  } catch (_) {
    render("bad", "Not active", "Couldn't determine the on-device model's status.", true);
    return;
  }

  switch (state) {
    case "available":
      render("ok", "Active", "Analysis runs entirely on your device.", false);
      break;

    case "downloading":
      render(
        "warn",
        "Model downloading",
        "Chrome is still downloading the on-device model. Scanning starts once it finishes.",
        false
      );
      break;

    case "downloadable":
      render(
        "warn",
        "Model not downloaded yet",
        "Your device supports on-device AI, but Chrome hasn't downloaded the model. " +
          "It downloads automatically on first use — open Gmail or WhatsApp Web to trigger it.",
        false
      );
      break;

    default:
      render(
        "bad",
        "Not active",
        "This device can't run the on-device model, so no messages are analysed.",
        true
      );
  }
})();
