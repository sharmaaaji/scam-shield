const input = document.getElementById("apiBase");
const status = document.getElementById("status");

chrome.storage.local.get("apiBase", ({ apiBase }) => {
  input.value = apiBase || "http://localhost:5090";
});

document.getElementById("save").addEventListener("click", () => {
  chrome.storage.local.set({ apiBase: input.value.trim() }, () => {
    status.textContent = "Saved.";
    setTimeout(() => (status.textContent = ""), 1500);
  });
});
