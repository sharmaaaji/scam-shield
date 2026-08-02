const DEFAULT_API_BASE = "http://localhost:5090";

async function getApiBase() {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  return apiBase || DEFAULT_API_BASE;
}

async function getCache() {
  const { cache } = await chrome.storage.local.get("cache");
  return cache || {};
}

async function setCacheEntry(key, value) {
  const cache = await getCache();
  cache[key] = value;
  const keys = Object.keys(cache);
  if (keys.length > 500) {
    delete cache[keys[0]];
  }
  await chrome.storage.local.set({ cache });
}

// Non-cryptographic hash - just needs to be a stable, cheap cache key so the
// same message text isn't re-sent to the API every time the DOM re-renders it.
function hashText(text) {
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = (hash << 5) - hash + text.charCodeAt(i);
    hash |= 0;
  }
  return String(hash);
}

async function analyze(text, source) {
  const key = hashText(text);
  const cache = await getCache();
  if (cache[key]) return cache[key];

  const apiBase = await getApiBase();
  const response = await fetch(`${apiBase}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, source })
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  const result = await response.json();
  await setCacheEntry(key, result);
  return result;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type !== "ANALYZE") return false;

  analyze(message.text, message.source)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: String(error) }));

  return true; // keep the message channel open for the async sendResponse above
});
