// PhishLens service worker: scans each page you open and warns on risky ones.
const DEFAULT_API = "http://localhost:8000";
const CACHE_MS = 10 * 60 * 1000;
const cache = new Map(); // url -> { at, result }

async function getApi() {
  const { api } = await chrome.storage.local.get("api");
  return (api || DEFAULT_API).replace(/\/$/, "");
}

async function isIgnored(host) {
  const { ignored = [] } = await chrome.storage.local.get("ignored");
  return ignored.includes(host);
}

async function scan(url) {
  const hit = cache.get(url);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.result;
  const res = await fetch((await getApi()) + "/scan-url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error("scan failed");
  const result = await res.json();
  cache.set(url, { at: Date.now(), result });
  return result;
}

function badge(tabId, verdict) {
  const map = { safe: ["✓", "#1B7F4F"], suspicious: ["!", "#9A5B00"], dangerous: ["✕", "#B42318"] };
  const [text, color] = map[verdict] || ["", "#666"];
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// Injected into the page. Must be self-contained.
function showWarning(result, host) {
  if (document.getElementById("phishlens-warning")) return;
  const danger = result.verdict === "dangerous";
  const root = document.createElement("div");
  root.id = "phishlens-warning";
  root.setAttribute("role", "alertdialog");
  const color = danger ? "#B42318" : "#9A5B00";
  root.style.cssText = danger
    ? "position:fixed;inset:0;z-index:2147483647;background:rgba(15,42,61,.96);display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;"
    : "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#FDF0D8;color:#4A2C00;border-bottom:3px solid " + color + ";font-family:system-ui,sans-serif;padding:12px 18px;";
  const reasons = result.reasons.slice(0, 3).map((r) => "<li>" + r.replace(/[<>&]/g, "") + "</li>").join("");
  if (danger) {
    root.innerHTML =
      '<div style="background:#fff;color:#0F2A3D;max-width:520px;margin:20px;padding:28px;border-radius:14px;border-left:10px solid ' + color + '">' +
      '<h1 style="margin:0 0 8px;font-size:26px;color:' + color + '">This site looks like phishing</h1>' +
      '<p style="margin:0 0 10px;font-size:16px;line-height:1.5">' + result.explanation.replace(/[<>&]/g, "") + "</p>" +
      '<ul style="margin:0 0 18px;padding-left:20px;font-size:15px;line-height:1.5">' + reasons + "</ul>" +
      '<button id="pl-back" style="background:#0B6E8A;color:#fff;border:0;border-radius:10px;padding:11px 20px;font-size:16px;font-weight:600;cursor:pointer;margin-right:10px">Take me back to safety</button>' +
      '<button id="pl-go" style="background:none;border:1.5px solid #CBD6DC;border-radius:10px;padding:10px 16px;font-size:15px;cursor:pointer">Continue anyway</button></div>';
  } else {
    root.innerHTML =
      '<b>Be careful on this page.</b> ' + result.explanation.replace(/[<>&]/g, "") +
      ' <button id="pl-go" style="margin-left:10px;border:1px solid #9A5B00;background:none;border-radius:8px;padding:4px 12px;cursor:pointer">Dismiss</button>';
  }
  document.documentElement.appendChild(root);
  const back = root.querySelector("#pl-back");
  if (back) back.onclick = () => (history.length > 1 ? history.back() : (location.href = "about:blank"));
  root.querySelector("#pl-go").onclick = () => {
    root.remove();
    chrome.runtime.sendMessage({ type: "ignore", host });
  };
}

chrome.tabs.onUpdated.addListener(async (tabId, change, tab) => {
  if (change.status !== "complete" || !/^https?:\/\//.test(tab.url || "")) return;
  const host = new URL(tab.url).hostname;
  if (await isIgnored(host)) return badge(tabId, "safe");
  try {
    const result = await scan(tab.url);
    badge(tabId, result.verdict);
    await chrome.storage.local.set({ ["tab" + tabId]: { url: tab.url, result } });
    if (result.verdict !== "safe") {
      await chrome.scripting.executeScript({ target: { tabId }, func: showWarning, args: [result, host] });
    }
  } catch {
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#666" });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.local.remove("tab" + tabId));

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "ignore") {
    chrome.storage.local.get("ignored").then(({ ignored = [] }) => {
      if (!ignored.includes(msg.host)) chrome.storage.local.set({ ignored: [...ignored, msg.host] });
    });
  }
});
