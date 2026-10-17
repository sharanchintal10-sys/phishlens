const TITLES = { safe: "Looks safe", suspicious: "Be careful", dangerous: "Likely phishing" };
const $ = (id) => document.getElementById(id);

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const { api } = await chrome.storage.local.get("api");
  $("api").value = api || "http://localhost:8000";
  const data = (await chrome.storage.local.get("tab" + tab.id))["tab" + tab.id];
  if (!data) {
    $("title").textContent = "No result for this tab";
    $("why").textContent = "Open a web page, or check that the scanner is running at the address below.";
    return;
  }
  const r = data.result;
  $("top").className = "top " + r.verdict;
  $("title").textContent = TITLES[r.verdict] + " (risk " + r.score + "/100)";
  $("host").textContent = new URL(data.url).hostname;
  $("why").textContent = r.explanation;
  r.reasons.slice(0, 4).forEach((x) => { const li = document.createElement("li"); li.textContent = x; $("reasons").appendChild(li); });
})();

$("save").onclick = async () => { await chrome.storage.local.set({ api: $("api").value.trim() }); $("save").textContent = "Saved"; };
$("reset").onclick = async () => { await chrome.storage.local.set({ ignored: [] }); $("reset").textContent = "Cleared"; };
