// ================================
// Browser IPS - Background Script
// ================================

const SERVER_URL = "http://127.0.0.1:8000/api/browser/report";

// ================================
// 1️⃣ DeclarativeNetRequest Rules (Pre-load Blocking)
// ================================
chrome.runtime.onInstalled.addListener(() => {

  const rules = [
    // SQLi - UNION SELECT
    {
      id: 10,
      priority: 1,
      action: { type: "block" },
      condition: {
        regexFilter: "(?i)(union%20select|union\\+select)",
        resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"]
      }
    },

    // SQLi - OR 1=1
    {
      id: 11,
      priority: 1,
      action: { type: "block" },
      condition: {
        regexFilter: "(?i)(or%201=1|'\\+or\\+'1'='1|'\\%20or\\%20'1'='1)",
        resourceTypes: ["main_frame"]
      }
    },

    // XSS - <script>
    {
      id: 12,
      priority: 1,
      action: { type: "block" },
      condition: {
        regexFilter: "(?i)%3cscript",
        resourceTypes: ["main_frame"]
      }
    }
  ];

  chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: rules.map(r => r.id),
    addRules: rules
  });

  console.log("🔒 Browser IPS regex rules installed");
});


// ================================
// 2️⃣ Report when rule blocks a request
// ================================
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(info => {
  if (!info?.request?.url) return;

  console.log("🚨 BLOCKED by Rule:", info.request.url);

  fetch(SERVER_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: info.request.url,
      issue: "Attack Detected (Domain Blacklisted)",
      severity: "High"
    })
  }).catch(() => {});
});


// ================================
// 3️⃣ Fallback Detection (tabs.onUpdated)
// ================================
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;

  let decoded;
  try {
    decoded = decodeURIComponent(tab.url).toLowerCase();
  } catch {
    decoded = tab.url.toLowerCase();
  }

  const isAttack =
    decoded.includes("union select") ||
    decoded.includes("or 1=1") ||
    decoded.includes("<script");

  if (isAttack) {
    console.log("🚨 BLOCKED by System:", tab.url);

    chrome.tabs.remove(tabId);

    fetch(SERVER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: tab.url,
        issue: "Auto-Blocked Web Attack",
        severity: "High"
      })
    }).catch(() => {});
  }
});


// ================================
// 4️⃣ Tabs Sync (Dashboard)
// ================================
function syncTabs() {
  chrome.tabs.query({}, tabs => {
    const sites = tabs
      .filter(t => t.id && typeof t.url === "string" && t.url.startsWith("http"))
      .map(t => ({
        tab_id: t.id,
        url: t.url
      }));

    fetch("http://127.0.0.1:8000/api/browser/tabs-sync", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sites })
    }).catch(() => {});
  });
}

// Initial + listeners
syncTabs();
chrome.tabs.onCreated.addListener(syncTabs);
chrome.tabs.onRemoved.addListener(syncTabs);
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete") syncTabs();
});
