/** Service worker — badge, detection log, cross-frame banner relay. */

const BADGE_COLOR = "#991b1b";

type TabRiskPayload = {
  targetUrl: string;
  reason: string;
  confidence: number;
  kind: string;
  label?: string;
};

function mergeRisks(existing: TabRiskPayload[], incoming: TabRiskPayload[]): TabRiskPayload[] {
  const map = new Map<string, TabRiskPayload>();
  for (const r of [...existing, ...incoming]) {
    const key = `${r.kind}|${r.targetUrl}|${r.label ?? ""}`;
    const prev = map.get(key);
    if (!prev || r.confidence > prev.confidence) map.set(key, r);
  }
  return Array.from(map.values()).sort((a, b) => b.confidence - a.confidence);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (message.type === "DOWNLOAD_TRAP_DETECTED") {
    const count = Number(message.count) || 0;
    const url = String(message.url ?? "");
    const risks = (message.risks as TabRiskPayload[] | undefined) ?? [];

    console.info("[Download Trap Guard]", count, "risk(s) on", url, sender.frameId ? `(frame ${sender.frameId})` : "");

    void chrome.action.setBadgeText({ text: String(count) });
    void chrome.action.setBadgeBackgroundColor({ color: BADGE_COLOR });

    void chrome.storage.session.get("dtg_detection_log").then((data) => {
      const log = (data.dtg_detection_log as Array<{ ts: number; count: number; url: string }>) ?? [];
      log.push({ ts: Date.now(), count, url });
      return chrome.storage.session.set({ dtg_detection_log: log.slice(-50) });
    });

    if (tabId && risks.length > 0) {
      void chrome.storage.session.get(`dtg_tab_risks_${tabId}`).then((data) => {
        const prev = (data[`dtg_tab_risks_${tabId}`] as TabRiskPayload[] | undefined) ?? [];
        const merged = mergeRisks(prev, risks);
        return chrome.storage.session
          .set({ [`dtg_tab_risks_${tabId}`]: merged })
          .then(() =>
            chrome.tabs.sendMessage(tabId, { type: "DTG_SHOW_BANNER", risks: merged }).catch(() => {})
          );
      });
    }

    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "DOWNLOAD_TRAP_CLEAR" && tabId) {
    void chrome.storage.session.remove(`dtg_tab_risks_${tabId}`);
    void chrome.tabs.sendMessage(tabId, { type: "DTG_CLEAR_BANNER" }).catch(() => {});
    void chrome.action.setBadgeText({ text: "" });
    sendResponse({ ok: true });
    return true;
  }

  return false;
});

function isTicketTabUrl(url: string): boolean {
  try {
    return new URL(url).pathname.toLowerCase().includes("/tickets/details/");
  } catch {
    return false;
  }
}

const reinjectCooldown = new Set<number>();

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status !== "complete" || !tab.url || !isTicketTabUrl(tab.url)) return;
  if (reinjectCooldown.has(tabId)) return;
  reinjectCooldown.add(tabId);
  setTimeout(() => reinjectCooldown.delete(tabId), 5000);

  // Re-inject after a short delay so email content is loaded.
  // The IIFE guard in content.js will call __dtgRescan() instead of
  // re-running the full script, triggering a fresh scan cheaply.
  setTimeout(() => {
    void chrome.scripting
      .executeScript({
        target: { tabId, allFrames: true },
        files: ["analysis.js", "content.js"]
      })
      .catch(() => {});
  }, 1500);
});
