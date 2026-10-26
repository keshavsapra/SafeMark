/* ═════════ Safemark · service worker ═════════
 * Opens the vault as a docked Side Panel on icon click.
 * Chrome 116+: setPanelBehavior opens it automatically.
 * Older Chrome: onClicked fallback via sidePanel.open(). */

const PANEL_PATH = "popup.html";

/* Chrome 116+ — panel opens automatically on toolbar click */
try {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
} catch {}

/* Fallback for older Chrome builds that don't support setPanelBehavior */
chrome.action.onClicked.addListener(async (tab) => {
  try {
    await chrome.sidePanel.open({ windowId: tab.windowId });
  } catch {
    try {
      await chrome.sidePanel.open({ tabId: tab.id });
    } catch {
      chrome.tabs.create({ url: chrome.runtime.getURL(PANEL_PATH) });
    }
  }
});
