/* ═════════ Safemark · service worker ═════════ */

const PANEL_PATH = "popup.html";

/* Chrome 116+ — panel opens automatically on toolbar click */
try {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
} catch {}

/* Fallback for older Chrome */
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

/* Keyboard shortcut: Ctrl+Shift+S → tell the panel to save current page */
chrome.commands.onCommand.addListener((command) => {
  if (command === "save-page") {
    chrome.runtime.sendMessage({ type: "shortcut-save-page" }).catch(() => {});
  }
});
