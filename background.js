/* ═════════ Safemark · service worker ═════════
 * Clicking the shield action opens the vault as a docked Side Panel.
 * Never a death-silent click: if the panel can't be opened (Brand of
 * Chromium, sidebar disabled by user settings, API unavailable), we
 * fall back through increasingly-guaranteed paths and record why. */

const PANEL_PATH = "popup.html";

function rememberErr(reason) {
  console.warn("Safemark:", reason);
  try { void chrome.storage.local.set({ smPanelErr: String(reason) }); } catch {}
}
function clearErr() {
  try { void chrome.storage.local.remove("smPanelErr"); } catch {}
}

/* last-resort: a normal browser tab. Always works. */
function openAsTab(reason) {
  const detail = "side panel unavailable — " + reason + " — opened in a tab";
  rememberErr(detail);
  try { void chrome.tabs.create({ url: chrome.runtime.getURL(PANEL_PATH) }); } catch {}
}

async function openPanel(tab) {
  // API truly absent (very old Chromium)
  if (!chrome.sidePanel?.open || !chrome.sidePanel?.setOptions) {
    openAsTab("sidePanel API missing");
    return;
  }
  try {
    // no windowId in setOptions — some Brave builds reject the property
    await chrome.sidePanel.setOptions({ path: PANEL_PATH, enabled: true });
    await chrome.sidePanel.open({ windowId: tab.windowId });
    clearErr();
    return;
  } catch (e1) {
    // try panel-per-tab form
    try {
      await chrome.sidePanel.open({ tabId: tab.id });
      clearErr();
      return;
    } catch (e2) {
      openAsTab(
        "windowId-open: " + (e1?.message || String(e1)) +
        " | tabId-open: " + (e2?.message || String(e2))
      );
    }
  }
}

chrome.action.onClicked.addListener(openPanel);
