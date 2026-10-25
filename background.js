/* ═════════ Safemark · service worker ═════════
 * Clicking the shield toolbar action opens the vault as a docked
 * Side Panel (right side, shares the browser window) — never a pop-out.
 *
 * We do NOT use setPanelBehavior({ openPanelOnActionClick }) here:
 * it silently fails on some Brave builds, leaving the icon dead.
 * An explicit onClicked handler works everywhere and fires only when
 * no popup is set (our manifest has none). */

async function openPanel() {
  if (!chrome.sidePanel?.open) return; // very old Chromium — no panel API
  try {
    const win = await chrome.windows.getCurrent();
    // NOTE: some Brave builds reject `windowId` in setOptions — set globally
    await chrome.sidePanel.setOptions({ path: "popup.html", enabled: true });
    await chrome.sidePanel.open({ windowId: win.id });
  } catch (e) {
    console.warn("Safemark: could not open side panel", e);
  }
}

chrome.action.onClicked.addListener(openPanel);
