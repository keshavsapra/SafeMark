/* ═════════ Safemark v1.5 · popup logic ═════════
 *
 * Storage layout (chrome.storage.local + mirrored to chrome.storage.sync):
 *   smOnboarded  {boolean}   onboarding finished
 *   smKdf        {number}    scheme version (3 = 600k-iteration PBKDF2)
 *   smSalt       {string}    hex salt (16 bytes) — synced so the same
 *                            password generates the same AES key everywhere
 *   smHash       {string}    hex password verifier (32 bytes)
 *   smMeta       {object}    { iv, rev, parts } — vault envelope metadata
 *   smVault0..N  {string}    AES-256-GCM ciphertext, chunked for sync's
 *                            8KB-per-item quota
 *   smFails      {object}    { n, until } — wrong-attempt lockout (local only)
 *   smDetachWin  {number}    source window id for detached vaults (session)
 *
 * Sync model (like bookmarks):
 *   • The password never leaves the device. Only ciphertext + salt + verifier
 *     sync — Brave/Chrome Sync transports what it cannot read.
 *   • Every write bumps a revision (smMeta.rev); remote changes with a newer
 *     revision are merged (union by URL) while unlocked, or adopted wholesale
 *     when locked, so a fresh install on a synced device shows the vault
 *     after entering the password.
 *   • Legacy layouts (v1.0 plaintext / v1.2-v1.4 single-blob) migrate
 *     transparently on the first successful unlock.
 */

const HAS_API =
  typeof chrome !== "undefined" && !!(chrome.storage && chrome.tabs);

const KDF_ITER = 600000;    // v1.2+ (smKdf = 3)
const LEGACY_ITER = 210000; // v1.0 / v1.1 recognised via smKdf / data shape
const SCHEME_V = 3;
const MAX_LOCK_MS = 60000;

const SYNC_CHUNK = 7000;    // stay under sync's 8192-byte-per-item quota
const FAVICON_MAX = 2048;   // never let a data-URI favicon bloat the sync

/* the shield action opens this page docked as a Side Panel
 * (fluid layout); there is no detached pop-out window anymore */
const PANEL_PAGE =
  typeof location === "undefined" || true; /* extension page == panel page */

/* ── DOM helpers ── */
const $ = (id) => document.getElementById(id);
const views = ["view-welcome", "view-setup", "view-gate", "view-vault"];

function show(viewId) {
  views.forEach((v) => $(v).classList.toggle("hidden", v !== viewId));
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(t._tm);
  t._tm = setTimeout(() => t.classList.add("hidden"), 2200);
}

function fail(el, form, msg) {
  el.textContent = msg;
  el.classList.remove("hidden");
  form.classList.remove("shake");
  void form.offsetWidth; // restart animation
  form.classList.add("shake");
}

/* ── encoding helpers ── */
const bufToHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

const bufToB64 = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)));

const b64ToBuf = (b64) =>
  Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

function newSalt() {
  return bufToHex(crypto.getRandomValues(new Uint8Array(16)));
}

const enc = new TextEncoder();

/* ── key derivation ── */
async function pbkdf2Bits(password, saltHex, length, iter) {
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    baseKey,
    length
  );
}

/* v1.0 verifier (kept only to migrate ancient plaintext installs) */
async function legacyHash(password, saltHex) {
  return bufToHex(await pbkdf2Bits(password, saltHex, 256, LEGACY_ITER));
}

/* verifier + AES key from a single derivation. */
async function deriveKeys(password, saltHex, iter = KDF_ITER) {
  const bits = new Uint8Array(await pbkdf2Bits(password, saltHex, 512, iter));
  const verifier = bufToHex(bits.slice(0, 32));
  const aes = await crypto.subtle.importKey(
    "raw", bits.slice(32), "AES-GCM", false, ["encrypt", "decrypt"]
  );
  return { verifier, aes };
}

/* ── vault sealing (AES-256-GCM, fresh IV on every write) ── */
async function sealVault(aesKey, list) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, aesKey, enc.encode(JSON.stringify(list))
  );
  return { iv: bufToB64(iv), ct: bufToB64(ct) };
}

async function openVault(aesKey, sealed) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBuf(sealed.iv) }, aesKey, b64ToBuf(sealed.ct)
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

const syncArea = () => (chrome.storage && chrome.storage.sync) || null;

/* ── chunking (sync items cap at 8KB each) ── */
function chunkStr(s, size = SYNC_CHUNK) {
  const out = [];
  for (let i = 0; i < s.length; i += size) out.push(s.slice(i, i + size));
  return out.length ? out : [""];
}

function stitchChunks(store, parts) {
  let ct = "";
  for (let i = 0; i < parts; i++) ct += store["smVault" + i] || "";
  return { iv: store.smMeta.iv, ct };
}

async function cleanOrphanParts(area, keep) {
  try {
    const all = await chrome.storage[area].get(null);
    const extra = Object.keys(all).filter(
      (k) => /^smVault\d+$/.test(k) && parseInt(k.slice(7), 10) >= keep
    );
    if (extra.length) await chrome.storage[area].remove(extra);
  } catch {}
}

/* persist the in-memory vault to local + sync, bumping the revision */
async function persistVault(extra = {}) {
  const sealed = await sealVault(window.__aesKey, window.__vault);
  const rev = (window.__rev || 0) + 1;
  window.__rev = rev;

  const chunks = chunkStr(sealed.ct);
  const keep = chunks.length;
  const data = {
    smMeta: { iv: sealed.iv, rev },
    ...extra,
  };
  data.smMeta.parts = keep;
  chunks.forEach((c, i) => { data["smVault" + i] = c; });

  await chrome.storage.local.set(data);
  let synced = true;
  try {
    await chrome.storage.sync.set(data);
  } catch {
    window.__syncFailed = true; // oversized / offline sync — local copy is intact
    synced = false;
  }
  await cleanOrphanParts("local", keep);
  if (synced) await cleanOrphanParts("sync", keep);
  return rev;
}

/* ═════════ BOOT ═════════ */
init();

async function init() {
  if (typeof document !== "undefined") {
    document.body.classList.add("panel"); // fluid layout for the Side Panel
  }
  if (!HAS_API) {
    // Preview / non-extension context: demo of the unlocked vault.
    window.__vault = [
      { id: "d1", title: "Hacker News", url: "https://news.ycombinator.com/", favicon: "", addedAt: Date.now() },
      { id: "d2", title: "MDN Web Docs", url: "https://developer.mozilla.org/", favicon: "", addedAt: Date.now() - 1e5 },
    ];
    renderVault();
    return;
  }

  let store = await chrome.storage.local.get(null);
  store = await adoptFromSync(store); // sync-first boot, like bookmarks

  if (syncArea()) {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "sync" && changes.smMeta?.newValue) {
        queueRemoteChange(changes.smMeta.newValue);
      }
    });
  }

  if (!store.smOnboarded || !store.smSalt || !store.smHash) {
    $("btn-next").addEventListener("click", () => show("view-setup"));
    $("form-setup").addEventListener("submit", onSetupSubmit);
    $("setup-pass").addEventListener("input", updateStrengthMeter);
    $("setup-pass").focus();
    show("view-welcome");
  } else {
    $("form-gate").addEventListener("submit", onGateSubmit);
    $("gate-pass").focus();
    show("view-gate");
    const remain = await lockRemainingMs();
    if (remain > 0) showLockout(remain);
  }

  await showPanelNotice();
}

/* ── docked-panel failure notice ──
 * If the Side Panel couldn't open (background stores the reason in
 * smPanelErr), the fallback tab says why instead of just appearing. */
async function showPanelNotice() {
  if (!HAS_API || typeof document === "undefined") return;
  try {
    const { smPanelErr } = await chrome.storage.local.get("smPanelErr");
    if (!smPanelErr) return;

    const app = document.querySelector(".app");
    if (!app || document.querySelector(".panel-note")) return;

    const esc = (s) => String(s).replace(/[<>&]/g, (c) =>
      ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));

    const note = document.createElement("div");
    note.className = "panel-note";
    note.innerHTML =
      '<div class="pn-text"><b>⚠️ Docked panel couldn\'t open — showing in a tab instead.</b><br>' +
      '<span class="pn-reason">reason: ' + esc(smPanelErr) + "</span><br>" +
      "In Brave, enable <b>Settings → Appearance → Show sidebar</b> (or open " +
      "<code>brave://settings/sidebar</code>), then click the Safemark shield again.</div>" +
      '<button class="pn-dismiss" title="Dismiss">✕</button>';
    note.querySelector(".pn-dismiss").addEventListener("click", () => {
      try { void chrome.storage.local.remove("smPanelErr"); } catch {}
      note.remove();
    });
    app.prepend(note);
  } catch {}
}

/* ═════════ SYNC ═════════ */
async function adoptFromSync(store) {
  const sync = syncArea();
  if (!sync) return store;
  let syncStore = null;
  try { syncStore = await sync.get(null); } catch { return store; }
  if (!syncStore || !syncStore.smMeta) return store;
  const srev = syncStore.smMeta.rev ?? 0;
  const lrev = store.smMeta?.rev ?? 0;
  if (srev <= lrev) return store;

  const localEmpty = !store.smOnboarded && !store.smHash;
  const sameVault =
    store.smHash && store.smSalt &&
    syncStore.smSalt === store.smSalt && syncStore.smHash === store.smHash;

  if (localEmpty || sameVault) {
    // adopt: fresh device resuming its synced vault (or a newer rev of the
    // same vault written elsewhere)
    const payload = {};
    Object.entries(syncStore).forEach(([k, v]) => {
      if (k.indexOf("smVault") === 0 ? /^smVault\d+$/.test(k) : true) payload[k] = v;
    });
    await chrome.storage.local.set(payload);
    await cleanOrphanParts("local", syncStore.smMeta.parts);
    return await chrome.storage.local.get(null);
  }

  // different vault identity with local data → LOCAL WINS: push the local
  // vault's ciphertext upstream so the stale copy stops shadowing it
  await pushLocalToSync(store);
  return store;
}

/* mirror local vault ciphertext + metadata into sync (no key needed —
 * the blob is already sealed) */
async function pushLocalToSync(store) {
  const sync = syncArea();
  if (!sync) return;
  const payload = {};
  Object.entries(store).forEach(([k, v]) => {
    if (/^sm(Onboarded|Kdf|Salt|Hash|Meta)$/.test(k) || /^smVault\d+$/.test(k)) {
      payload[k] = v;
    }
  });
  if (!payload.smMeta) return;
  try {
    await sync.set(payload);
    await cleanOrphanParts("sync", payload.smMeta.parts);
  } catch {}
}

let mergeTimer = 0;
function queueRemoteChange(incomingMeta) {
  const myRev = window.__rev || 0;
  if (!incomingMeta || (incomingMeta.rev ?? 0) <= myRev) return; // own echo / stale
  clearTimeout(mergeTimer);
  mergeTimer = setTimeout(remoteApply, 900);
}

async function remoteApply() {
  const sync = syncArea();
  const myRev = window.__rev || 0;
  let syncStore = null;
  try { syncStore = await syncArea().get(null); } catch { return; }
  const inRev = syncStore?.smMeta?.rev ?? 0;
  if (inRev <= myRev) return;

  if (!window.__aesKey) {
    // locked → adopt raw; the gate re-reads fresh state on submit
    await adoptRemoteRaw(syncStore);
    return;
  }
  if (syncStore.smSalt !== window.__salt) {
    // A DIFFERENT vault exists upstream. Never hot-swap under an unlocked
    // session (stale sync caches must not clobber freshly written data):
    // local wins while unlocked; boot-time adoptFromSync sorts the rest.
    return;
  }
  let incoming;
  try {
    incoming = await openVault(window.__aesKey, stitchChunks(syncStore, syncStore.smMeta.parts));
  } catch {
    return; // unreadable; our next write will win the revision race
  }

  // union-merge by URL — cross-device duplicates collapse to the earliest
  const byUrl = new Map();
  for (const b of [...incoming, ...window.__vault]) {
    const ex = byUrl.get(b.url);
    if (!ex || (b.addedAt ?? 0) < (ex.addedAt ?? 0)) byUrl.set(b.url, b);
  }
  window.__vault = [...byUrl.values()];
  await persistVault();
  renderBookmarkList();
  toast("Merged from another device ⚡");
}

async function adoptRemoteRaw(syncStore) {
  if (!syncStore || !syncStore.smMeta) return;
  const payload = {};
  Object.entries(syncStore).forEach(([k, v]) => {
    if (k.indexOf("smVault") === 0 ? /^smVault\d+$/.test(k) : true) payload[k] = v;
  });
  await chrome.storage.local.set(payload);
  await cleanOrphanParts("local", syncStore.smMeta.parts);
}

/* ═════════ ONBOARDING · create encrypted vault ═════════ */
async function onSetupSubmit(e) {
  e.preventDefault();
  const err = $("setup-error");
  err.classList.add("hidden");

  const pass = $("setup-pass").value;
  const pass2 = $("setup-pass2").value;

  if (pass.length < 8) return fail(err, $("form-setup"), "Password needs at least 8 characters.");
  if (pass !== pass2) return fail(err, $("form-setup"), "Passwords don't match — try again.");

  const salt = newSalt();
  const { verifier, aes } = await deriveKeys(pass, salt, KDF_ITER);
  window.__salt = salt;
  window.__aesKey = aes;
  window.__vault = [];
  window.__rev = 0;
  await persistVault({
    smOnboarded: true,
    smKdf: SCHEME_V,
    smSalt: salt,
    smHash: verifier,
  });

  setTimeout(() => toast("Encrypted vault created 🔒"), 50);
  renderVault();
}

/* ═════════ LOCK GATE ═════════ */
function showLockout(ms) {
  const err = $("gate-error");
  err.classList.remove("hidden");
  err.textContent = `Too many attempts — wait ${secs(ms)}s before trying again.`;
}

async function onGateSubmit(e) {
  e.preventDefault();
  const err = $("gate-error");
  err.classList.add("hidden");

  const remain = await lockRemainingMs();
  if (remain > 0) return showLockout(remain);

  // read fresh state — sync may have adopted something since boot
  const store = await chrome.storage.local.get(null);
  const pass = $("gate-pass").value;
  let vault = null;

  if (store.smMeta) {
    // ── current chunked layout ──
    const { verifier, aes } = await deriveKeys(pass, store.smSalt,
      store.smKdf === SCHEME_V ? KDF_ITER : LEGACY_ITER);
    if (verifier === store.smHash) {
      try {
        vault = await openVault(aes, stitchChunks(store, store.smMeta.parts));
        window.__aesKey = aes;
        window.__salt = store.smSalt;
        window.__rev = store.smMeta.rev ?? 0;
      } catch {}
    }
  } else if (store.smVault) {
    // ── v1.2/v1.4 single-blob → migrate to chunks ══
    const iter = store.smKdf === SCHEME_V ? KDF_ITER : LEGACY_ITER;
    const { verifier, aes } = await deriveKeys(pass, store.smSalt, iter);
    if (verifier === store.smHash) {
      try {
        vault = await openVault(aes, store.smVault);
        window.__aesKey = aes;
        window.__salt = store.smSalt;
      } catch {}
    }
  } else if (store.smBookmarks) {
    // ── v1.0 plaintext → encrypt everything, upgrade ──
    const legacyVer = await legacyHash(pass, store.smSalt);
    if (legacyVer === store.smHash) {
      const { verifier, aes } = await deriveKeys(pass, store.smSalt, KDF_ITER);
      window.__aesKey = aes;
      window.__salt = store.smSalt;
      vault = store.smBookmarks;
    }
  }

  if (vault === null) {
    const delaySecs = secs(await recordFail());
    return fail(err, $("form-gate"),
      "Wrong password. No recovery exists for this vault." +
      (delaySecs > 1 ? ` Next try in ${delaySecs}s.` : ""));
  }

  await clearFails();
  window.__vault = vault;
  $("gate-pass").value = ""; // drop password from DOM/memory

  // Unify everything to the current chunked layout; legacy layouts migrate
  // here. Migration ORDER matters: re-stretch + re-seal happen before the
  // verifier is updated, so decryption can never succeed with a stale key.
  if (!store.smMeta) {
    const { verifier, aes } = await deriveKeys(pass, window.__salt, KDF_ITER);
    window.__aesKey = aes;
    window.__rev = 0;
    const wasPlain = !!store.smBookmarks;
    await persistVault({
      smOnboarded: true,
      smKdf: SCHEME_V,
      smSalt: window.__salt,
      smHash: verifier,
    });
    // wipe legacy representations in both areas
    const rm = store.smVault ? ["smVault"] : ["smBookmarks"];
    await chrome.storage.local.remove(rm);
    if (syncArea()) {
      try { await chrome.storage.sync.remove(rm); } catch {}
    }
    window.__migrated = wasPlain ? "plain" : "blob";
  } else {
    await persistVault(); // normal unlock — stamps our revision into sync
  }
  renderVault();
  if (window.__migrated) {
    toast(window.__migrated === "plain"
      ? "Upgraded — plaintext copy wiped, vault now syncs 🛡️"
      : "Upgraded — vault now syncs 🛡️");
    window.__migrated = false;
  }
}

/* ═════════ VAULT VIEW ═════════ */
async function renderVault() {
  show("view-vault");
  $("search").addEventListener("input", renderBookmarkList);
  $("btn-lock").addEventListener("click", lockAndExit);
  $("btn-export").addEventListener("click", exportBookmarks);
  $("btn-save-page").addEventListener("click", saveCurrentPage);

  if (HAS_API && !window.__tabListeners) {
    window.__tabListeners = true;
    // switching tabs in the browser must update the "Bookmark this page" row
    chrome.tabs.onActivated.addListener(() => refreshActiveTab());
    chrome.tabs.onUpdated.addListener((tabId, info) => {
      if (window.__tab && tabId === window.__tab.id &&
          (info.url || info.title || info.status === "loading")) {
        refreshActiveTab();
      }
    });
  }

  await refreshActiveTab();
  await renderBookmarkList();
}

/* resolve the user's active tab and refresh the save row.
 * The Side Panel shares the browser window, so currentWindow is the
 * user's browsing context — never the panel itself. */
async function refreshActiveTab() {
  if (!HAS_API) return;
  const tab = await getSourceTab();
  if (tab && tab.url && /^https?:|^file:|^ftp:/i.test(tab.url)) {
    window.__tab = tab;
    $("save-page-url").textContent = tab.url;
    $("btn-save-page").disabled = false;
  } else {
    window.__tab = null;
    $("save-page-url").textContent = "This page can't be bookmarked";
    $("btn-save-page").disabled = true;
  }
}

function renderBookmarkList() {
  const q = ($("search").value || "").trim().toLowerCase();
  const list = q
    ? window.__vault.filter((b) => (b.title + " " + b.url).toLowerCase().includes(q))
    : window.__vault;

  const ul = $("bookmark-list");
  ul.innerHTML = "";
  list.forEach((bm) => ul.appendChild(bmRow(bm)));
  $("empty-state").classList.toggle("hidden", list.length > 0);
}

function bmRow(bm) {
  const li = document.createElement("li");
  li.className = "bm";

  const fav = document.createElement("div");
  fav.className = "bm-fav";
  let host = "•";
  try { host = new URL(bm.url).hostname.replace(/^www\./, ""); } catch {}
  const letter = (host[0] || "•").toUpperCase();

  if (bm.favicon) {
    const img = document.createElement("img");
    img.src = bm.favicon;
    img.onerror = () => { fav.textContent = letter; img.remove(); };
    fav.appendChild(img);
  } else {
    fav.textContent = letter;
  }

  const info = document.createElement("a");
  info.className = "bm-info";
  info.href = bm.url;
  info.target = "_blank";
  info.rel = "noopener";
  info.innerHTML = `<div class="bm-title"></div><div class="bm-url"></div>`;
  info.querySelector(".bm-title").textContent = bm.title || host;
  info.querySelector(".bm-url").textContent = host;

  const del = document.createElement("button");
  del.className = "bm-del";
  del.title = "Delete from vault";
  del.textContent = "🗑";
  del.addEventListener("click", async () => {
    if (!HAS_API) return;
    window.__vault = window.__vault.filter((b) => b.id !== bm.id);
    await persistVault();
    renderBookmarkList();
    toast("Removed from vault");
  });

  li.append(fav, info, del);
  return li;
}

/* ── save current page ── */
async function saveCurrentPage() {
  const tab = window.__tab;
  if (!tab || !tab.url) return;

  if (window.__vault.some((b) => b.url === tab.url)) {
    toast("Already in your vault 🔒");
    return;
  }

  window.__vault.push({
    id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
    title: tab.title || tab.url,
    url: tab.url,
    favicon: tab.favIconUrl && tab.favIconUrl.length < FAVICON_MAX ? tab.favIconUrl : "",
    addedAt: Date.now(),
  });
  await persistVault();
  renderBookmarkList();
  toast("Shielded ✅");
}

/* ── lock & exit ──
 * The AES key + decrypted list live only in this window's memory;
 * closing drops both — the vault on disk stays sealed. */
/* ── wrong-attempt lockout ── */
const secs = (ms) => Math.ceil(ms / 1000);

async function lockRemainingMs() {
  const { smFails = { n: 0, until: 0 } } = await chrome.storage.local.get("smFails");
  return Math.max(0, smFails.until - Date.now());
}

async function recordFail() {
  const { smFails = { n: 0, until: 0 } } = await chrome.storage.local.get("smFails");
  const n = (smFails.n || 0) + 1;
  const delay = Math.min(2 ** n * 500, MAX_LOCK_MS);
  await chrome.storage.local.set({ smFails: { n, until: Date.now() + delay } });
  return delay;
}

async function clearFails() {
  await chrome.storage.local.set({ smFails: { n: 0, until: 0 } });
}

/* ── source tab resolution ──
 * The Side Panel shares the browser window, so the active tab of the
 * current window is the user's browsing tab — never the panel itself.
 * (Headless/tab-based loads return the panel tab, which the caller guards.) */
async function getSourceTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) return tab;
  } catch {}
  return null;
}

/* ── lock & exit closes the Side Panel ── */
async function lockAndExit() {
  window.__vault = null;
  window.__aesKey = null;
  if (HAS_API && chrome.sidePanel?.setOptions) {
    try {
      // no windowId here — some Brave builds reject the property
      await chrome.sidePanel.setOptions({ enabled: false });
    } catch {}
  }
  window.close(); // no-op for a docked panel; keeps behaviour when testing as tab
}

/* ── export (Netscape bookmarks HTML — importable into any browser) ── */
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function exportBookmarks() {
  const all = window.__vault;
  if (!all || !all.length) {
    toast("Vault is empty — nothing to export");
    return;
  }

  const items = all
    .map(
      (b) =>
        `    <DT><A HREF="${esc(b.url)}" ADD_DATE="${Math.floor(b.addedAt / 1000)}">${esc(b.title || b.url)}</A>\n`
    )
    .join("");

  const html =
`<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- This is an automatically generated file. It will be read and overwritten.
     DO NOT EDIT! -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Safemark Bookmarks</TITLE>
<H1>Safemark Bookmarks</H1>
<DL><p>
${items}</DL><p>
`;

  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "safemark-vault-bookmarks.html";
  a.click();
  URL.revokeObjectURL(url);
  toast("Exported ⤓");
}

/* ── password strength meter ── */
function passStrength(p) {
  if (!p) return { score: 0, label: "" };
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(p)).length;
  let score = 0;
  if (p.length >= 8) score++;
  if (p.length >= 12) score++;
  if (p.length >= 16) score++;
  if (classes >= 2) score++;
  if (classes >= 3) score++;
  if (classes >= 4 && p.length >= 12) score++;
  const labels = ["Very weak", "Weak", "Okay", "Good", "Strong", "Fortress"];
  return { score, label: labels[Math.min(score, 5)] };
}

function updateStrengthMeter() {
  const p = $("setup-pass").value;
  const meterFill = $("meter-fill");
  const label = $("meter-label");
  const { score, label: text } = passStrength(p);
  const colors = ["#ff6080", "#ff6080", "#ffb454", "#ffb454", "#4ade80", "#4ade80"];
  meterFill.style.width = `${(Math.min(score, 5) / 5) * 100}%`;
  meterFill.style.background = colors[Math.min(score, 5)];
  label.textContent = p ? `${text} — aim for 12+ characters` : "";
}
