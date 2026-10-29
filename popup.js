/* ═════════ Safemark v1.8.0 · popup logic ═════════
 *
 * Storage layout (chrome.storage.local + mirrored to chrome.storage.sync):
 *   smOnboarded  {boolean}   onboarding finished
 *   smKdf        {number}    scheme version (3 = 600k-iteration PBKDF2)
 *   smSalt       {string}    hex salt (16 bytes)
 *   smHash       {string}    hex password verifier (32 bytes)
 *   smMeta       {object}    { iv, rev, parts } — vault envelope metadata
 *   smVault0..N  {string}    AES-256-GCM ciphertext chunks
 *   smFails      {object}    { n, until } — wrong-attempt lockout
 *   smSettings   {object}    { autoLock, blurLock, sortBy } — local prefs
 *   smPasskey    {object}    { credId } — WebAuthn credential id (base64)
 *   smPasskeyMat {object}    { iv, ct } — password wrapped by PRF-derived key
 *
 * v1.8 new features:
 *   1.  Auto-lock on idle (configurable 5/15/30 min)
 *   2.  Copy URL to clipboard per bookmark
 *   3.  Editable title + tags before saving
 *   4.  Change password (settings view)
 *   5.  Sort: Newest / Oldest / A–Z / Z–A
 *   6.  Tags on bookmarks + tag filter bar
 *   7.  Import Netscape bookmark HTML
 *   8.  Keyboard shortcuts (/ = focus search, Esc = clear/cancel, Ctrl+Shift+S via background)
 *   9.  Bulk select + delete
 *   10. Per-bookmark notes (collapsible, encrypted with vault)
 *   11. Auto-lock on window/tab blur
 *   12. WebAuthn / passkey unlock via PRF extension
 */

const HAS_API =
  typeof chrome !== "undefined" && !!(chrome.storage && chrome.tabs);

const KDF_ITER   = 600000;
const LEGACY_ITER = 210000;
const SCHEME_V   = 3;
const MAX_LOCK_MS = 60000;

const SYNC_CHUNK  = 7000;
const FAVICON_MAX = 2048;

const PRF_LABEL = "safemark-prf-v1";    // constant PRF input label
const WRAP_SALT = "safemark-wrap-v1";   // constant PBKDF2 salt label for wrap key

/* ── v1.8 state ── */
let __settings    = { autoLock: 0, blurLock: false, sortBy: "newest" };
let __idleTimer   = 0;
let __activeTag   = null;
let __selectMode  = false;
let __selectedIds = new Set();

/* ── DOM helpers ── */
const $ = (id) => document.getElementById(id);
const views = ["view-welcome", "view-setup", "view-gate", "view-vault", "view-settings"];

function show(viewId) {
  views.forEach((v) => { const el = $(v); if (el) el.classList.toggle("hidden", v !== viewId); });
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
  void form.offsetWidth;
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

async function legacyHash(password, saltHex) {
  return bufToHex(await pbkdf2Bits(password, saltHex, 256, LEGACY_ITER));
}

async function deriveKeys(password, saltHex, iter = KDF_ITER) {
  const bits = new Uint8Array(await pbkdf2Bits(password, saltHex, 512, iter));
  const verifier = bufToHex(bits.slice(0, 32));
  const aes = await crypto.subtle.importKey(
    "raw", bits.slice(32), "AES-GCM", false, ["encrypt", "decrypt"]
  );
  return { verifier, aes };
}

/* ── vault sealing ── */
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

/* ── chunking ── */
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

async function persistVault(extra = {}) {
  const sealed = await sealVault(window.__aesKey, window.__vault);
  const rev = (window.__rev || 0) + 1;
  window.__rev = rev;

  const chunks = chunkStr(sealed.ct);
  const keep = chunks.length;
  const data = { smMeta: { iv: sealed.iv, rev }, ...extra };
  data.smMeta.parts = keep;
  chunks.forEach((c, i) => { data["smVault" + i] = c; });

  await chrome.storage.local.set(data);
  let synced = true;
  try {
    await chrome.storage.sync.set(data);
  } catch {
    window.__syncFailed = true;
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
    document.body.classList.add("panel");
  }
  if (!HAS_API) {
    window.__vault = [
      { id: "d1", title: "Hacker News", url: "https://news.ycombinator.com/", favicon: "", tags: [], note: "", addedAt: Date.now() },
      { id: "d2", title: "MDN Web Docs", url: "https://developer.mozilla.org/", favicon: "", tags: ["dev"], note: "", addedAt: Date.now() - 1e5 },
    ];
    renderVault();
    return;
  }

  /* load settings before anything else */
  await loadSettings();

  let store = await chrome.storage.local.get(null);
  store = await adoptFromSync(store);

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
    await updatePasskeyGateButton();
  }

  await showPanelNotice();

  /* global keyboard shortcuts */
  document.addEventListener("keydown", onKeyDown);

  /* background shortcut: Ctrl+Shift+S */
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "shortcut-save-page" && window.__aesKey) showSaveEdit();
  });

  /* auto-lock on visibility change (blur) */
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && __settings.blurLock && window.__aesKey) {
      lockAndExit();
    }
  });
}

/* ── Panel failure notice (kept from v1.7) ── */
async function showPanelNotice() {
  if (!HAS_API || typeof document === "undefined") return;
  try {
    const { smPanelErr } = await chrome.storage.local.get("smPanelErr");
    if (!smPanelErr) return;
    const app = document.querySelector(".app");
    if (!app || document.querySelector(".panel-note")) return;
    const escStr = (s) => String(s).replace(/[<>&]/g, (c) =>
      ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
    const note = document.createElement("div");
    note.className = "panel-note";
    note.innerHTML =
      '<div class="pn-text"><b>⚠️ Docked panel couldn\'t open — showing in a tab instead.</b><br>' +
      '<span class="pn-reason">reason: ' + escStr(smPanelErr) + "</span><br>" +
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

/* ═════════ SETTINGS ═════════ */
async function loadSettings() {
  if (!HAS_API) return;
  try {
    const { smSettings } = await chrome.storage.local.get("smSettings");
    if (smSettings) Object.assign(__settings, smSettings);
  } catch {}
}

async function saveSettings() {
  if (!HAS_API) return;
  await chrome.storage.local.set({ smSettings: __settings });
}

function openSettings() {
  $("autolock-select").value  = String(__settings.autoLock);
  $("blur-lock-toggle").checked = __settings.blurLock;
  $("sort-select").value      = __settings.sortBy;
  $("stat-count").textContent = window.__vault ? window.__vault.length : "—";
  updatePasskeySettingsUI();
  show("view-settings");
}

function wireSettingsListeners() {
  $("btn-settings-back").addEventListener("click", () => {
    show("view-vault");
  });

  $("autolock-select").addEventListener("change", async () => {
    __settings.autoLock = parseInt($("autolock-select").value, 10);
    await saveSettings();
    resetIdleTimer();
    toast(__settings.autoLock === 0 ? "Auto-lock disabled" : `Auto-lock: ${__settings.autoLock} min`);
  });

  $("blur-lock-toggle").addEventListener("change", async () => {
    __settings.blurLock = $("blur-lock-toggle").checked;
    await saveSettings();
    toast(__settings.blurLock ? "Lock on blur enabled" : "Lock on blur disabled");
  });

  $("form-chpass").addEventListener("submit", onChangePassword);
  $("btn-passkey-enroll").addEventListener("click", enrollPasskey);
  $("btn-passkey-remove").addEventListener("click", removePasskey);
}

/* ═════════ AUTO-LOCK ═════════ */
function resetIdleTimer() {
  clearTimeout(__idleTimer);
  if (__settings.autoLock <= 0 || !window.__aesKey) return;
  __idleTimer = setTimeout(() => {
    toast("Auto-locked after idle ⏱");
    lockAndExit();
  }, __settings.autoLock * 60 * 1000);
}

function touchIdle() {
  if (window.__aesKey) resetIdleTimer();
}

/* ═════════ KEYBOARD SHORTCUTS ═════════ */
function onKeyDown(e) {
  /* / → focus search when vault is open */
  if (
    e.key === "/" &&
    document.activeElement?.tagName !== "INPUT" &&
    document.activeElement?.tagName !== "TEXTAREA" &&
    !$("view-vault").classList.contains("hidden")
  ) {
    e.preventDefault();
    $("search").focus();
    return;
  }
  /* Esc → cancel save-edit or clear search */
  if (e.key === "Escape") {
    if (!$("save-row-edit").classList.contains("hidden")) {
      hideSaveEdit(); return;
    }
    if ($("search").value) {
      $("search").value = "";
      renderBookmarkList(); return;
    }
  }
}

/* ═════════ CHANGE PASSWORD ═════════ */
async function onChangePassword(e) {
  e.preventDefault();
  const errEl = $("chpass-error");
  const okEl  = $("chpass-ok");
  errEl.classList.add("hidden");
  okEl.classList.add("hidden");

  const cur = $("chpass-current").value;
  const nw  = $("chpass-new").value;
  const nw2 = $("chpass-confirm").value;

  if (nw.length < 8) {
    errEl.textContent = "New password needs at least 8 characters.";
    errEl.classList.remove("hidden"); return;
  }
  if (nw !== nw2) {
    errEl.textContent = "New passwords don't match.";
    errEl.classList.remove("hidden"); return;
  }

  const store = await chrome.storage.local.get(["smSalt", "smHash", "smKdf"]);
  const iter  = store.smKdf === SCHEME_V ? KDF_ITER : LEGACY_ITER;
  const { verifier } = await deriveKeys(cur, store.smSalt, iter);
  if (verifier !== store.smHash) {
    errEl.textContent = "Current password is wrong.";
    errEl.classList.remove("hidden");
    $("form-chpass").classList.remove("shake");
    void $("form-chpass").offsetWidth;
    $("form-chpass").classList.add("shake");
    return;
  }

  const { verifier: newVer, aes: newAes } = await deriveKeys(nw, store.smSalt, KDF_ITER);
  window.__aesKey = newAes;
  await persistVault({ smKdf: SCHEME_V, smHash: newVer });

  /* if passkey enrolled, remove it — it was wrapping the old password */
  const { smPasskey } = await chrome.storage.local.get("smPasskey");
  if (smPasskey) {
    await chrome.storage.local.remove(["smPasskey", "smPasskeyMat"]);
    updatePasskeySettingsUI();
    okEl.textContent = "Password changed ✓  (Biometric unlock removed — re-enroll in settings)";
  } else {
    okEl.textContent = "Password changed ✓";
  }

  $("chpass-current").value = "";
  $("chpass-new").value     = "";
  $("chpass-confirm").value = "";
  okEl.classList.remove("hidden");

  /* update stored raw pass for passkey if needed */
  window.__rawPass = nw;
  setTimeout(() => { window.__rawPass = null; }, 30000);
  await updatePasskeyGateButton();
}

/* ═════════ SAVE EDIT FLOW ═════════ */
function showSaveEdit() {
  const tab = window.__tab;
  if (!tab || !tab.url) return;

  let domain = "";
  try { domain = new URL(tab.url).hostname.replace(/^www\./, ""); } catch {}

  $("save-title-input").value  = tab.title || domain;
  $("save-tag-input").value    = "";
  $("save-edit-domain").textContent = domain;

  $("save-row-idle").classList.add("hidden");
  $("save-row-edit").classList.remove("hidden");
  $("save-title-input").focus();
  $("save-title-input").select();
}

function hideSaveEdit() {
  $("save-row-edit").classList.add("hidden");
  $("save-row-idle").classList.remove("hidden");
}

/* ═════════ SORT ═════════ */
function sortedVault() {
  const v = [...(window.__vault || [])];
  const filtered = __activeTag
    ? v.filter(b => (b.tags || []).includes(__activeTag))
    : v;
  switch (__settings.sortBy) {
    case "oldest": return filtered.sort((a, b) => (a.addedAt || 0) - (b.addedAt || 0));
    case "az":     return filtered.sort((a, b) => (a.title || "").localeCompare(b.title || ""));
    case "za":     return filtered.sort((a, b) => (b.title || "").localeCompare(a.title || ""));
    default:       return filtered.sort((a, b) => (b.addedAt || 0) - (a.addedAt || 0));
  }
}

/* ═════════ TAGS ═════════ */
function allTags() {
  const set = new Set();
  (window.__vault || []).forEach(b => (b.tags || []).forEach(t => set.add(t)));
  return [...set].sort();
}

function renderTagFilterBar() {
  const bar  = $("tag-filter-bar");
  const tags = allTags();
  if (!tags.length) { bar.classList.add("hidden"); return; }
  bar.classList.remove("hidden");
  bar.innerHTML = "";
  tags.forEach(tag => {
    const chip = document.createElement("button");
    chip.className = "tag-chip" + (tag === __activeTag ? " active" : "");
    chip.textContent = "# " + tag;
    chip.addEventListener("click", () => {
      __activeTag = __activeTag === tag ? null : tag;
      renderTagFilterBar();
      renderBookmarkList();
    });
    bar.appendChild(chip);
  });
}

/* ═════════ IMPORT ═════════ */
function handleImportFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async (ev) => {
    const html   = ev.target.result;
    const parser = new DOMParser();
    const doc    = parser.parseFromString(html, "text/html");
    const links  = [...doc.querySelectorAll("a[href]")];
    const existing = new Set((window.__vault || []).map(b => b.url));
    let added = 0;
    for (const a of links) {
      const url = a.getAttribute("href");
      if (!url || !/^https?:/.test(url) || existing.has(url)) continue;
      const addDate = parseInt(a.getAttribute("add_date") || "0", 10);
      window.__vault.push({
        id:      crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
        title:   a.textContent.trim() || url,
        url,
        favicon: "",
        tags:    [],
        note:    "",
        addedAt: addDate ? addDate * 1000 : Date.now(),
      });
      existing.add(url);
      added++;
    }
    if (added > 0) {
      await persistVault();
      renderTagFilterBar();
      renderBookmarkList();
      toast(`Imported ${added} bookmark${added === 1 ? "" : "s"} ✓`);
    } else {
      toast("No new bookmarks found");
    }
    $("import-file").value = "";
  };
  reader.readAsText(file);
}

/* ═════════ BULK SELECT ═════════ */
function toggleSelectMode() {
  __selectMode = !__selectMode;
  __selectedIds.clear();
  document.body.classList.toggle("selecting", __selectMode);
  $("bulk-bar").classList.toggle("hidden", !__selectMode);
  $("btn-select-mode").style.color = __selectMode ? "var(--accent)" : "";
  updateBulkBar();
  renderBookmarkList();
}

function exitSelectMode() {
  __selectMode = false;
  __selectedIds.clear();
  document.body.classList.remove("selecting");
  $("bulk-bar").classList.add("hidden");
  $("btn-select-mode").style.color = "";
  renderBookmarkList();
}

function updateBulkBar() {
  $("bulk-count").textContent = `${__selectedIds.size} selected`;
  $("btn-bulk-delete").disabled = __selectedIds.size === 0;
}

async function bulkDelete() {
  if (!__selectedIds.size) return;
  const count = __selectedIds.size;
  window.__vault = window.__vault.filter(b => !__selectedIds.has(b.id));
  await persistVault();
  exitSelectMode();
  renderTagFilterBar();
  renderBookmarkList();
  toast(`Deleted ${count} bookmark${count === 1 ? "" : "s"}`);
}

/* ═════════ WEBAUTHN / PASSKEY ═════════ */
async function updatePasskeyGateButton() {
  if (!HAS_API) return;
  try {
    const { smPasskey } = await chrome.storage.local.get("smPasskey");
    const supported = !!window.PublicKeyCredential;
    $("btn-passkey-unlock").classList.toggle("hidden", !(smPasskey && supported));
  } catch {}
}

async function updatePasskeySettingsUI() {
  if (!HAS_API) return;
  try {
    const { smPasskey } = await chrome.storage.local.get("smPasskey");
    $("passkey-enrolled").classList.toggle("hidden", !smPasskey);
    $("passkey-not-enrolled").classList.toggle("hidden", !!smPasskey);
    $("passkey-error").classList.add("hidden");
  } catch {}
}

async function enrollPasskey() {
  const errEl = $("passkey-error");
  errEl.classList.add("hidden");

  if (!window.PublicKeyCredential) {
    errEl.textContent = "WebAuthn not supported in this browser.";
    errEl.classList.remove("hidden"); return;
  }
  if (!window.__rawPass) {
    errEl.textContent = "Session expired. Lock and unlock with your password first, then enroll biometric.";
    errEl.classList.remove("hidden"); return;
  }

  try {
    const userId    = crypto.getRandomValues(new Uint8Array(16));
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    /* Step 1: create credential */
    const cred = await navigator.credentials.create({
      publicKey: {
        rp:   { name: "Safemark" },
        user: { id: userId, name: "vault", displayName: "Safemark Vault" },
        challenge,
        pubKeyCredParams: [
          { type: "public-key", alg: -7   },  // ES256
          { type: "public-key", alg: -257 },  // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "preferred",
        },
        extensions: { prf: {} },
        timeout: 60000,
      }
    });

    /* Step 2: assertion to get PRF output */
    const prfInput  = enc.encode(PRF_LABEL);
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: cred.rawId }],
        userVerification: "required",
        extensions: { prf: { eval: { first: prfInput } } },
        timeout: 60000,
      }
    });

    const prfResult = assertion.getClientExtensionResults()?.prf?.results?.first;
    if (!prfResult) {
      errEl.textContent = "Your device/authenticator does not support the PRF extension required for biometric unlock. Try a different device.";
      errEl.classList.remove("hidden"); return;
    }

    /* Step 3: derive wrap key from PRF output */
    const prfKey = await crypto.subtle.importKey("raw", prfResult, "PBKDF2", false, ["deriveBits"]);
    const wrapBits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: enc.encode(WRAP_SALT), iterations: 100000, hash: "SHA-256" },
      prfKey, 256
    );
    const wrapKey = await crypto.subtle.importKey("raw", wrapBits, "AES-GCM", false, ["encrypt", "decrypt"]);

    /* Step 4: encrypt the raw password under wrapKey */
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, enc.encode(window.__rawPass));

    const credIdB64 = bufToB64(new Uint8Array(cred.rawId));
    await chrome.storage.local.set({
      smPasskey:    { credId: credIdB64 },
      smPasskeyMat: { iv: bufToB64(iv), ct: bufToB64(ct) },
    });

    await updatePasskeySettingsUI();
    await updatePasskeyGateButton();
    toast("Biometric unlock enabled 🔑");
  } catch (err) {
    errEl.textContent = err.name === "NotAllowedError"
      ? "Biometric enrollment cancelled."
      : "Error: " + (err.message || String(err));
    errEl.classList.remove("hidden");
  }
}

async function removePasskey() {
  if (!HAS_API) return;
  await chrome.storage.local.remove(["smPasskey", "smPasskeyMat"]);
  await updatePasskeySettingsUI();
  await updatePasskeyGateButton();
  toast("Biometric unlock removed");
}

async function passkeyUnlock() {
  const errEl = $("gate-error");
  errEl.classList.add("hidden");

  try {
    const { smPasskey, smPasskeyMat } = await chrome.storage.local.get(["smPasskey", "smPasskeyMat"]);
    if (!smPasskey || !smPasskeyMat) {
      errEl.textContent = "No biometric credential found. Use your password.";
      errEl.classList.remove("hidden"); return;
    }

    const credIdBytes = b64ToBuf(smPasskey.credId);
    const prfInput    = enc.encode(PRF_LABEL);

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: credIdBytes }],
        userVerification: "required",
        extensions: { prf: { eval: { first: prfInput } } },
        timeout: 60000,
      }
    });

    const prfResult = assertion.getClientExtensionResults()?.prf?.results?.first;
    if (!prfResult) {
      errEl.textContent = "Biometric unlock failed — device returned no PRF result.";
      errEl.classList.remove("hidden"); return;
    }

    const prfKey = await crypto.subtle.importKey("raw", prfResult, "PBKDF2", false, ["deriveBits"]);
    const wrapBits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: enc.encode(WRAP_SALT), iterations: 100000, hash: "SHA-256" },
      prfKey, 256
    );
    const wrapKey = await crypto.subtle.importKey("raw", wrapBits, "AES-GCM", false, ["encrypt", "decrypt"]);

    const pwBytes = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBuf(smPasskeyMat.iv) }, wrapKey, b64ToBuf(smPasskeyMat.ct)
    );
    const password = new TextDecoder().decode(pwBytes);

    /* feed recovered password into normal gate submit */
    $("gate-pass").value = password;
    $("form-gate").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  } catch (err) {
    errEl.textContent = err.name === "NotAllowedError"
      ? "Biometric cancelled."
      : "Biometric unlock error: " + (err.message || String(err));
    errEl.classList.remove("hidden");
  }
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
  const sameVault  =
    store.smHash && store.smSalt &&
    syncStore.smSalt === store.smSalt && syncStore.smHash === store.smHash;

  if (localEmpty || sameVault) {
    const payload = {};
    Object.entries(syncStore).forEach(([k, v]) => {
      if (k.indexOf("smVault") === 0 ? /^smVault\d+$/.test(k) : true) payload[k] = v;
    });
    await chrome.storage.local.set(payload);
    await cleanOrphanParts("local", syncStore.smMeta.parts);
    return await chrome.storage.local.get(null);
  }

  await pushLocalToSync(store);
  return store;
}

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
  if (!incomingMeta || (incomingMeta.rev ?? 0) <= myRev) return;
  clearTimeout(mergeTimer);
  mergeTimer = setTimeout(remoteApply, 900);
}

async function remoteApply() {
  const myRev = window.__rev || 0;
  let syncStore = null;
  try { syncStore = await syncArea().get(null); } catch { return; }
  const inRev = syncStore?.smMeta?.rev ?? 0;
  if (inRev <= myRev) return;

  if (!window.__aesKey) { await adoptRemoteRaw(syncStore); return; }
  if (syncStore.smSalt !== window.__salt) return;

  let incoming;
  try {
    incoming = await openVault(window.__aesKey, stitchChunks(syncStore, syncStore.smMeta.parts));
  } catch { return; }

  const byUrl = new Map();
  for (const b of [...incoming, ...window.__vault]) {
    const ex = byUrl.get(b.url);
    if (!ex || (b.addedAt ?? 0) < (ex.addedAt ?? 0)) byUrl.set(b.url, b);
  }
  window.__vault = [...byUrl.values()];
  await persistVault();
  renderTagFilterBar();
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

/* ═════════ ONBOARDING ═════════ */
async function onSetupSubmit(e) {
  e.preventDefault();
  const err = $("setup-error");
  err.classList.add("hidden");

  const pass  = $("setup-pass").value;
  const pass2 = $("setup-pass2").value;

  if (pass.length < 8) return fail(err, $("form-setup"), "Password needs at least 8 characters.");
  if (pass !== pass2)  return fail(err, $("form-setup"), "Passwords don't match — try again.");

  const salt = newSalt();
  const { verifier, aes } = await deriveKeys(pass, salt, KDF_ITER);
  window.__salt    = salt;
  window.__aesKey  = aes;
  window.__vault   = [];
  window.__rev     = 0;
  window.__rawPass = pass;
  setTimeout(() => { window.__rawPass = null; }, 30000);

  await persistVault({
    smOnboarded: true,
    smKdf:  SCHEME_V,
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

  const store = await chrome.storage.local.get(null);
  const pass  = $("gate-pass").value;
  let vault   = null;

  if (store.smMeta) {
    const { verifier, aes } = await deriveKeys(pass, store.smSalt,
      store.smKdf === SCHEME_V ? KDF_ITER : LEGACY_ITER);
    if (verifier === store.smHash) {
      try {
        vault = await openVault(aes, stitchChunks(store, store.smMeta.parts));
        window.__aesKey = aes;
        window.__salt   = store.smSalt;
        window.__rev    = store.smMeta.rev ?? 0;
      } catch {}
    }
  } else if (store.smVault) {
    const iter = store.smKdf === SCHEME_V ? KDF_ITER : LEGACY_ITER;
    const { verifier, aes } = await deriveKeys(pass, store.smSalt, iter);
    if (verifier === store.smHash) {
      try {
        vault = await openVault(aes, store.smVault);
        window.__aesKey = aes;
        window.__salt   = store.smSalt;
      } catch {}
    }
  } else if (store.smBookmarks) {
    const legacyVer = await legacyHash(pass, store.smSalt);
    if (legacyVer === store.smHash) {
      const { verifier, aes } = await deriveKeys(pass, store.smSalt, KDF_ITER);
      window.__aesKey = aes;
      window.__salt   = store.smSalt;
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
  window.__vault   = vault;
  window.__rawPass = pass;
  $("gate-pass").value = "";
  setTimeout(() => { window.__rawPass = null; }, 30000);

  if (!store.smMeta) {
    const { verifier, aes } = await deriveKeys(pass, window.__salt, KDF_ITER);
    window.__aesKey = aes;
    window.__rev    = 0;
    const wasPlain  = !!store.smBookmarks;
    await persistVault({
      smOnboarded: true,
      smKdf:  SCHEME_V,
      smSalt: window.__salt,
      smHash: verifier,
    });
    const rm = store.smVault ? ["smVault"] : ["smBookmarks"];
    await chrome.storage.local.remove(rm);
    if (syncArea()) { try { await chrome.storage.sync.remove(rm); } catch {} }
    window.__migrated = wasPlain ? "plain" : "blob";
  } else {
    await persistVault();
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

  /* wire listeners once */
  if (!window.__vaultWired) {
    window.__vaultWired = true;

    $("search").addEventListener("input", renderBookmarkList);
    $("btn-lock").addEventListener("click", lockAndExit);
    $("btn-export").addEventListener("click", exportBookmarks);

    /* save flow */
    $("btn-save-page").addEventListener("click", () => {
      if (!$("btn-save-page").disabled) showSaveEdit();
    });
    $("btn-save-confirm").addEventListener("click", saveCurrentPage);
    $("btn-save-cancel").addEventListener("click", hideSaveEdit);

    /* toolbar */
    $("sort-select").addEventListener("change", async () => {
      __settings.sortBy = $("sort-select").value;
      await saveSettings();
      renderBookmarkList();
    });
    $("btn-select-mode").addEventListener("click", toggleSelectMode);
    $("btn-bulk-delete").addEventListener("click", bulkDelete);
    $("btn-cancel-select").addEventListener("click", exitSelectMode);
    $("btn-import").addEventListener("click", () => $("import-file").click());
    $("import-file").addEventListener("change", handleImportFile);

    /* settings */
    $("btn-settings").addEventListener("click", openSettings);
    wireSettingsListeners();

    /* passkey on gate */
    $("btn-passkey-unlock").addEventListener("click", passkeyUnlock);

    /* tab listeners */
    if (HAS_API) {
      chrome.tabs.onActivated.addListener(() => refreshActiveTab());
      chrome.tabs.onUpdated.addListener((tabId, info) => {
        if (window.__tab && tabId === window.__tab.id &&
            (info.url || info.title || info.status === "loading")) {
          refreshActiveTab();
        }
      });
    }

    /* idle reset */
    ["click", "keydown", "mousemove", "touchstart"].forEach(ev =>
      document.addEventListener(ev, touchIdle, { passive: true })
    );
  }

  /* sync UI state with settings */
  $("sort-select").value = __settings.sortBy;

  await refreshActiveTab();
  resetIdleTimer();
  renderTagFilterBar();
  renderBookmarkList();
}

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
  const q    = ($("search").value || "").trim().toLowerCase();
  const all  = sortedVault();
  const list = q
    ? all.filter(b =>
        (b.title + " " + b.url + " " + (b.tags || []).join(" "))
          .toLowerCase().includes(q))
    : all;

  const ul = $("bookmark-list");
  ul.innerHTML = "";
  list.forEach(bm => ul.appendChild(bmRow(bm)));
  $("empty-state").classList.toggle("hidden", list.length > 0);
}

/* ─── Avatar colors ─── */
const AVATAR_COLORS = [
  ["#F59E0B", "#000"], // amber
  ["#10B981", "#000"], // emerald
  ["#3B82F6", "#fff"], // blue
  ["#8B5CF6", "#fff"], // violet
  ["#EF4444", "#fff"], // red
  ["#EC4899", "#fff"], // pink
  ["#06B6D4", "#000"], // cyan
  ["#F97316", "#000"], // orange
];

function avatarColor(host) {
  let h = 0;
  for (let i = 0; i < host.length; i++) h = (h * 31 + host.charCodeAt(i)) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

function bmRow(bm) {
  const li = document.createElement("li");
  li.className = "bm";
  li.dataset.id = bm.id;

  /* checkbox (bulk select) */
  const cbWrap = document.createElement("div");
  cbWrap.className = "bm-checkbox-wrap";
  const cb = document.createElement("input");
  cb.type      = "checkbox";
  cb.className = "bm-checkbox";
  cb.checked   = __selectedIds.has(bm.id);
  cb.addEventListener("change", () => {
    if (cb.checked) __selectedIds.add(bm.id);
    else __selectedIds.delete(bm.id);
    updateBulkBar();
  });
  cbWrap.appendChild(cb);

  /* avatar */
  const fav = document.createElement("div");
  fav.className = "bm-fav";
  let host = "•";
  try { host = new URL(bm.url).hostname.replace(/^www\./, ""); } catch {}
  const letter = (host[0] || "•").toUpperCase();
  const [bg, fg] = avatarColor(host);
  fav.style.background = bg;
  fav.style.color = fg;

  if (bm.favicon) {
    const img = document.createElement("img");
    img.src = bm.favicon;
    img.onerror = () => { fav.textContent = letter; img.remove(); };
    fav.appendChild(img);
  } else {
    fav.textContent = letter;
  }

  /* info */
  const info = document.createElement("a");
  info.className = "bm-info";
  info.href      = bm.url;
  info.target    = "_blank";
  info.rel       = "noopener";

  const titleEl = document.createElement("div");
  titleEl.className   = "bm-title";
  titleEl.textContent = bm.title || host;

  const urlEl = document.createElement("div");
  urlEl.className   = "bm-url";
  urlEl.textContent = host;

  info.appendChild(titleEl);
  info.appendChild(urlEl);

  /* tags */
  if (bm.tags && bm.tags.length) {
    const tagsEl = document.createElement("div");
    tagsEl.className = "bm-tags";
    bm.tags.forEach(t => {
      const chip = document.createElement("span");
      chip.className   = "bm-tag";
      chip.textContent = t;
      tagsEl.appendChild(chip);
    });
    info.appendChild(tagsEl);
  }

  /* action buttons */
  const actions = document.createElement("div");
  actions.className = "bm-actions";

  /* copy URL */
  const copyBtn = document.createElement("button");
  copyBtn.className = "bm-copy";
  copyBtn.title     = "Copy URL";
  copyBtn.textContent = "📋";
  copyBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    try {
      await navigator.clipboard.writeText(bm.url);
    } catch {
      const inp = document.createElement("input");
      inp.value = bm.url;
      document.body.appendChild(inp);
      inp.select();
      document.execCommand("copy");
      inp.remove();
    }
    toast("URL copied ✓");
  });

  /* note toggle */
  const noteBtn = document.createElement("button");
  noteBtn.className   = "bm-note-toggle" + (bm.note ? " has-note" : "");
  noteBtn.title       = bm.note ? "View/edit note" : "Add note";
  noteBtn.textContent = "📝";

  /* delete */
  const del = document.createElement("button");
  del.className   = "bm-del";
  del.title       = "Delete from vault";
  del.textContent = "🗑";
  del.addEventListener("click", async () => {
    if (!HAS_API) return;
    window.__vault = window.__vault.filter(b => b.id !== bm.id);
    await persistVault();
    renderTagFilterBar();
    renderBookmarkList();
    toast("Removed from vault");
  });

  actions.append(copyBtn, noteBtn, del);

  /* collapsible note area */
  const noteArea = document.createElement("div");
  noteArea.className = "bm-note-area hidden";

  const noteText = document.createElement("textarea");
  noteText.className   = "bm-note-text";
  noteText.placeholder = "Private note (encrypted with your vault)…";
  noteText.value       = bm.note || "";
  noteText.rows        = 3;

  const noteSave = document.createElement("button");
  noteSave.className   = "bm-note-save";
  noteSave.textContent = "Save note";
  noteSave.addEventListener("click", async () => {
    const entry = window.__vault.find(b => b.id === bm.id);
    if (entry) {
      entry.note = noteText.value.trim();
      await persistVault();
      noteBtn.className = "bm-note-toggle" + (entry.note ? " has-note" : "");
      noteBtn.title     = entry.note ? "View/edit note" : "Add note";
      toast("Note saved 🔒");
    }
  });

  noteArea.append(noteText, noteSave);

  noteBtn.addEventListener("click", (e) => {
    e.preventDefault();
    noteArea.classList.toggle("hidden");
    if (!noteArea.classList.contains("hidden")) noteText.focus();
  });

  li.append(cbWrap, fav, info, actions, noteArea);
  return li;
}

/* ═════════ SAVE CURRENT PAGE ═════════ */
async function saveCurrentPage() {
  const tab = window.__tab;
  if (!tab || !tab.url) return;

  const editVisible = !$("save-row-edit").classList.contains("hidden");
  const titleVal = editVisible
    ? ($("save-title-input").value.trim() || tab.title || tab.url)
    : (tab.title || tab.url);
  const tagsRaw = editVisible ? $("save-tag-input").value.trim() : "";
  const tags    = tagsRaw
    ? tagsRaw.split(",").map(t => t.trim().toLowerCase()).filter(Boolean)
    : [];

  if (window.__vault.some(b => b.url === tab.url)) {
    toast("Already in your vault 🔒");
    hideSaveEdit();
    return;
  }

  window.__vault.push({
    id:      crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
    title:   titleVal,
    url:     tab.url,
    favicon: tab.favIconUrl && tab.favIconUrl.length < FAVICON_MAX ? tab.favIconUrl : "",
    tags,
    note:    "",
    addedAt: Date.now(),
  });
  await persistVault();
  hideSaveEdit();
  renderTagFilterBar();
  renderBookmarkList();
  toast("Shielded ✅");
  touchIdle();
}

/* ═════════ LOCK ═════════ */
const secs = (ms) => Math.ceil(ms / 1000);

async function lockRemainingMs() {
  const { smFails = { n: 0, until: 0 } } = await chrome.storage.local.get("smFails");
  return Math.max(0, smFails.until - Date.now());
}

async function recordFail() {
  const { smFails = { n: 0, until: 0 } } = await chrome.storage.local.get("smFails");
  const n     = (smFails.n || 0) + 1;
  const delay = Math.min(2 ** n * 500, MAX_LOCK_MS);
  await chrome.storage.local.set({ smFails: { n, until: Date.now() + delay } });
  return delay;
}

async function clearFails() {
  await chrome.storage.local.set({ smFails: { n: 0, until: 0 } });
}

async function getSourceTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) return tab;
  } catch {}
  return null;
}

async function lockAndExit() {
  clearTimeout(__idleTimer);
  window.__vault   = null;
  window.__aesKey  = null;
  window.__salt    = null;
  window.__rev     = 0;
  window.__rawPass = null;
  __selectedIds.clear();
  __activeTag = null;
  if (__selectMode) exitSelectMode();

  if (HAS_API) {
    const store = await chrome.storage.local.get(["smOnboarded", "smSalt", "smHash"]);
    if (store.smOnboarded && store.smSalt && store.smHash) {
      $("gate-pass").value = "";
      $("gate-error").classList.add("hidden");
      await updatePasskeyGateButton();
      show("view-gate");
      setTimeout(() => $("gate-pass").focus(), 50);
    }
  }
}

/* ═════════ EXPORT ═════════ */
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function exportBookmarks() {
  const all = window.__vault;
  if (!all || !all.length) { toast("Vault is empty — nothing to export"); return; }

  const items = all
    .map(b => `    <DT><A HREF="${esc(b.url)}" ADD_DATE="${Math.floor(b.addedAt / 1000)}">${esc(b.title || b.url)}</A>\n`)
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
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = "safemark-vault-bookmarks.html";
  a.click();
  URL.revokeObjectURL(url);
  toast("Exported ⤓");
}

/* ═════════ PASSWORD STRENGTH ═════════ */
function passStrength(p) {
  if (!p) return { score: 0, label: "" };
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(r => r.test(p)).length;
  let score = 0;
  if (p.length >= 8)  score++;
  if (p.length >= 12) score++;
  if (p.length >= 16) score++;
  if (classes >= 2)   score++;
  if (classes >= 3)   score++;
  if (classes >= 4 && p.length >= 12) score++;
  const labels = ["Very weak", "Weak", "Okay", "Good", "Strong", "Fortress"];
  return { score, label: labels[Math.min(score, 5)] };
}

function updateStrengthMeter() {
  const p          = $("setup-pass").value;
  const meterFill  = $("meter-fill");
  const label      = $("meter-label");
  const { score, label: text } = passStrength(p);
  const colors = ["#ff6080", "#ff6080", "#ffb454", "#ffb454", "#4ade80", "#4ade80"];
  meterFill.style.width      = `${(Math.min(score, 5) / 5) * 100}%`;
  meterFill.style.background = colors[Math.min(score, 5)];
  label.textContent          = p ? `${text} — aim for 12+ characters` : "";
}
