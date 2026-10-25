#!/usr/bin/env python3
"""E2E test Safemark v1.5 — Brave/Chrome Sync integration of the vault."""
import asyncio, json, http.client, time, websockets

EXT = "chrome-extension://mdlgpdkhfnlafabmklfmhlhoimoeeenk/"
PORT = 9333

class CDP:
    def __init__(self, ws):
        self.ws = ws
        self.mid = 0

    async def send(self, method, params=None):
        self.mid += 1
        await self.ws.send(json.dumps({"id": self.mid, "method": method,
                                       "params": params or {}}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == self.mid:
                return msg

    async def eval(self, expr):
        r = await self.send("Runtime.evaluate",
                            {"expression": expr, "returnByValue": True,
                             "awaitPromise": True})
        if "exceptionDetails" in r.get("result", {}):
            return "__EXC__ " + r["result"]["exceptionDetails"]["exception"].get("description", "?")[:250]
        return r["result"].get("result", {}).get("value")

def json_targets():
    conn = http.client.HTTPConnection("127.0.0.1", PORT)
    conn.request("GET", "/json")
    return json.loads(conn.getresponse().read())

async def main():
    page = next(t for t in json_targets() if t["type"] == "page")
    ws = await websockets.connect(page["webSocketDebuggerUrl"], max_size=None)
    cdp = CDP(ws)
    await cdp.send("Runtime.enable")
    await cdp.send("Page.enable")

    ok_all = True
    def check(name, got, want):
        nonlocal ok_all
        ok = got == want
        ok_all = ok_all and ok
        print(("PASS" if ok else "FAIL") + f"  {name}: {got!r}" + ("" if ok else f" (want {want!r})"))

    async def open_popup(suffix="?x" + str(time.time())):
        await cdp.send("Page.navigate", {"url": EXT + "popup.html" + suffix})
        await asyncio.sleep(1.3)
        return await cdp.eval("document.querySelector('.view:not(.hidden)').id")

    async def areas():
        local = json.loads(await cdp.eval("chrome.storage.local.get(null).then(s=>JSON.stringify(s))"))
        sync = json.loads(await cdp.eval("chrome.storage.sync.get(null).then(s=>JSON.stringify(s))"))
        return local, sync

    # ─ 1 · setup via UI ─
    await cdp.eval("chrome.storage.local.clear()")
    try:
        await cdp.eval("chrome.storage.sync.clear()")
    except Exception:
        pass
    view = await open_popup()
    check("1 fresh → onboarding", view, "view-welcome")
    await cdp.eval("document.getElementById('btn-next').click()")
    await cdp.eval("document.getElementById('setup-pass').value='plaza-vertex-moon-33'")
    await cdp.eval("document.getElementById('setup-pass2').value='plaza-vertex-moon-33'")
    await cdp.eval("document.getElementById('form-setup').requestSubmit()")
    await asyncio.sleep(2.6)
    check("2 setup unlocks", await cdp.eval(
        "document.querySelector('.view:not(.hidden)').id"), "view-vault")

    local, sync = await areas()
    check("3 local has chunked meta", bool(local.get("smMeta")), True)
    check("4 sync mirrors meta", bool(sync.get("smMeta")), True)
    check("5 sync has parts", any(k.startswith("smVault") for k in sync), True)
    check("6 verifiers equal both areas", local["smHash"] == sync["smHash"], True)

    # add one bookmark, then re-check revisions bumped
    await cdp.eval("window.__tab={title:'Sync Alpha',url:'https://alpha.example/',favIconUrl:''}")
    await cdp.eval("saveCurrentPage()")
    await asyncio.sleep(0.8)
    local, sync = await areas()
    check("7 local rev bumped on save", local["smMeta"]["rev"] >= 2, True)
    check("8 sync rev matches local", sync["smMeta"]["rev"], local["smMeta"]["rev"])

    # ─ 9 · simulated OTHER DEVICE write → merge ─
    await cdp.eval("""(async()=>{
      // same key (same password + synced salt) as this vault
      const {aes} = await deriveKeys('plaza-vertex-moon-33', await chrome.storage.sync.get('smSalt').then(s=>s.smSalt), 600000);
      const local = await chrome.storage.local.get(null);
      const mine = await openVault(aes, {iv: local.smMeta.iv, ct: local.smVault0});
      const seeded = mine.concat([{
        id:'Remote1', title:'Sync Bravo', url:'https://bravo.example/', favicon:'', addedAt: Date.now()
      }]);
      const sealed = await sealVault(aes, seeded);
      const chunks = (s)=>{const o=[];for(let i=0;i<s.length;i+=7000)o.push(s.slice(i,i+7000));return o.length?o:[''];};
      const parts = chunks(sealed.ct);
      const data = {smMeta:{iv:sealed.iv, rev: local.smMeta.rev + 5, parts: parts.length}};
      parts.forEach((c,i)=>{data['smVault'+i]=c});
      await chrome.storage.sync.set(data);
      return 'remote write done';
    })()""")
    # wait for onChanged → debounce 900ms → merge
    await asyncio.sleep(2.6)
    check("9 remote merged into UI", await cdp.eval(
        "window.__vault.map(b=>b.title).sort().join('|')"), "Sync Alpha|Sync Bravo")
    local, sync = await areas()
    check("10 local rev overtakes remote", local["smMeta"]["rev"],
          json.loads(json.dumps(sync["smMeta"]))["rev"])
    check("11 merged result encrypted in sync", "bravo.example" in json.dumps(sync).lower(), False)

    # ─ 12 · fresh device: local cleared, sync has the vault ─
    await cdp.eval("chrome.storage.local.clear()")
    view = await open_popup()
    check("12 fresh device → gate (vault synced in)", view, "view-gate")
    l2 = json.loads(await cdp.eval("chrome.storage.local.get(['smMeta','smSalt']).then(s=>JSON.stringify(s))"))
    check("13 sync adopted into local automatically", bool(l2.get("smMeta") and l2.get("smSalt")), True)
    await cdp.eval("document.getElementById('gate-pass').value='plaza-vertex-moon-33'")
    await cdp.eval("document.getElementById('form-gate').requestSubmit()")
    await asyncio.sleep(2.6)
    check("14 new device decrypts same password", await cdp.eval(
        "document.querySelector('.view:not(.hidden)').id"), "view-vault")
    check("15 data intact across devices", await cdp.eval(
        "window.__vault.map(b=>b.title).sort().join('|')"), "Sync Alpha|Sync Bravo")

    # ─ 16 · favicon bloat guard ─
    await cdp.eval("window.__tab={title:'Favicon Bloat',url:'https://bloat.example/',favIconUrl:'data:image/png;base64,'+'A'.repeat(90000)}")
    await cdp.eval("saveCurrentPage()")
    await asyncio.sleep(1.0)
    local, sync = await areas()
    check("16 giant favicon not stored", "data:image/png" in json.dumps(sync), False)
    bookmark_titles = await cdp.eval("window.__vault.map(b=>b.title).join(',')")
    check("17 bookmark itself present", "Favicon Bloat" in bookmark_titles, True)

    # ─ 18 · legacy v1.4 single-blob migrates to chunked+synced ─
    await cdp.eval("""(async()=>{
      const salt='90909090909090909090909090909090';
      const k=await deriveKeys('midi-single-14',salt,600000);
      const sealed=await sealVault(k.aes,[{id:'l1',title:'Legacy Blob',url:'https://legacy14.example/',favicon:'',addedAt:1e12}]);
      await chrome.storage.local.clear();
      await chrome.storage.sync.clear();
      await chrome.storage.local.set({smOnboarded:true,smKdf:3,smSalt:salt,smHash:k.verifier,smVault:sealed});
      return'ready';
    })()""")
    view = await open_popup()
    check("18 legacy blob → gate", view, "view-gate")
    await cdp.eval("document.getElementById('gate-pass').value='midi-single-14'")
    await cdp.eval("document.getElementById('form-gate').requestSubmit()")
    await asyncio.sleep(3.0)
    check("19 legacy unlock → vault", await cdp.eval(
        "document.querySelector('.view:not(.hidden)').id"), "view-vault")
    check("20 legacy data preserved", await cdp.eval(
        "window.__vault[0].title"), "Legacy Blob")
    local, sync = await areas()
    check("21 smVault blob replaced by chunks", "smVault" in local and "smMeta" in sync, False)
    check("22 legacy data now in sync parts",
          any(k.startswith("smVault") for k in sync), True)
    check("23 plaintext never in sync", "legacy14.example" in json.dumps(sync).lower(), False)

    # ─ 24 · legacy v1.0 plaintext migrates, wiped from both areas ─
    await cdp.eval("""(async()=>{
      const salt='a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0';
      const oldHash=await legacyHash('oldplainpass', salt);
      await chrome.storage.local.clear();
      await chrome.storage.sync.clear();
      await chrome.storage.local.set({smOnboarded:true,smSalt:salt,smHash:oldHash,
        smBookmarks:[{id:'o1',title:'Plaintext Era',url:'https://plain.example/',favicon:'',addedAt:1e12}]});
      return'ready';
    })()""")
    view = await open_popup()
    check("24 v1.0 → gate", view, "view-gate")
    await cdp.eval("document.getElementById('gate-pass').value='oldplainpass'")
    await cdp.eval("document.getElementById('form-gate').requestSubmit()")
    await asyncio.sleep(3.0)
    check("25 v1.0 unlock → vault", await cdp.eval(
        "document.querySelector('.view:not(.hidden)').id"), "view-vault")
    local, sync = await areas()
    check("26 smBookmarks gone from local", "smBookmarks" in local, False)
    check("27 smBookmarks gone from sync", "smBookmarks" in sync, False)
    check("28 data encrypted in sync now", any(k.startswith("smVault") for k in sync), True)
    check("29 upgrade toast", await cdp.eval("document.getElementById('toast').textContent"),
          "Upgraded — plaintext copy wiped, vault now syncs 🛡️")

    print("\n" + ("ALL ✔" if ok_all else "✘ SOME FAILED"))

asyncio.run(main())
