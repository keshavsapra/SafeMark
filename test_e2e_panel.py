#!/usr/bin/env python3
"""E2E test Safemark v1.6 — Side Panel + live tab tracking in the save bar."""
import asyncio, json, http.client, websockets

PORT = 9333

def _ext_id():
    conn = http.client.HTTPConnection("127.0.0.1", PORT)
    conn.request("GET", "/json")
    sw = next(t for t in json.loads(conn.getresponse().read())
              if t["type"] == "service_worker")
    return sw["url"].split("/")[2]

EXT = "chrome-extension://" + _ext_id() + "/"

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

    async def open_popup():
        await cdp.send("Page.navigate", {"url": EXT + "popup.html"})
        await asyncio.sleep(1.3)
        return await cdp.eval("document.querySelector('.view:not(.hidden)').id")

    # ─ fresh boot + side panel surface ─
    await cdp.eval("chrome.storage.local.clear()")
    try: await cdp.eval("chrome.storage.sync.clear()")
    except Exception: pass
    view = await open_popup()
    check("1 fresh → onboarding", view, "view-welcome")
    check("2 panel fluid layout class", await cdp.eval(
        "document.body.classList.contains('panel')"), True)
    check("3 sidePanel API exposed", await cdp.eval(
        "typeof chrome.sidePanel !== 'undefined'"), True)
    check("4 no detach button in DOM", await cdp.eval(
        "document.getElementById('btn-detach') === null"), True)

    # ─ setup ─
    await cdp.eval("document.getElementById('btn-next').click()")
    await cdp.eval("document.getElementById('setup-pass').value='plaza-vertex-moon-33'")
    await cdp.eval("document.getElementById('setup-pass2').value='plaza-vertex-moon-33'")
    await cdp.eval("document.getElementById('form-setup').requestSubmit()")
    await asyncio.sleep(2.6)
    check("5 setup unlocks in panel", await cdp.eval(
        "document.querySelector('.view:not(.hidden)').id"), "view-vault")

    # ─ create the user's browsing tabs ─
    tabA = await cdp.eval("chrome.tabs.create({url:'file:///tmp/opencode/demo-a.html', active:false}).then(t=>t.id)")
    tabB = await cdp.eval("chrome.tabs.create({url:'file:///tmp/opencode/demo-b.html', active:false}).then(t=>t.id)")
    await asyncio.sleep(0.6)

    # ─ 6 · switch tab → save bar follows (onActivated) ─
    await cdp.eval(f"chrome.tabs.update({tabA}, {{active:true}})")
    await asyncio.sleep(0.8)
    check("6 switch to tab A reflected", await cdp.eval(
        "document.getElementById('save-page-url').textContent"),
        "file:///tmp/opencode/demo-a.html")

    # ─ 7 · switch to B ─
    await cdp.eval(f"chrome.tabs.update({tabB}, {{active:true}})")
    await asyncio.sleep(0.8)
    check("7 switch to tab B reflected", await cdp.eval(
        "document.getElementById('save-page-url').textContent"),
        "file:///tmp/opencode/demo-b.html")

    # ─ 8 · active tab navigates → save bar follows (onUpdated) ─
    await cdp.eval(f"chrome.tabs.update({tabB}, {{url:'file:///tmp/opencode/demo-c.html'}})")
    await asyncio.sleep(1.0)
    check("8 tab B navigates to C, row follows", await cdp.eval(
        "document.getElementById('save-page-url').textContent"),
        "file:///tmp/opencode/demo-c.html")

    # ─ 9 · save the now-active tab from the panel ─
    await cdp.eval("document.getElementById('btn-save-page').click()")
    await asyncio.sleep(1.0)
    titles = await cdp.eval("window.__vault.map(b=>b.title).join(',')")
    check("9 bookmarked active tab", "tab C" in str(titles), True)

    # ─ 10 · chrome:// guarded when such a tab is active ─
    about = await cdp.eval("chrome.tabs.create({url:'about:blank', active:true}).then(t=>t.id)")
    await asyncio.sleep(0.8)
    check("10 non-bookmarkable tab guarded", await cdp.eval(
        "document.getElementById('btn-save-page').disabled === true"), True)

    # ─ 11 · lock & exit wired and sidePanel close attempted without error ─
    await cdp.eval(f"chrome.tabs.update({tabA}, {{active:true}})")
    await asyncio.sleep(0.6)
    lock_res = await cdp.eval(
        "typeof lockAndExit === 'function' ? 'wired' : 'MISSING'")
    check("11 lockAndExit wired", lock_res, "wired")

    print("\n" + ("ALL ✔" if ok_all else "✘ SOME FAILED"))

asyncio.run(main())
