// 08_727.js — raw 727 (0x2D7) with REAL out-pointer (Y2JB full args).
// No wrapper needed: syscall by number. init-first, paced, survivor-marked.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[g8] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("g8: " + tag); say(tag); await pace();
        try { const r = await fn(); shout(("g8: " + tag + "=" + String(r)).slice(0,110)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("g8: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "go");
    await step("init", async () => await syscall(0x29En, 0n,0n,0n,0n,0n,0n));
    await step("dbg727", async () => {
        const ob = malloc(0x40);
        for (let i = 0n; i < 0x40n; i += 8n) write64(ob + i, 0xDEADBEEFn + i);
        const r = await syscall(0x2D7n, 1n, ob, 0n, 0n, 0n, 0n);
        let ch = [];
        try {
            for (let i = 0n; i < 0x40n; i += 8n) {
                const v = read64(ob + i);
                if (v !== (0xDEADBEEFn + i)) ch.push(i.toString() + "=" + v.toString(16));
            }
        } catch (e) { return String(r) + " READFAULT"; }
        return String(r) + " changed[" + ch.length + "]" + (ch.length ? " " + ch.slice(0,4).join(" ") : "");
    });
    await step("done", async () => "ok");
})()
