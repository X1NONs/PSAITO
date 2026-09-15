// 06_next.js — untested singles, paced + survivor-marked. Fresh YT -> bases -> calltest -> this.
// Order: create, osem(valid), socketpair, 727-probe. Stops at first death.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[n6] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("n6: " + tag); say(tag); await pace();
        try { const r = await fn(); shout("n6: " + tag + "=" + String(r)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("n6: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "go");
    await step("create", async () => await syscall(0x29Cn, 1n,0n,0n,0n,0n,0n));
    await step("osem", async () => {
        const nm = malloc(32);
        for (let i = 0; i < 32; i++) write8(nm + BigInt(i), 0);
        write8(nm, 87); write8(nm+1n, 65); write8(nm+2n, 75); write8(nm+3n, 69);
        const at = malloc(0x20);
        for (let i = 0; i < 0x20; i++) write8(at + BigInt(i), 0);
        write32(at, 1); write32(at + 8n, 1);
        const r = await syscall(0x225n, nm, at, 0n,0n,0n,0n);
        try { if (r >= 0n) await syscall(0x226n, r, 0n,0n,0n,0n,0n); } catch (e) {}
        return r;
    });
    await step("sockpair", async () => {
        const sv = malloc(8); write64(sv, 0n);
        const r = await syscall(0x35n, 1n, 1n, 0n, sv, 0n, 0n);
        try {
            const v = read64(sv);
            const a = Number(v & 0xFFFFFFFFn), b = Number((v >> 32n) & 0xFFFFFFFFn);
            try { await syscall(0x06n, BigInt(a), 0n,0n,0n,0n,0n); } catch (e) {}
            try { await syscall(0x06n, BigInt(b), 0n,0n,0n,0n,0n); } catch (e) {}
            return String(r) + " fds=" + a + "," + b;
        } catch (e) { return String(r) + " (sv unreadable)"; }
    });
    await step("727", async () => {
        const ob = malloc(0x40);
        for (let i = 0n; i < 0x40n; i += 8n) write64(ob + i, 0xDEADBEEFn + i);
        const r = await syscall(0x2D7n, 1n, ob, 0n, 0n, 0n, 0n);
        let ch = false;
        try { for (let i = 0n; i < 0x40n; i += 8n) if (read64(ob+i) !== (0xDEADBEEFn+i)) ch = true; } catch (e) {}
        return String(r) + " wrote=" + ch;
    });
    await step("done", async () => "ok");
})()
