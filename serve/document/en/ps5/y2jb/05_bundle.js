// 05_bundle.js — one send: bases -> sanity -> kex probes. Popup+log+pace per step
// (TV popups survive app death; log POSTs may not). Last popup seen = next call crashed.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[b5] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const toBig = (v) => {
        if (typeof v === "bigint") return v;
        if (typeof v === "number") return BigInt(v>>>0) | (BigInt(Math.floor(v/0x100000000))<<32n);
        if (v && typeof v.low === "number") return (BigInt(v.hi>>>0)<<32n)|BigInt(v.low>>>0);
        throw new Error("bad addr");
    };
    const step = async (tag, fn) => {
        shout("b5: " + tag); say(tag); await pace();
        try { const r = await fn(); shout("b5: " + tag + "=" + String(r)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("b5: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "go");
    let LK = 0n;
    await step("bases", async () => {
        const g = (typeof libkernel_base !== "undefined") ? libkernel_base : globalThis.libkernel_base;
        LK = toBig(g); return "0x" + LK.toString(16);
    });
    if (!LK) return;
    await step("init", async () => await syscall(0x29En, 0n,0n,0n,0n,0n,0n));
    let rfd = -1;
    await step("pipe", async () => {
        const a = malloc(8); write64(a, 0n);
        const r = await syscall(0x2AFn, a, 0n,0n,0n,0n,0n);
        try { rfd = Number(read64(a) & 0xFFFFFFFFn); } catch (e) {}
        return String(r) + " rfd=" + rfd;
    });
    await step("kqueue", async () => {
        const r = await syscall(0x16An, 0n,0n,0n,0n,0n,0n);
        try { if (r >= 0n) await syscall(0x06n, r, 0n,0n,0n,0n,0n); } catch (e) {}
        return r;
    });
    await step("submit?", async () => {
        const data = malloc(64);
        for (let i = 0; i < 64; i += 8) write64(data + BigInt(i), 0n);
        const req = malloc(0x40);
        for (let i = 0; i < 0x40; i += 8) write64(req + BigInt(i), 0n);
        write32(req, rfd >= 0 ? rfd : 0);
        write64(req + 8n, data);
        write64(req + 16n, 64n);
        return await syscall(0x295n, 0n, req, 1n, 0n, 0n, 0n);
    });
    await step("create?", async () => await syscall(0x29Cn, 1n,0n,0n,0n,0n,0n));
    try { if (rfd >= 0) await syscall(0x06n, BigInt(rfd), 0n,0n,0n,0n,0n); } catch (e) {}
    await step("done", async () => "ok");
})()
