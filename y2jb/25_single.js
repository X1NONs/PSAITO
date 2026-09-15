// 24_data.js — DATA oracle: prefill pipe with known bytes, multi-read, check buffer.
// Data arriving = fd+data+len layouts ALL correct (stronger than state codes).
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[s25] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("d24: " + tag); say(tag); await pace();
        try { const r = await fn(); shout(("d24: " + tag + "=" + String(r)).slice(0,110)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("d24: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    const HX = (b, n) => {
        let x = "";
        try { for (let i = 0n; i < BigInt(n); i++) { const v = Number(read8(b + i)) & 255; x += (v < 16 ? "0" : "") + v.toString(16); } }
        catch (e) { x = "FAULT"; }
        return x;
    };
    await step("start", async () => "single-read-oracle");
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
    await step("prefill", async () => {
        const msg = malloc(16);
        const hello = [72, 69, 76, 76, 79, 33, 33, 33]; // "HELLO!!!"
        for (let i = 0; i < 8; i++) write8(msg + BigInt(i), hello[i]);
        const r = await syscall(0x04n, BigInt(wfd), msg, 8n, 0n, 0n, 0n);
        return String(r) + " bytes-into-pipe";
    });
    let data = 0n;
    await step("submit", async () => {
        const RB = 0x28;
        const reqs = malloc(RB * 1);
        for (let i = 0; i < RB * 1; i += 8) write64(reqs + BigInt(i), 0n);
        data = malloc(64);
        for (let i = 0; i < 64; i++) write8(data + BigInt(i), 0xAA);
        for (let i = 0; i < 1; i++) {
            write32(reqs + BigInt(i * RB + 0x20), rfd);
            write64(reqs + BigInt(i * RB + 0x08), data);
            write64(reqs + BigInt(i * RB + 0x10), 8n);
        }
        const ids = malloc(8), states = malloc(8);
        write32(ids, 0n); write32(ids + 4n, 0n);
        write32(states, 0n); write32(states + 4n, 0n);
        const r = await syscall(0x29Dn, 0x1n, reqs, 1n, 3n, ids, 0n);
        await syscall(0x297n, ids, 1n, states, 1n, 0n, 0n);
        for (let i = 0; i < 200; i++) { try { await syscall(0x14Bn, 0n,0n,0n,0n,0n,0n); } catch (e) {} }
        return String(r) + " waited+yielded";
    });
    await step("readback", async () => "buf=" + HX(data, 16) + " (want 48454c4c4f212121...)");
    await step("done", async () => "ok");
})()
