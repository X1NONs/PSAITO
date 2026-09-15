// 21_waitstate.js — are our AIO requests genuinely PENDING? No fire.
// wait(t=0) -> read states (expect 0) -> wake-write -> yields -> wait(t=0) ->
// read states (expect COMPLETE=3). Transition = real machinery; stuck = duds.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[w21] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("w21: " + tag); say(tag); await pace();
        try { const r = await fn(); shout(("w21: " + tag + "=" + String(r)).slice(0,110)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("w21: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    const dumpStates = (states) => {
        try { return Number(read32(states)) + "," + Number(read32(states + 4n)); }
        catch (e) { return "unreadable"; }
    };
    await step("start", async () => "no-fire state proof");
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
    await step("wait-pre", async () => {
        const r = await syscall(0x297n, ids, 2n, states, 1n, 0n, 0n);
        return String(r) + " states=" + dumpStates(states) + " (want pending)";
    });
    await step("wake", async () => {
        const wb = malloc(4); write8(wb, 0x57);
        const r = await syscall(0x04n, BigInt(wfd), wb, 1n, 0n, 0n, 0n);
        for (let i = 0; i < 200; i++) { try { await syscall(0x14Bn, 0n,0n,0n,0n,0n,0n); } catch (e) {} }
        return String(r) + " written+yielded";
    });
    await step("wait-post", async () => {
        const r = await syscall(0x297n, ids, 2n, states, 1n, 0n, 0n);
        return String(r) + " states=" + dumpStates(states) + " (want 3,3=COMPLETE)";
    });
    await step("verdict", async () => "transition? real : duds");
    try { await syscall(0x29An, ids, 2n, states, 0n,0n,0n,0n); } catch (e) {}
    try { await syscall(0x296n, ids, 2n, states, 0n,0n,0n,0n); } catch (e) {}
    try { if (rfd >= 0) await syscall(0x06n, BigInt(rfd), 0n,0n,0n,0n,0n); } catch (e) {}
    try { if (wfd >= 0) await syscall(0x06n, BigInt(wfd), 0n,0n,0n,0n,0n); } catch (e) {}
    await step("done", async () => "ok");
})()
