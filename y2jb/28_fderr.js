// 28_fderr.js — does the fd field matter? valid-pipe vs bogus-fd vs null-data.
// Different states => field live. Identical => field ignored/wrong offset.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[e28] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const R32 = (a) => { try { return Number(read32(a)); } catch (e) { return -999; } };
    shout("e28: start"); say("start"); await pace();
    await syscall(0x29En, 0n,0n,0n,0n,0n,0n);
    const mkpipe = async () => {
        const a = malloc(8); write64(a, 0n);
        await syscall(0x2AFn, a, 0n,0n,0n,0n,0n);
        const fds = read64(a);
        return [Number(fds & 0xFFFFFFFFn), Number((fds >> 32n) & 0xFFFFFFFFn)];
    };
    const variants = [["validfd", null, false], ["badfd9999", 9999, false], ["nulldata", null, true]];
    for (const [nm, fdfix, nulldata] of variants) {
        shout("e28: " + nm); say(nm); await pace();
        try {
            const [r0, w0] = await mkpipe();
            const fd = (fdfix === null) ? r0 : fdfix;
            const RB = 0x28;
            const reqs = malloc(RB * 2);
            for (let i = 0; i < RB * 2; i += 8) write64(reqs + BigInt(i), 0n);
            const data = malloc(64);
            for (let i = 0; i < 64; i++) write8(data + BigInt(i), 0xAA);
            for (let i = 0; i < 2; i++) {
                write32(reqs + BigInt(i * RB + 0x20), fd);
                write64(reqs + BigInt(i * RB + 0x08), nulldata ? 0n : data);
                write64(reqs + BigInt(i * RB + 0x10), 8n);
            }
            const ids = malloc(8), states = malloc(8);
            write32(ids, 0n); write32(ids + 4n, 0n);
            write32(states, 0n); write32(states + 4n, 0n);
            const r = await syscall(0x29Dn, 0x1001n, reqs, 2n, 3n, ids, 0n);
            await syscall(0x297n, ids, 2n, states, 1n, 0n, 0n);
            const st = R32(states) + "," + R32(states + 4n);
            shout(("e28: " + nm + " sub=" + String(r) + " st=" + st).slice(0,110));
            say(nm + " sub=" + String(r) + " st=" + st); await pace();
            try { await syscall(0x29An, ids, 2n, states, 0n,0n,0n,0n); } catch (e) {}
            try { await syscall(0x296n, ids, 2n, states, 0n,0n,0n,0n); } catch (e) {}
            try { await syscall(0x06n, BigInt(r0), 0n,0n,0n,0n,0n); } catch (e) {}
            try { await syscall(0x06n, BigInt(w0), 0n,0n,0n,0n,0n); } catch (e) {}
        } catch (e) { shout("e28: " + nm + " THREW"); say(nm + " threw"); await pace(); }
    }
    shout("e28: done"); say("fderr done");
})()
