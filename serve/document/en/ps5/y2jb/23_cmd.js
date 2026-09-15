// 23_cmd.js — sweep submit_cmd cmd values; non-COMPLETE pre-wake states = live read path.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[c23] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    shout("c23: start"); say("start"); await pace();
    await syscall(0x29En, 0n,0n,0n,0n,0n,0n);
    const allfds = [];
    for (const cmd of [0x1, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1010]) {
        const tag = "cmd0x" + cmd.toString(16);
        shout("c23: " + tag); say(tag); await pace();
        try {
            const a = malloc(8); write64(a, 0n);
            await syscall(0x2AFn, a, 0n,0n,0n,0n,0n);
            const fds = read64(a);
            const rfd = Number(fds & 0xFFFFFFFFn), wfd = Number((fds >> 32n) & 0xFFFFFFFFn);
            allfds.push(rfd, wfd);
            const RB = 0x28;
            const reqs = malloc(RB * 2);
            for (let i = 0; i < RB * 2; i += 8) write64(reqs + BigInt(i), 0n);
            const data = malloc(64);
            for (let i = 0; i < 64; i += 8) write64(data + BigInt(i), 0n);
            for (let i = 0; i < 2; i++) {
                write32(reqs + BigInt(i * RB + 0x20), rfd);
                write64(reqs + BigInt(i * RB + 0x08), data);
                write64(reqs + BigInt(i * RB + 0x10), 64n);
            }
            const ids = malloc(8), states = malloc(8);
            write32(ids, 0n); write32(ids + 4n, 0n);
            write32(states, 0n); write32(states + 4n, 0n);
            const r = await syscall(0x29Dn, BigInt(cmd), reqs, 2n, 3n, ids, 0n);
            await syscall(0x297n, ids, 2n, states, 1n, 0n, 0n);
            let st = "?";
            try { st = Number(read32(states)) + "," + Number(read32(states + 4n)); } catch (e) {}
            shout(("c23: " + tag + " sub=" + String(r) + " st=" + st).slice(0,110));
            say(tag + " sub=" + String(r) + " st=" + st); await pace();
            try { await syscall(0x29An, ids, 2n, states, 0n,0n,0n,0n); } catch (e) {}
            try { await syscall(0x296n, ids, 2n, states, 0n,0n,0n,0n); } catch (e) {}
        } catch (e) { shout("c23: " + tag + " THREW"); say(tag + " threw"); await pace(); }
    }
    for (const fd of allfds) { try { await syscall(0x06n, BigInt(fd), 0n,0n,0n,0n,0n); } catch (e) {} }
    shout("c23: done"); say("cmd sweep done");
})()
