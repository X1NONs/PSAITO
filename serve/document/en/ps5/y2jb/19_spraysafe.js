// 19_spraysafe.js — safety gate: mass pipe spray + close, NO fire.
// Must survive cleanly or the differential is invalid.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[p19] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    shout("p19: start"); say("start"); await pace();
    const fds = [];
    let made = 0;
    for (let i = 0; i < 200; i++) {
        try {
            const a = malloc(8); write64(a, 0n);
            const r = await syscall(0x2AFn, a, 0n,0n,0n,0n,0n);
            if (String(r) === "0") {
                const v = read64(a);
                fds.push(Number(v & 0xFFFFFFFFn), Number((v >> 32n) & 0xFFFFFFFFn));
                made++;
            }
        } catch (e) { break; }
        if (i % 50 === 49) { shout("p19: made=" + made); say("made=" + made); await pace(); }
    }
    shout("p19: sprayed-pairs=" + made); say("sprayed=" + made); await pace();
    let closed = 0;
    for (const fd of fds) {
        try { await syscall(0x06n, BigInt(fd), 0n,0n,0n,0n,0n); closed++; } catch (e) { break; }
    }
    shout("p19: closed=" + closed); say("closed=" + closed); await pace();
    shout("p19: done"); say("spraysafe done");
})()
