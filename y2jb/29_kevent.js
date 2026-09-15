// 29_kevent.js — is ANYTHING real here? EVFILT_TIMER via kevent(0x16B).
// Returns 1 fired event on a live kernel; 0/-1/crash maps neutering.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[k29] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    shout("k29: start"); say("start"); await pace();
    try {
        const kq = await syscall(0x16An, 0n,0n,0n,0n,0n,0n);
        shout("k29: kq=" + String(kq)); say("kq=" + String(kq)); await pace();
        // struct kevent { ident8, filter2+flags2, fflags4, data8, udata8 } = 32B
        // EVFILT_TIMER=-7 (0xFFF9), EV_ADD|EV_ENABLE|EV_ONESHOT = 0x1|0x4|0x10
        const ch = malloc(32);
        for (let i = 0; i < 32; i++) write8(ch + BigInt(i), 0);
        write64(ch, 1n);                    // ident = 1 (ms)
        write16(ch + 8n, 0xFFF9);           // filter = EVFILT_TIMER
        write16(ch + 10n, 0x15);            // flags = ADD|ENABLE|ONESHOT
        write32(ch + 12n, 0);               // fflags
        write64(ch + 16n, 10n);             // data = 10ms
        const ev = malloc(32);
        for (let i = 0; i < 32; i++) write8(ev + BigInt(i), 0xAA);
        const to = malloc(16);
        write64(to, 2n); write64(to + 8n, 0n); // 2s timeout
        const t0 = Date.now();
        const r = await syscall(0x16Bn, kq, ch, 1n, ev, 1n, to);
        const dt = Date.now() - t0;
        let evhx = "";
        try {
            evhx = Number(read64(ev)).toString(16) + "/" + Number(read64(ev+8n)).toString(16);
        } catch (e) { evhx = "unreadable"; }
        shout(("k29: kevent=" + String(r) + " dt=" + dt + "ms ev=" + evhx).slice(0,120));
        say("kevent=" + String(r) + " dt=" + dt + "ms ev=" + evhx); await pace();
        try { await syscall(0x06n, kq, 0n,0n,0n,0n,0n); } catch (e) {}
    } catch (e) { shout("k29: THREW"); say("threw"); await pace(); }
    shout("k29: done"); say("kevent done");
})()
