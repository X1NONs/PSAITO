// 01_sanity.js — Y2JB session sanity (from scratch): shout/say + aio_init + pipe2 + kqueue.
// Expect: start, aio_init ret, pipe2 ret=0 + real fds, kqueue fd, done.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[ok] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    shout("ok: start");
    say("sanity start");
    try {
        const r = await syscall(0x29En, 0n, 0n, 0n, 0n, 0n, 0n);
        say("aio_init=" + String(r)); shout("ok: init=" + String(r));
    } catch (e) { say("init THREW"); shout("ok: init THREW"); }
    try {
        const a = malloc(8);
        write64(a, 0n);
        const r = await syscall(0x2AFn, a, 0n, 0n, 0n, 0n, 0n);
        const fds = read64(a);
        const rfd = Number(fds & 0xFFFFFFFFn), wfd = Number((fds >> 32n) & 0xFFFFFFFFn);
        say("pipe2=" + String(r) + " " + rfd + "," + wfd);
        shout("ok: pipe=" + String(r) + " " + rfd + "," + wfd);
        try { await syscall(0x06n, BigInt(rfd)); } catch (e) {}
        try { await syscall(0x06n, BigInt(wfd)); } catch (e) {}
    } catch (e) { say("pipe THREW"); shout("ok: pipe THREW"); }
    try {
        const r = await syscall(0x16An, 0n, 0n, 0n, 0n, 0n, 0n);
        say("kqueue=" + String(r)); shout("ok: kq=" + String(r));
        try { await syscall(0x06n, r); } catch (e) {}
    } catch (e) { say("kq THREW"); shout("ok: kq THREW"); }
    say("sanity done");
    shout("ok: done");
})()
