// 04_submit.js — init + pipe + ONE submit(valid req), paced. Lived through pipe2;
// if this dies, submit-on-13.40 (struct layout) is the killer.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[s4] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    shout("s4: start"); say("s4 start"); await pace();
    let r = await syscall(0x29En, 0n, 0n, 0n, 0n, 0n, 0n);
    shout("s4: init=" + String(r)); say("init=" + String(r)); await pace();
    const ab = malloc(8); write64(ab, 0n);
    r = await syscall(0x2AFn, ab, 0n, 0n, 0n, 0n, 0n);
    let rfd = -1;
    try { rfd = Number(read64(ab) & 0xFFFFFFFFn); } catch (e) {}
    shout("s4: pipe=" + String(r) + " rfd=" + rfd); say("pipe rfd=" + rfd); await pace();
    const data = malloc(64);
    for (let i = 0; i < 64; i += 8) write64(data + BigInt(i), 0n);
    const req = malloc(0x40);
    for (let i = 0; i < 0x40; i += 8) write64(req + BigInt(i), 0n);
    write32(req, rfd >= 0 ? rfd : 0);
    write64(req + 8n, data);
    write64(req + 16n, 64n);
    shout("s4: struct-ready"); say("struct ready"); await pace();
    try {
        r = await syscall(0x295n, 0n, req, 1n, 0n, 0n, 0n);
        shout("s4: submit=" + String(r)); say("submit=" + String(r)); await pace();
    } catch (e) { shout("s4: submit THREW"); say("submit threw"); await pace(); }
    try { if (rfd >= 0) await syscall(0x06n, BigInt(rfd), 0n,0n,0n,0n,0n); } catch (e) {}
    shout("s4: done"); say("submit-trace done");
})()
