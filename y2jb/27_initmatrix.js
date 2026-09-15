// 27_initmatrix.js — aio_init arg matrix, isolated paced steps.
// Engine fails EFAILED on ITS combo; calltest safe-fails on (0,0).
// Any ret=0 = subsystem UP (unblocks everything downstream).
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[i27] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    shout("i27: start"); say("start"); await pace();
    for (const [a, b] of [[0,0],[1,0],[0,1],[1,1],[2,0],[0,2]]) {
        const tag = "init(" + a + "," + b + ")";
        shout("i27: " + tag); say(tag); await pace();
        try {
            const r = await syscall(0x29En, BigInt(a), BigInt(b), 0n,0n,0n,0n);
            shout(("i27: " + tag + "=" + String(r)).slice(0,110));
            say(tag + "=" + String(r)); await pace();
        } catch (e) { shout("i27: " + tag + " THREW"); say(tag + " threw"); await pace(); }
    }
    shout("i27: done"); say("init matrix done");
})()
