// 12_727b.js — 727 arg-shape matrix (writeup implies a count/index arg).
// Same session only. Any ch>0 = shape found.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[t12] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const shapes = [
        ["2a-id-out", (id,ob) => [id,ob,0n,0n,0n,0n]],
        ["3a-id-cnt-out", (id,ob) => [id,1n,ob,0n,0n,0n]],
        ["3a-id-cnt4-out", (id,ob) => [id,4n,ob,0n,0n,0n]],
        ["3a-id-out-cnt", (id,ob) => [id,ob,1n,0n,0n,0n]],
    ];
    const IDS = [1n, 25003n];
    shout("t12: start"); say("start"); await pace();
    for (const id of IDS) {
        for (const [nm, mk] of shapes) {
            const tag = nm + "/" + id;
            shout("t12: " + tag); say(tag); await pace();
            try {
                const ob = malloc(0x40);
                for (let i = 0n; i < 0x40n; i += 8n) write64(ob + i, 0xDEADBEEFn + i);
                const r = await syscall(0x2D7n, ...mk(id, ob));
                let ch = [];
                try {
                    for (let i = 0n; i < 0x40n; i += 8n) {
                        const v = read64(ob + i);
                        if (v !== (0xDEADBEEFn + i)) ch.push(i.toString() + "=" + v.toString(16));
                    }
                } catch (e) { ch.push("READFAULT"); }
                shout(("t12: " + tag + " ret=" + String(r) + " ch=" + ch.length).slice(0,110));
                say(tag + " ret=" + String(r) + " ch[" + ch.length + "]" + (ch.length ? " " + ch.slice(0,4).join(" ") : ""));
                await pace();
            } catch (e) { shout("t12: " + tag + " THREW"); say(tag + " threw"); await pace(); }
        }
    }
    shout("t12: done"); say("shape sweep done");
})()
