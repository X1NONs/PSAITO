// 17_osem.js — osem_create arg matrix (mode x initial). Safe clean-fail expected;
// any ret>=0 = live reclaim object (record it).
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[o17] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    shout("o17: start"); say("start"); await pace();
    for (const mode of [0, 1, 2, 3]) {
        for (const init of [0, 1]) {
            const tag = "m" + mode + "i" + init;
            shout("o17: " + tag); say(tag); await pace();
            try {
                const nm = malloc(16);
                for (let j = 0; j < 16; j++) write8(nm + BigInt(j), 0);
                write8(nm, 84); // 'T'
                const at = malloc(0x20);
                for (let j = 0; j < 0x20; j++) write8(at + BigInt(j), 0);
                write32(at, mode); write32(at + 8n, init);
                const r = await syscall(0x225n, nm, at, 0n, 0n, 0n, 0n);
                shout(("o17: " + tag + "=" + String(r)).slice(0,110));
                say(tag + "=" + String(r)); await pace();
                try { if (typeof r === "bigint" && r >= 0n) await syscall(0x226n, r, 0n,0n,0n,0n,0n); } catch (e) {}
            } catch (e) { shout("o17: " + tag + " THREW"); say(tag + " threw"); await pace(); }
        }
    }
    shout("o17: done"); say("osem matrix done");
})()
