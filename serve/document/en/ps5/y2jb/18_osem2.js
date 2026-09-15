// 18_osem2.js — osem_create with INT 2nd arg (0/1/2) + 1-arg form.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[o18] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    shout("o18: start"); say("start"); await pace();
    const nm = malloc(16);
    for (let j = 0; j < 16; j++) write8(nm + BigInt(j), 0);
    write8(nm, 84);
    const forms = [["1a", [nm,0n,0n,0n,0n,0n]], ["2a-0", [nm,0n,0n,0n,0n,0n]],
        ["2a-1", [nm,1n,0n,0n,0n,0n]], ["2a-2", [nm,2n,0n,0n,0n,0n]]];
    for (const [tag, args] of forms) {
        shout("o18: " + tag); say(tag); await pace();
        try {
            const r = await syscall(0x225n, ...args);
            shout(("o18: " + tag + "=" + String(r)).slice(0,110));
            say(tag + "=" + String(r)); await pace();
            try { if (typeof r === "bigint" && r >= 0n) await syscall(0x226n, r, 0n,0n,0n,0n,0n); } catch (e) {}
        } catch (e) { shout("o18: " + tag + " THREW"); say(tag + " threw"); await pace(); }
    }
    shout("o18: done"); say("osem2 done");
})()
