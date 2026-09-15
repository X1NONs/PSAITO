// 03_trace.js — paced micro-steps (500ms each) so every line flushes before
// the next step runs. Last ARRIVED line + 1 = the crashing call.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[tr3] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const toBig = (v) => {
        if (typeof v === "bigint") return v;
        if (typeof v === "number") return BigInt(v>>>0) | (BigInt(Math.floor(v/0x100000000))<<32n);
        if (v && typeof v.low === "number") return (BigInt(v.hi>>>0)<<32n)|BigInt(v.low>>>0);
        throw new Error("bad addr");
    };
    shout("tr3: s0-start"); say("s0 start"); await pace();
    let LK = 0n;
    try {
        const g = (typeof libkernel_base !== "undefined") ? libkernel_base : globalThis.libkernel_base;
        shout("tr3: s1-hasglobal"); say("s1 hasglobal"); await pace();
        LK = toBig(g);
        shout("tr3: s2-LK=0x" + LK.toString(16)); say("s2 LK=0x" + LK.toString(16)); await pace();
    } catch (e) { shout("tr3: LK FAIL"); say("LK fail"); return; }
    const SC = async (tag, num, args) => {
        shout("tr3: call-" + tag); say("call " + tag); await pace();
        try {
            const r = await syscall(BigInt(num), ...args.map((a)=>BigInt(a)));
            shout("tr3: ret-" + tag + "=" + String(r)); say("ret " + tag + "=" + String(r)); await pace();
            return r;
        } catch (e) { shout("tr3: threw-" + tag); say("threw " + tag); await pace(); return null; }
    };
    let r = await SC("init", 0x29E, [0n,0n,0n,0n,0n,0n]);
    if (r === null) return;
    const ab = malloc(8); write64(ab, 0n);
    shout("tr3: struct-pipe"); say("struct pipe"); await pace();
    r = await SC("pipe2", 0x2AF, [ab,0n,0n,0n,0n,0n]);
    if (r === null) return;
    shout("tr3: done"); say("trace done");
})()
