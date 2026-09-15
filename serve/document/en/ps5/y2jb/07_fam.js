// 07_fam.js — zero-arg sweep across AIO numbers (no state change, like init).
// Maps dispatcher gaps (crash = number ungated) vs subsystem gating.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[f7] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("f7: " + tag); say(tag); await pace();
        try { const r = await fn(); shout("f7: " + tag + "=" + String(r)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("f7: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "go");
    const FAM = {del:0x296,cancel:0x29A,poll:0x298,get:0x299,mlock:0x2B0,suspend:0x13B,subcmd:0x29D};
    for (const [n,num] of Object.entries(FAM)) {
        const r = await step(n, async () => await syscall(BigInt(num), 0n,0n,0n,0n,0n,0n));
        if (r === null && n !== "subcmd") { /* THREW = dispatcher-level, keep going */ }
    }
    await step("done", async () => "ok");
})()
