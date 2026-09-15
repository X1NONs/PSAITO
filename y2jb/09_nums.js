// 09_nums.js — zero-arg sweep of neighboring AIO numbers to map dispatcher holes.
// Lived: 29E,296,29A,298. Crashed: 299,29C,295. Untested: below.
(async () => {
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[n9] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const pace = () => new Promise((r) => setTimeout(r, 500));
    const step = async (tag, fn) => {
        shout("n9: " + tag); say(tag); await pace();
        try { const r = await fn(); shout("n9: " + tag + "=" + String(r)); say(tag + "=" + String(r)); await pace(); return r; }
        catch (e) { shout("n9: " + tag + " THREW"); say(tag + " threw"); await pace(); return null; }
    };
    await step("start", async () => "go");
    const NUMS = {x29B:0x29B,x29D:0x29D,x29F:0x29F,x2A0:0x2A0,x2A1:0x2A1,x2A2:0x2A2,x2A3:0x2A3,x2D7b:0x2D7};
    for (const [n,num] of Object.entries(NUMS)) {
        const r = await step(n, async () => await syscall(BigInt(num), 0n,0n,0n,0n,0n,0n));
        if (r === null) return;
    }
    await step("done", async () => "ok");
})()
