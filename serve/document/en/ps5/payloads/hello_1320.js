// hello_1320.js -- Y2JB CANARY (PS5 13.20): canario de salud del loader/eval.
// 2026-08-27 -- 3 logs + getpid: si el loader evalua, se reciben los 3 logs.

(async () => {
    await log("[canary] hello: loader reached eval()");
    try {
        const pid = syscall(SYSCALL.getpid);
        await log("[canary] getpid ok = " + toHex(pid));
        await log("[canary] DONE - payload completed without crash");
    } catch (e) {
        await log("[canary] ERROR en getpid: " + e);
    }
})();
