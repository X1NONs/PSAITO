// sim/fakeps5.mjs — simulador Node del entorno post-exploit del userland
// mansoor0x + bridge.js. NO simula el bug de WebKit: simula desde el HANDOFF
// (window.__PS5_CTX) hacia abajo: memoria, trampolines del UCollator falso,
// CPU mini-x86 que ejecuta de verdad las cadenas ROP del bridge (bytecode),
// y un kernel fake con tabla de syscalls ORBIS configurable (AIO viva/muerta).
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import vm from "node:vm";

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const PAYLOADS = path.resolve(HERE, "../payloads");
const BRIDGE = path.resolve(HERE, "../modules/bridge.js");
const MENU = path.resolve(HERE, "../modules/menu.js");

// ---------- memoria paginada 4K ----------
const PAGES = new Map();
function pageOf(a) {
    a = BigInt(a);
    const key = a >> 12n;
    let p = PAGES.get(key);
    if (!p) { p = new Uint8Array(4096); PAGES.set(key, p); }
    return [p, Number(a & 0xfffn)];
}
const M = {
    read8(a) { const [p, o] = pageOf(a); return p[o]; },
    write8(a, v) { const [p, o] = pageOf(a); p[o] = v & 0xff; },
    read64(a) { let v = 0n; for (let i = 7; i >= 0; --i) v = (v << 8n) | BigInt(this.read8(BigInt(a) + BigInt(i))); return v; },
    write64(a, v) { v = BigInt.asUintN(64, BigInt(v)); for (let i = 0; i < 8; ++i) this.write8(BigInt(a) + BigInt(i), Number((v >> BigInt(8 * i)) & 0xffn)); },
    writeBytes(a, u8) { for (let i = 0; i < u8.length; ++i) this.write8(BigInt(a) + BigInt(i), u8[i]); },
    readBytes(a, n) { const o = new Uint8Array(n); for (let i = 0; i < n; ++i) o[i] = this.read8(BigInt(a) + BigInt(i)); return o; },
    read32(a) { let v = 0; for (let i = 3; i >= 0; --i) v = v * 256 + this.read8(BigInt(a) + BigInt(i)); return v >>> 0; },
    write32(a, v) { v = v >>> 0; for (let i = 0; i < 4; ++i) this.write8(BigInt(a) + BigInt(i), (v >>> (8 * i)) & 0xff); },
};

// ---------- layout de módulos ----------
const LIBK = 0x810000000n;    // base libkernel (texto 0x44000)
const ARENA = 0x8012340000n;
const COLLCELL = 0x8011000240n;
const ICU_RET = LIBK + 0x21abcn;          // "reingreso ICU" tras la cadena
const R0STK = 0x7ffffffdff40n;            // rsp real de ICU (pila)
const NOTIFY_ENTRY = LIBK + 0x48b0n;
let strCursor = 0x8020000000n;

// ---------- libkernel fake con gadgets reales ----------
function put(off, bytes) { M.writeBytes(LIBK + BigInt(off), Uint8Array.from(bytes)); }
put(0x10c0, [0xc3]);                          // ret
put(0x10d0, [0x58, 0xc3]);                    // pop rax; ret
put(0x10d8, [0x5f, 0xc3]);                    // pop rdi; ret
put(0x10e0, [0x5e, 0xc3]);                    // pop rsi; ret
put(0x10e8, [0x5a, 0xc3]);                    // pop rdx; ret
put(0x10f0, [0x59, 0xc3]);                    // pop rcx; ret
put(0x10f8, [0x41, 0x5a, 0xc3]);              // pop r10; ret
put(0x1100, [0x41, 0x58, 0xc3]);              // pop r8; ret
put(0x1108, [0x41, 0x59, 0xc3]);              // pop r9; ret
put(0x1110, [0x5c, 0xc3]);                    // pop rsp; ret
put(0x1118, [0x0f, 0x05, 0xc3]);              // syscall; ret
put(0x1120, [0x48, 0x89, 0x07, 0xc3]);        // mov [rdi],rax; ret
put(0x1128, [0x48, 0x89, 0x27, 0xc3]);        // mov [rdi],rsp; ret
put(0x1130, [0x48, 0x8b, 0xe7, 0xc3]);        // mov rsp,rdi; ret
put(0x1140, [0x49, 0x89, 0xca, 0x48, 0x89, 0xf8, 0x0f, 0x05]); // syscall() wrapper
M.write64(R0STK, ICU_RET);
// UCollator real: m_collator original en COLLCELL+0x18
M.write64(COLLCELL + 0x18n, 0x8011050a00n);
// centinela arena "ROP1" en +0xf00 (el exploit lo deja puesto)
M.writeBytes(ARENA + 0xf00n, Uint8Array.from([0x52, 0x4f, 0x50, 0x31]));

// ---------- kernel fake ----------
let AIO_ALIVE = true;
let PID = 4242, nextFd = 23, mmapCur = 0x7000000000n;
const openFds = new Set();
let tcpConnected = false;
export const out = { notifs: [], tcp: [], pclog: [] };
export function resetOut() {
    out.notifs.length = out.tcp.length = out.pclog.length = 0;
}
function kernel(rax, rdi, rsi, rdx, r10, r8, r9) {
    rax = Number(BigInt.asIntN(64, rax));
    const A = (i) => BigInt.asUintN(64, [rdi, rsi, rdx, r10, r8, r9][i]);
    const neg = (e) => -BigInt(e);
    switch (rax) {
        case 20: return BigInt(PID);                       // getpid
        case 331: return 0n;                               // sched_yield
        case 97: {                                         // socket
            if (A(0) === 2n && A(1) === 1n) { openFds.add(nextFd); return BigInt(nextFd++); }
            return neg(22);                                // EINVAL
        }
        case 98: {                                         // connect
            const fd = Number(A(0));
            if (!openFds.has(fd)) return neg(9);
            const b = M.readBytes(A(1), 16);
            const port = (b[2] << 8) | b[3];
            const ip = `${b[4]}.${b[5]}.${b[6]}.${b[7]}`;
            tcpConnected = true;
            out.tcp.push(`CONNECT ${ip}:${port}`);
            return 0n;
        }
        case 53: {                                         // socketpair
            const a = A(3);
            if (a < 0x100000000n || a > 0x8fffffffffn) return neg(14);
            openFds.add(nextFd); openFds.add(nextFd + 1);
            M.write32(a, nextFd); M.write32(a + 4n, nextFd + 1);
            nextFd += 2;
            return 0n;
        }
        case 4: {                                          // write
            const fd = Number(A(0)), n = Number(A(2));
            if (!openFds.has(fd)) return neg(9);
            const s = Buffer.from(M.readBytes(A(1), Math.min(n, 1024))).toString("latin1").trimEnd();
            out.tcp.push(s);
            console.log("  [PS5→PC:8081] " + s);
            return BigInt(n);
        }
        case 6: openFds.delete(Number(A(0))); return 0n;   // close
        case 3:                                            // read
            if (openFds.has(Number(A(0)))) return 0n;      // EOF
            return neg(9);
        case 5: return neg(2);                              // open ENOENT
        case 33: return neg(2);                             // access ENOENT
        case 99: return 0n;                                 // lseek
        case 9: {                                           // mmap: region propia
            const sz = Math.max(0x1000, (Number(BigInt.asUintN(64, rsi)) + 0xfff) & ~0xfff);
            const a = mmapCur; mmapCur += BigInt(sz); return a;
        }
        case 73: return 0n;                                 // munmap
        case 74: return 0n;                                 // mprotect
        case 54: return openFds.has(Number(A(0))) ? 0n : neg(9); // listen
        case 5: return neg(35);                             // accept EAGAIN
        case 105: return 0n;                                // setsockopt
        case 118: {                                         // getsockopt: valor 0, len 4
            if (A(3)) M.write32(A(3), 0);
            if (A(4)) M.write32(A(4), 4);
            return 0n;
        }
        case 240: return 0n;                                // nanosleep (no-op)
        case 455: return 0n;                                // orbis user_usleep
        case 0x295: case 0x296: case 0x297: case 0x298: case 0x299:
        case 0x29A: case 0x29C: case 0x29D: case 0x29E: case 0x2B0:
        case 0x13B: {
            if (!AIO_ALIVE) return neg(78);                // ENOSYS
            if (rax === 0x29E) return 0n;                  // init
            if (rax === 0x29C) return 0x11n;               // create
            if (rax === 0x297) return neg(35);             // wait EAGAIN
            return neg(22);                                // resto EINVAL
        }
        case 0x2D7: {                                      // GET_AIO_DEBUG_REQUEST_INFO
            if (!AIO_ALIVE) return neg(78);
            const id = Number(BigInt.asUintN(64, rdi));
            const dstv = A(1);
            if (dstv < 0x100000000n || dstv > 0x8fffffffffn) return neg(14); // EFAULT
            if (id >= 1 && id <= 0x228 && Number(BigInt.asUintN(64, rdi) >> 16n) < 0x80) {
                const dst = A(1);
                for (let i = 0; i < 3; ++i) M.write64(dst + BigInt(i * 8), 0xffff860000000000n + BigInt(i) * 0x40n + BigInt(id));
                return 0n;                                 // simula leak
            }
            return neg(22);
        }
        default: return neg(78);                           // ENOSYS
    }
}

// ---------- mini-CPU x86 (solo los gadgets del bridge) ----------
// Semantica real: la pila al entrar al gadget apunta a la dir. de retorno.
// Cada gadget termina en ret: pc = [rsp]; rsp += 8 DESPUES de ejecutar el
// cuerpo. "pop X; ret" consume 2 qwords (valor + siguiente pc).
function cpu(entryPc, st, maxSteps = 200000) {
    let pc = entryPc;
    for (let step = 0; step < maxSteps; ++step) {
        if (pc === ICU_RET) return;             // reingreso a ICU
        const b0 = M.read8(pc), b1 = M.read8(pc + 1n);
        let next = null;                         // pc-advance (multi-byte ins)
        if (b0 === 0xb8) {                       // mov eax, imm32 (stub prologue)
            st.rax = BigInt(M.read32(pc + 1n));
            next = pc + 5n;
        }
        else if (b0 === 0x58 || b0 === 0x5f || b0 === 0x5e || b0 === 0x5a || b0 === 0x59) {
            const v = M.read64(st.rsp); st.rsp += 8n;
            if (b0 === 0x58) st.rax = v; else if (b0 === 0x5f) st.rdi = v;
            else if (b0 === 0x5e) st.rsi = v; else if (b0 === 0x5a) st.rdx = v;
            else st.rcx = v;
        }
        else if (b0 === 0x41 && (b1 === 0x5a || b1 === 0x58 || b1 === 0x59)) {
            const v = M.read64(st.rsp); st.rsp += 8n;
            if (b1 === 0x5a) st.r10 = v; else if (b1 === 0x58) st.r8 = v;
            else st.r9 = v;
        }
        else if (b0 === 0x5c) {                 // pop rsp
            st.rsp = M.read64(st.rsp);
        }
        else if (b0 === 0x0f && b1 === 0x05) {
            st.rax = kernel(st.rax, st.rdi, st.rsi, st.rdx, st.r10, st.r8, st.r9);
        }
        else if (b0 === 0x48 && b1 === 0x89) {
            const modrm = M.read8(pc + 2n);
            if (modrm === 0x07) M.write64(st.rdi, st.rax);          // [rdi]=rax
            else if (modrm === 0x27) M.write64(st.rdi, st.rsp);     // [rdi]=rsp
            else if (modrm === 0x47) M.write64(st.rdi + BigInt(M.read8(pc + 3n)), st.rax);
            else throw new Error("BADGADGET4889:" + modrm.toString(16) + "@" + pc.toString(16));
        }
        else if (b0 === 0x48 && b1 === 0x8b && M.read8(pc + 2n) === 0xe7) {
            st.rsp = st.rdi;                    // mov rsp,rdi
        }
        else if (b0 === 0xc3) { /* ret puro */ }
        else throw new Error("BADGADGET " + b0.toString(16) + "@" + pc.toString(16));
        if (next !== null) { pc = next; continue; }
        pc = M.read64(st.rsp); st.rsp += 8n;    // ret del gadget
    }
    throw new Error("ROP-RUNAWAY");
}

// ---------- ctx tipo handoff (lo que publicaría exploit.js) ----------
function viewProxy() {
    let cur = 0n;
    const proxy = new Proxy(new Array(256), {
        get: (t, i) => (typeof i === "string" && /^\d+$/.test(i)) ? M.read8(cur + BigInt(i)) : t[i],
        set: (t, i, v) => { if (/^\d+$/.test(i)) M.write8(cur + BigInt(i), v); else t[i] = v; return true; },
    });
    const arenaProxy = new Proxy(new Array(0x10000), {
        get: (t, i) => (typeof i === "string" && /^\d+$/.test(i)) ? M.read8(ARENA + BigInt(i)) : (i === "length" ? 0x10000 : t[i]),
        set: (t, i, v) => { if (/^\d+$/.test(i)) M.write8(ARENA + BigInt(i), v); else t[i] = v; return true; },
    });
    return {
        aim(a) { cur = BigInt(a); return proxy; },
        proxy, arenaProxy,
    };
}
function makeCtx() {
    const vp = viewProxy();
    const collatorSaved = M.readBytes(COLLCELL + 0x18n, 0x20);
    return {
        aim: vp.aim,
        view: () => vp.proxy,
        arena: vp.arenaProxy,
        arenaBacking: Number(ARENA),
        arenaBytes: 0x10000,
        fakeCollator: Number(ARENA + 0x100n),
        fakeVtable: Number(ARENA + 0x300n),
        collatorCell: Number(COLLCELL),
        collatorSaved,
        compare(req) {
            const B0 = ARENA + 0x100n;
            const target = M.read64(B0 + 0xe0n);
            const rdi = M.read64(B0 + 0x48n);
            const rcx = M.read64(B0 + 0x60n);
            if (M.read64(COLLCELL + 0x18n) !== ARENA + 0x100n)
                throw new Error("COLLATOR-NOT-ARMED");
            const strA = strCursor; strCursor += 0x2000n;
            M.writeBytes(strA, Buffer.from(String(req), "latin1"));
            if (target === NOTIFY_ENTRY) {
                const msg = Buffer.from(M.readBytes(strA, 0xc30)).toString("latin1")
                    .slice(0x2d).replace(/\x00+$/, "");
                out.notifs.push(msg);
                return 0;
            }
            const st = { rax: 0n, rdi, rsi: strA, rdx: BigInt(String(req).length),
                rcx, r10: 0n, r8: 0n, r9: 0n, rsp: R0STK };
            cpu(target, st);
            return Number(BigInt.asIntN(32, st.rax));
        },
        requestPadded(message) {
            const off = 0x2d, cap = 0xc30;
            let m = String(message), cut = cap - off - 1;
            if (m.length > cut) m = m.slice(0, cut);
            let s = "";
            for (let i = 0; i < cap; ++i) {
                const c = i < off ? 0 : (i < off + m.length ? (m.charCodeAt(i - off) & 0x7f) : 0);
                s += String.fromCharCode(c);
            }
            return s;
        },
        webkitBase: Number(0x8200000000n),
        libkernelBase: Number(LIBK),
        notifyEntry: Number(NOTIFY_ENTRY),
        trampoline: Number(LIBK + 0x1d6fan),
        fw: "13.20",
    };
}

// ---------- sandbox navegador mínimo + carga del bridge ----------
export function bootSim() {
    const sandbox = {};
    sandbox.window = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.console = console;
    sandbox.setTimeout = (f, ms) => {
        const t = setTimeout(f, ms);
        if (t.unref) t.unref(); // timers de UI no mantienen viva la sim
        return t;
    };
    sandbox.clearTimeout = clearTimeout;
    sandbox.URLSearchParams = URLSearchParams;
    sandbox.location = { search: "?go=1&pb=payloads/" };
    sandbox.navigator = { userAgent: "Mozilla/5.0 (PlayStation; PlayStation 5/2.26) AppleWebKit/605.1.15 Version/13.20 PlayStation 5/13.20" };
    sandbox.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
    const lsStore = {};
    sandbox.localStorage = {
        getItem: (k) => (k in lsStore ? lsStore[k] : null),
        setItem: (k, v) => { lsStore[k] = String(v); },
        removeItem: (k) => { delete lsStore[k]; },
    };
    sandbox.__lsStore = lsStore;
    sandbox.__write8 = (a, v) => M.write8(a, v);
    sandbox.setInterval = () => 0;
    sandbox.clearInterval = () => {};
    sandbox.Blob = class { constructor(parts) { this.parts = parts; } };
    sandbox.MutationObserver = class { observe() {} disconnect() {} };
    sandbox.URL = { createObjectURL: () => "blob:sim", revokeObjectURL: () => {} };
    const elems = {};
    const mkEl = (id) => elems[id] || (elems[id] = {
        id, textContent: "", value: "", className: "", innerHTML: "",
        style: {}, scrollTop: 0, scrollHeight: 0, options: [],
        classList: { remove() {} }, appendChild() {},
        querySelector: (s) => mkEl(id + "::" + s),
        addEventListener() {},
    });
    sandbox.__elems = elems;
    sandbox.document = {
        getElementById: mkEl, createElement: () => mkEl("el" + Math.random()),
        querySelector: mkEl("qs"), head: mkEl("head"), body: mkEl("body"),
    };
    sandbox.XMLHttpRequest = class {
        open(m, u) { this.m = m; this.u = u; }
        setRequestHeader() {}
        send(body) {
            const u = this.u;
            // log remoto unificado: POST a http://<host>:8080/log o ruta log/
            if (/\/log\/?$/.test(u) || u.startsWith("log/")) {
                const line = body !== undefined ? String(body) : decodeURIComponent(u.slice(4));
                out.pclog.push(line);
                console.log("  [PS5→PC-LOG] " + line);
                this.status = 200; this.responseText = "";
            } else if (u.startsWith("payloads/") || /\/payloads\//.test(u)) {
                const rel = u.startsWith("payloads/") ? u.slice("payloads/".length)
                    : u.slice(u.indexOf("/payloads/") + "/payloads/".length);
                const f = path.join(PAYLOADS, rel);
                this.status = fs.existsSync(f) ? 200 : 404;
                this.responseText = this.status === 200 ? fs.readFileSync(f, "utf8") : "";
            } else { this.status = 404; this.responseText = ""; }
            if (this.onload) this.onload();
        }
    };
    const ctx = vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(BRIDGE, "utf8"), ctx, { filename: "bridge.js" });
    vm.runInContext(fs.readFileSync(MENU, "utf8"), ctx, { filename: "menu.js" });
    sandbox.__PS5_CTX = makeCtx();
    sandbox.onUserland();
    return sandbox;
}

export function runPayload(name) {
    const src = fs.readFileSync(path.join(PAYLOADS, name), "utf8");
    return src;
}
export function setAioAlive(v) { AIO_ALIVE = !!v; }
export { M };
