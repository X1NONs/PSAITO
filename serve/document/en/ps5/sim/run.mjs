// sim/run.mjs — ejecuta la simulacion: bridge + payloads reales de DEMO/
// sobre el entorno fake (ver fakeps5.mjs). Uso: node sim/run.mjs
import vm from "node:vm";
import { bootSim, runPayload, setAioAlive, out } from "./fakeps5.mjs";

const results = [];
function check(name, cond, extra) {
    results.push({ name, pass: !!cond, extra: extra || "" });
    console.log((cond ? "  PASS " : "  FAIL ") + name + (extra ? "  [" + extra + "]" : ""));
}

console.log("=== SIM USERLAND mansoor0x + bridge (post-handoff) ===");
const sb = bootSim();
const PS5 = sb.PS5;
console.log("bridge: modo=" + PS5.mode + " fw=" + PS5.fw
    + " libk=0x" + PS5.libkernelBase.toString(16)
    + " pid-notify=" + out.notifs.length);
check("boot: bridge listo", PS5.ready === true);
check("boot: gadgets ROP completos", PS5.mode === "ROP", PS5.mode);
check("boot: getpid via ROP = 4242",
    String(out.notifs[0]).indexOf("pid=4242") >= 0, out.notifs[0]);

// ---------- menu (DOM stub) ----------
const els = Object.values(sb.__elems);
check("menu: panel visible", 
    els.some((e) => e.style && e.style.display === "block"));
const modeEl = els.find((e) => String(e.textContent).includes("fw 13.20"));
check("menu: badge modo visible", !!modeEl, modeEl ? modeEl.textContent.trim() : "-");
check("menu: rescue DOWNLOAD LOG button exists",
    els.some((e) => e.id === "dlfab"), "dlfab");
check("menu: STOP button wired", !!sb.__psaitoAppend, "append hook");

// ---------- payload 1: hello (canary de API) ----------
console.log("\n-- hello_1320.js (canary API loader) --");
out.pclog.length = 0;
vm.runInContext(runPayload("hello_1320.js"), sb);
await new Promise((r) => setTimeout(r, 30));
check("hello: 3 lineas de log", out.pclog.filter((l) => l.startsWith("[canary]")).length >= 3,
    out.pclog.join(" | "));

// ---------- payload 2: aio_reach, escenario AIO VIVA ----------
console.log("\n-- aio_reach_1320.js · escenario AIO VIVA --");
setAioAlive(true);
out.notifs.length = 0; out.tcp.length = 0; out.pclog.length = 0;
vm.runInContext(runPayload("aio_reach_1320.js"), sb);
const joined = out.tcp.join("\n") + "\n" + out.notifs.join("\n");
check("aio viva: canal TCP abierto (connect+writes)", out.tcp.length > 3,
    out.tcp.length + " lineas, 1a=" + (out.tcp[0] || "-"));
check("aio viva: GATE AL MENOS UNA VIVA", joined.indexOf("AL MENOS UNA VIVA") >= 0);
check("aio viva: DEBUG 0x2D7 escribe (leak SI)", joined.indexOf("leak=SI") >= 0);
check("aio viva: VEREDICTO AIO VIVA", joined.indexOf("VEREDICTO: AIO VIVA") >= 0,
    (out.notifs[out.notifs.length - 1] || "").slice(0, 90));

// ---------- payload 2b: aio_reach, escenario AIO MUERTA (SAR) ----------
console.log("\n-- aio_reach_1320.js · escenario AIO MUERTA (SAR) --");
setAioAlive(false);
out.notifs.length = 0; out.tcp.length = 0; out.pclog.length = 0;
vm.runInContext(runPayload("aio_reach_1320.js"), sb);
const joined2 = out.tcp.join("\n") + "\n" + out.notifs.join("\n");
check("aio muerta: GATE CERRADA por SAR", joined2.indexOf("CERRADA por SAR") >= 0);
check("aio muerta: VEREDICTO AIO MUERTA", joined2.indexOf("AIO MUERTA") >= 0,
    (out.notifs[out.notifs.length - 1] || "").slice(0, 90));

// ---------- bridge: recuperacion de base desde candidata ----------
console.log("\n-- bridge: base fuera de banda + candidata valida --");
const sb2 = bootSim();
{
    const c = sb2.__PS5_CTX;
    c.libkernelBase = 0xDEAD;                       // fuera de banda
    c.kernelBaseCandidates = { getpid: 0x810000000, close: 0x123, error: 0x456,
        getpidPtr: 0, closePtr: 0, errorPtr: 0 };
    sb2.__PS5_CTX = c;
    sb2.onUserland();
}
check("bridge: recupera base getpid y entra en ROP",
    sb2.PS5.mode === "ROP", sb2.PS5.mode + " notes=" + sb2.PS5.notes.join(";"));
check("bridge: nota kbase-recovered-from:getpid",
    sb2.PS5.notes.some((n) => String(n).startsWith("kbase-recovered-from:getpid")));

// ---------- bridge: fallback X1NON (gadgets WebKit + stubs libkernel) ----------
console.log("\n-- bridge: fallback X1NON (libkernel ilegible) --");
const sb3 = bootSim();
{
    const F2 = (await import("node:fs")).readFileSync;
    // 1) gadgets X1NON falsos dentro del "WebKit" del sim (webkitBase=0x8200000000)
    const WK = 0x8200000000n;
    const gbytes = [
        ["pop rdi", 0x1000, [0x5f, 0xc3]],
        ["pop rsi", 0x1010, [0x5e, 0xc3]],
        ["pop rdx", 0x1020, [0x5a, 0xc3]],
        ["pop rcx", 0x1030, [0x59, 0xc3]],
        ["pop rax", 0x1038, [0x58, 0xc3]],
        ["pop r8", 0x1040, [0x41, 0x58, 0xc3]],
        ["pop r9", 0x1050, [0x41, 0x59, 0xc3]],
        ["pop rsp", 0x1060, [0x5c, 0xc3]],
        ["mov [rdi], rax", 0x1070, [0x48, 0x89, 0x07, 0xc3]],
        ["ret", 0x1080, [0xc3]],
    ];
    const wkGadgets = {};
    for (const [name, rva, bytes] of gbytes) {
        wkGadgets[name] = rva;
        let i = 0;
        for (const b of bytes) sb3.__write8(WK + BigInt(rva + i++), b);
    }
    // pivot y save NO van en la tabla X1NON: el bridge los escanea en wk .text
    const pivotAt = 0x2000, saveAt = 0x2010;
    for (const [i, b] of [0x48, 0x8b, 0xe7, 0xc3].entries()) sb3.__write8(WK + BigInt(pivotAt + i), b);
    for (const [i, b] of [0x48, 0x89, 0x27, 0xc3].entries()) sb3.__write8(WK + BigInt(saveAt + i), b);
    // 2) stub getpid en un libkernel alternativo (banda valida, sin gadgets)
    const LK2 = 0x850000000n;
    const getpidRva = 0x1b860;
    // mov eax,20; syscall; ret
    for (const [i, b] of [0xb8, 0x14, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3].entries())
        sb3.__write8(LK2 + BigInt(getpidRva + i), b);
    // 3) tabla X1NON falsa + ctx con base invalida y candidata alternativa
    sb3.X1NON_13X = {
        "13.20": {
            wkGadgets,
            syscallStubs: { "20": getpidRva, "297": 0x1c290 },
        },
    };
    const c3 = sb3.__PS5_CTX;
    c3.libkernelBase = 0xDEAD;
    c3.kernelBaseCandidates = { getpid: Number(LK2), close: 0x123, error: 0x456,
        getpidPtr: 0, closePtr: 0, errorPtr: 0 };
    sb3.__PS5_CTX = c3;
    out.notifs.length = 0;
    sb3.onUserland();
}
check("bridge: fallback X1NON activa stubMode",
    sb3.PS5.mode === "ROP" && sb3.PS5.stubMode === true,
    sb3.PS5.mode + " notes=" + sb3.PS5.notes.join(";"));
check("bridge: stub getpid expuesto",
    sb3.SYSCALL_STUBS && String(sb3.SYSCALL_STUBS["20"]) === String(0x850000000 + 0x1b860),
    sb3.SYSCALL_STUBS ? "0x" + Number(sb3.SYSCALL_STUBS["20"]).toString(16) : "null");
check("bridge: getpid via cadena stub = 4242",
    out.notifs.some((n) => String(n).indexOf("pid=4242") >= 0),
    (out.notifs[0] || "(sin notif)").slice(0, 80));

// ---------- resumen ----------
const fails = results.filter((r) => !r.pass);
console.log("\n=== RESULTADO: " + (results.length - fails.length) + "/" + results.length + " OK ===");
process.exit(fails.length ? 1 : 0);
