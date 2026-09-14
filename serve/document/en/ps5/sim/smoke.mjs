// 2026-09-11 smoke.mjs — pasa TODOS los payloads de DEMO/payloads por el
// entorno simulado (bridge real + kernel fake) con watchdog por payload.
// No valida logica del payload: caza crashes de compatibilidad API del
// bridge (TypeError/not-defined), hangs y errores de sintaxis.
// Uso: node sim/smoke.mjs [--timeout=ms]
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import * as F from "./fakeps5.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.resolve(HERE, "../payloads");
const TO = Number((process.argv.find((a) => a.startsWith("--timeout=")) || "").split("=")[1]) || 4000;
const ONLY = (process.argv.find((a) => a.startsWith("--only=")) || "").slice(7)
    .split(",").map((s) => s.trim()).filter(Boolean);

let files = fs.readdirSync(DIR).filter((f) => f.endsWith(".js")).sort();
if (ONLY.length) files = files.filter((f) => ONLY.some((o) => f.includes(o)));
const tally = {};
const rows = [];
for (const f of files) {
    const src = fs.readFileSync(path.join(DIR, f), "utf8");
    let st, info = "";
    const t0 = Date.now();
    let logs = 0, tcp = 0, last = "";
    try {
        F.resetOut();
        const sb = F.bootSim();
        vm.runInContext(src, sb, { filename: f, timeout: TO });
        st = "OK";
    } catch (e) {
        const m = String((e && e.message) || e).split("\n")[0];
        if (/timed out/i.test(m)) st = "HANG";
        else if (/is not a function|is not defined|Cannot read propert.*undefined/.test(m)) st = "APIGAP";
        else st = "CRASH";
        info = m.slice(0, 78);
    }
    logs = F.out.pclog.length; tcp = F.out.tcp.length;
    last = F.out.pclog.length ? String(F.out.pclog[F.out.pclog.length - 1]).slice(0, 60) : "";
    tally[st] = (tally[st] || 0) + 1;
    rows.push([st, f, Date.now() - t0, logs, tcp, info || last]);
}
const W = { OK: "#", HANG: "H", APIGAP: "A", CRASH: "C" };
for (const [st, f, ms, logs, tcp, info] of rows)
    console.log(`${W[st] || "?"} ${st.padEnd(6)} ${f.padEnd(28)} ${String(ms).padStart(5)}ms log=${String(logs).padStart(3)} tcp=${String(tcp).padStart(3)}  ${info}`);
console.log("---");
console.log(Object.entries(tally).map(([k, v]) => `${k}=${v}`).join("  "), " total=" + files.length);
