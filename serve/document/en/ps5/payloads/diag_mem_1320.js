// diag_mem_1320.js -- Y2JB payload: DIAGNOSTICO MINIMO de por que leer
// libc_base crashea el proceso Cobalt (PS5 13.20).
// --------------------------------------------------------------------------------
// PROBLEMA: los probes previos (reach_probe_1320 v3/v4/v5) sufrieron 4 crashes
// del proceso EXACTAMENTE EN EL MISMO PUNTO: el primer contacto con la region
// apuntada por el leak libc_base (pipe-probe / read64 sobre libc_base). El
// ultimo scan murio siempre ahi, con lo que nunca se supo si el leak era
// invalido, la region estaba protegida, o el metodo de sonda estaba roto.
//
// HIPOSISIS PRINCIPAL (XOM/SAR): la region del leak NO es legible desde user
// (Execute-Only Memory / Supervisor-only Access): el kernel la rechaza con
// EFAULT en el copyin del write() del pipe-probe, o el read64 directo produce
// SIGSEGV del proceso. Si el proceso MUERE justo tras el log "PASO 5:
// ejecutando" -> leer esa region mata el proceso -> XOM confirmado como causa
// de los 4 crashes del scan.
//
// DISENO: payload PEQUENO y secuencial. Cada paso loguea ANTES de ejecutarse
// ("[diag] PASO N: <desc> - ejecutando") y DESPUES ("[diag] PASO N result:
// <v>"), cada uno en su propio try/catch (un error JS de un paso NO impide los
// siguientes; SOLO un SIGSEGV/crash del proceso corta la secuencia, y el
// ultimo "ejecutando" recibido identifica al culpable). Sin scan, sin race,
// sin thr_new, sin bucles largos: duracion total < 2s.
//
// Controles incluidos:
//   PASO 3 = control POSITIVO del pipe-probe sobre heap propio (SIEMPRE
//            legible): si diera EFAULT, el metodo de sonda esta roto (no la
//            memoria) y nada de lo demas vale.
//   PASO 5 = pipe-probe de libc_base (write(pipeWr, libc_base, 1)): el kernel
//            hace uiomove DESDE esa direccion; EFAULT(14) = no legible;
//            MUERTE del proceso aqui = lectura de esa region mata el proceso
//            (XOM/SAR) -- es la respuesta buscada.
//   PASO 6 = read64 crudo SOLO si el PASO 5 no dio EFAULT (esperado ELF:
//            bajos 4 bytes 0x464c457f = "\x7fELF" little-endian).
//
// Interfaz Y2JB (globals verificados en global.js/misc.js): syscall(),
// SYSCALL{getpid=0x14, pipe=0x2a, read=0x3, write=0x4, close=0x6}, malloc,
// read32/read64, write64, toHex, log (async), get_error_string() (crudo:
// "<errno> <strerror>", EFAULT=14), send_notification(). Globals de leaks:
// libc_base, eboot_base, libstarboard_base (global.js L25-28) -> cada uno se
// usa solo tras un chequeo typeof, nunca a ciegas.
//
// v1 (2026-08-27). Referencia: 4 crashes en el scan de reach_probe_1320_v5.

(async () => {
    const B = (x) => (typeof x === "bigint" ? x : BigInt(x));

    // log blindado: si el propio log revienta, no corta la secuencia
    const say = async (m) => { try { await log(m); } catch (e) {} };

    // estado compartido entre pasos (fds del pipe para limpieza final)
    let pipeRd = -1n, pipeWr = -1n;
    let scratch = 0n;
    let paso5 = { fault: null }; // null=no EFAULT detectable (sin pipe)

    // ---------------------------------------------------------------------
    // PASO 1: getpid -> baseline de que el runtime esta vivo
    // ---------------------------------------------------------------------
    await say("[diag] PASO 1: getpid (baseline runtime vivo) - ejecutando");
    try {
        const pid = BigInt.asIntN(64, syscall(SYSCALL.getpid));
        await say("[diag] PASO 1 result: pid=" + pid + " (" + toHex(pid) + ")");
    } catch (e) { await say("[diag] PASO 1 result: EX " + e); }

    // ---------------------------------------------------------------------
    // PASO 2: pipe(fds) -> canal de sondeo de legibilidad
    // ---------------------------------------------------------------------
    await say("[diag] PASO 2: pipe(fds) - ejecutando");
    try {
        const pfd = malloc(8);
        const raw = syscall(SYSCALL.pipe, pfd);              // SYS_pipe=0x2a
        const r = BigInt.asIntN(64, raw);
        if (r < 0n) {
            await say("[diag] PASO 2 result: ERR " + get_error_string() +
                      " -> SIN canal de sondeo (pasos 5/7 sin probe, solo read64)");
        } else {
            pipeRd = BigInt.asIntN(32, read32(pfd));         // fds[0] lectura
            pipeWr = BigInt.asIntN(32, read32(pfd + 4n));    // fds[1] escritura
            scratch = malloc(16);                            // patron de drenaje
            await say("[diag] PASO 2 result: ok pipeRd=" + pipeRd +
                      " pipeWr=" + pipeWr + " (fds leidos via read32 de " + toHex(pfd) + ")");
        }
    } catch (e) { await say("[diag] PASO 2 result: EX " + e); }

    // Sonda de legibilidad: write(pipeWr, addr, 1) hace al kernel uiomove
    // DESDE addr (valida la lectura del buffer de usuario EL PROPIO KERNEL,
    // sin riesgo de SIGSEGV). EFAULT(14)=no legible. Ok => drena 1 byte.
    // Devuelve {desc, fault} o null si aun no hay pipe.
    const probe = (addr) => {
        if (pipeWr < 0n) return { desc: "SIN PIPE (paso 2 fallo)", fault: null };
        const raw = syscall(SYSCALL.write, pipeWr, addr, 1n);
        const r = BigInt.asIntN(64, raw);
        if (r < 0n) {
            let es = "errno?";
            try { es = get_error_string(); } catch (e) { es = "get_error_string EX " + e; }
            return { desc: "ERR " + es, fault: /^14(\s|$)/.test(es) || /EFAULT/.test(es) };
        }
        try { syscall(SYSCALL.read, pipeRd, scratch, 1n); } catch (e) {}   // drenar
        return { desc: "ok legible (escribio " + r + " byte, errno=no)", fault: false };
    };

    // ---------------------------------------------------------------------
    // PASO 3: CONTROL POSITIVO del pipe-probe sobre heap propio (malloc).
    // El heap SIEMPRE es legible: si esto da EFAULT, el METODO esta roto
    // (no la memoria) y todo lo demas no vale.
    // ---------------------------------------------------------------------
    await say("[diag] PASO 3: control positivo pipe-probe sobre heap malloc (esperado: ok) - ejecutando");
    try {
        const ctrlBuf = malloc(64);
        write64(ctrlBuf, 0x4141414141414141n);
        if (pipeWr < 0n) {
            await say("[diag] PASO 3 result: SKIPPED (sin pipe; heap escrito ok en " +
                      toHex(ctrlBuf) + ") -> metodo de sonda NO validado");
        } else {
            const p = probe(ctrlBuf);
            await say("[diag] PASO 3 result: " + p.desc +
                      (p.fault ? " -> EL METODO PIPE-PROBE ESTA ROTO (heap EFAULT): nada de lo demas vale"
                               : " -> metodo validado: heap legible"));
        }
    } catch (e) { await say("[diag] PASO 3 result: EX " + e); }

    // ---------------------------------------------------------------------
    // PASO 4: valor del global libc_base (SOLO el valor, sin leer memoria)
    // ---------------------------------------------------------------------
    await say("[diag] PASO 4: leer global libc_base (sin tocar memoria) - ejecutando");
    try {
        if (typeof libc_base === "undefined") {
            await say("[diag] PASO 4 result: global libc_base NO EXISTE (typeof undefined)");
        } else {
            await say("[diag] PASO 4 result: libc_base = " + toHex(B(libc_base)) +
                      " (typeof=" + (typeof libc_base) + ")");
        }
    } catch (e) { await say("[diag] PASO 4 result: EX " + e); }

    // ---------------------------------------------------------------------
    // PASO 5: PIPE-PROBE de libc_base. Si el proceso MUERE aqui (ultimo log
    // recibido = "PASO 5 ... ejecutando"): leer esa region MATA el proceso
    // (XOM/SAR) -> es la respuesta a los 4 crashes del scan.
    // ---------------------------------------------------------------------
    await say("[diag] PASO 5: pipe-probe write(pipeWr, libc_base, 1) - ejecutando");
    try {
        if (typeof libc_base === "undefined") {
            await say("[diag] PASO 5 result: SKIPPED (libc_base no existe)");
        } else {
            const p = probe(B(libc_base));
            paso5.fault = p.fault;
            await say("[diag] PASO 5 result: " + p.desc + " en " + toHex(B(libc_base)) +
                      (p.fault === true ? " -> libc_base NO legible por el kernel (EFAULT): leak invalido o region protegida"
                       : p.fault === false ? " -> libc_base legible: el crash del scan NO es la primera direccion"
                                           : ""));
        }
    } catch (e) { await say("[diag] PASO 5 result: EX " + e); }

    // ---------------------------------------------------------------------
    // PASO 6: read64(libc_base) crudo - SOLO si el PASO 5 NO fue EFAULT.
    // Esperado si el leak es bueno: bajos 4 bytes 0x464c457f ("\x7fELF").
    // ---------------------------------------------------------------------
    await say("[diag] PASO 6: read64(libc_base) (solo si PASO 5 no fue EFAULT) - ejecutando");
    try {
        if (typeof libc_base === "undefined") {
            await say("[diag] PASO 6 result: SKIPPED (libc_base no existe)");
        } else if (paso5.fault === true) {
            await say("[diag] PASO 6 result: SKIPPED (PASO 5 dio EFAULT: leer directo = SIGSEGV seguro)");
        } else {
            const q = read64(B(libc_base));
            const elf = (q & 0xffffffffn) === 0x464c457fn;
            await say("[diag] PASO 6 result: " + toHex(q) +
                      (elf ? " -> ELF magic OK (0x464c457f)" : " -> NO es ELF (leak invalido?)"));
        }
    } catch (e) { await say("[diag] PASO 6 result: EX " + e); }

    // ---------------------------------------------------------------------
    // PASO 7: pipe-probe de libc_base+0x4000 (mitad de la primera pagina
    // supuesta, PAGE_SIZE=0x4000) + read64 solo si el probe la vio legible.
    // ---------------------------------------------------------------------
    await say("[diag] PASO 7: pipe-probe libc_base+0x4000 (+read64 si legible) - ejecutando");
    try {
        if (typeof libc_base === "undefined") {
            await say("[diag] PASO 7 result: SKIPPED (libc_base no existe)");
        } else {
            const a = B(libc_base) + 0x4000n;
            const p = probe(a);
            let extra = "";
            if (p.fault === false) {
                try {
                    const q = read64(a);
                    extra = " | read64=" + toHex(q);
                } catch (e) { extra = " | read64 EX " + e; }
            }
            await say("[diag] PASO 7 result: " + p.desc + " en " + toHex(a) + extra);
        }
    } catch (e) { await say("[diag] PASO 7 result: EX " + e); }

    // ---------------------------------------------------------------------
    // PASO 8: valores de eboot_base / libstarboard_base si existen (typeof),
    // SOLO log del valor hex (sin leer memoria) -> contexto del leak.
    // ---------------------------------------------------------------------
    await say("[diag] PASO 8: log de eboot_base / libstarboard_base (sin leer memoria) - ejecutando");
    try {
        const parts = [];
        try { parts.push("eboot_base=" + (typeof eboot_base === "undefined"
              ? "NO EXISTE" : toHex(B(eboot_base)))); } catch (e) { parts.push("eboot_base EX " + e); }
        try { parts.push("libstarboard_base=" + (typeof libstarboard_base === "undefined"
              ? "NO EXISTE" : toHex(B(libstarboard_base)))); } catch (e) { parts.push("libstarboard_base EX " + e); }
        await say("[diag] PASO 8 result: " + parts.join(" | "));
    } catch (e) { await say("[diag] PASO 8 result: EX " + e); }

    // ---------------------------------------------------------------------
    // PASO 9 (final): getpid de nuevo + veredicto de consola viva
    // ---------------------------------------------------------------------
    await say("[diag] PASO 9: getpid final + send_notification - ejecutando");
    try {
        const pid2 = BigInt.asIntN(64, syscall(SYSCALL.getpid));
        await say("[diag] PASO 9 result: pid=" + pid2 + " (" + toHex(pid2) + ")");
        await say("[diag] COMPLETO: consola viva al final del diagnostico");
        try { send_notification("[diag] done"); } catch (e) {}
    } catch (e) { await say("[diag] PASO 9 result: EX " + e); }

    // ---------------------------------------------------------------------
    // PASO 10: limpieza - close de los fds del pipe
    // ---------------------------------------------------------------------
    await say("[diag] PASO 10: close(pipeRd), close(pipeWr) - ejecutando");
    try {
        if (pipeRd >= 0n) syscall(SYSCALL.close, pipeRd);
        if (pipeWr >= 0n) syscall(SYSCALL.close, pipeWr);
        await say("[diag] PASO 10 result: fds cerrados (" + pipeRd + "," + pipeWr + ")");
    } catch (e) { await say("[diag] PASO 10 result: EX " + e); }
})();
