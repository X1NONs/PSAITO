// reach_probe_1320.js -- Y2JB payload: probe de reachability (PS5 13.20)
// -----------------------------------------------------------------------
// Ejecutar como payload de Y2JB (sender). NO toca kernel. Mide qué
// syscalls/devices/red del sandbox de la app quedan accesibles, para
// decidir la superficie de ataque kernel desde este contexto.
//
// Interfaz Y2JB (global.js/main.js/misc.js): syscall(), SYSCALL, malloc,
// alloc_string, read32/read64, toHex, log, send_notification,
// get_error_string().
//
// v2 (2026-08-27) -- fixes verificados contra FreeBSD releng/11.0 y la
// tabla de slopkit (RESEARCH/orbis-syscalls-playbook.md):
//  - SysV: números REALES de FreeBSD amd64 (0xa9-0xab, 0xdd-0xe7,
//    0x18e, 0x1ff, 0x200). La lista vieja [0x38..0x71] probaba
//    revoke/symlink/umask/chroot/SOCKETEX, no SysV.
//  - TIOCNOTTY = 0x20007471 (antes 0x4e, inexistente) y
//    TIOCSCTTY = 0x20007461 (antes 0x40207461). sys/ttycom.h 11.0.
//  - IPV6_MSFILTER = 74 (antes 51 = IPV6_RTHDR, primitiva quemada de
//    lapse/IPv6-UAF). netinet6/in6.h releng/11.0.
//  - ksem_init(semid_t *idp, unsigned int value): args en orden correcto
//    y con buffer real (antes (1,0) = EFAULT seguro aunque exista).
//  - socket(AF_ROUTE) con SOCK_RAW(3), no SOCK_DGRAM (rtsock exige raw).
//  - OSEM_WAIT -> OSEM_TRYWAIT (evita colgar el payload si el handle 0
//    llegara a ser válido).
//  - Manejo de signo: el wrapper devuelve rax crudo en BigUint64Array
//    (-1 => 0xffffffffffffffffn, que NO es < 0n) => BigInt.asIntN(64, r).
//  - ENOSYS = errno 78 en FreeBSD => clasificación precisa en el resumen.
//  - Añadidos: bloque 0x2xx extra (PHYSHM_OPEN, GET_PHYS_PAGE_SIZE,
//    QUERY_MEMORY_PROTECTION, BATCH_MAP, REGMGR_CALL, VIRTUAL_QUERY,
//    NAMEDOBJ_CREATE, GET_SELF_AUTH_INFO con dump), /dev/notification0
//    como control positivo, /dev/zero, /dev/random, /dev/rnd.
//
// Riesgo asumido: syscalls propietarias con args cero podrían paniquear
// si Sony no valida args. Se avisa por log antes del bloque.

(async () => {
    const R = {};
    const ORDER = [];

    const rec = async (k, v) => {
        R[k] = v; ORDER.push(k);
        try { await log("[probe] " + k + " = " + v); } catch (e) {}
    };

    const B = (x) => (typeof x === "bigint" ? x : BigInt(x));

    const sy = (num, ...args) => {
        try {
            const raw = syscall(B(num), ...args.map(B));
            const r = BigInt.asIntN(64, raw);
            if (r < 0n) return "ERR:" + get_error_string();
            return "ok:" + toHex(raw);
        } catch (e) { return "EX:" + e; }
    };

    // 1) identidad (controles)
    await rec("getpid",        sy(SYSCALL.getpid));        // 0x014
    await rec("getuid",        sy(SYSCALL.getuid));        // 0x018
    await rec("geteuid",       sy(0x19));
    await rec("getgid",        sy(0x2f));
    await rec("getegid",       sy(0x2b));
    await rec("is_in_sandbox", sy(SYSCALL.is_in_sandbox)); // 0x249

    // 2) SysV IPC -- NEGATIVO esperado en Orbis (slots FreeBSD eliminados)
    //    Cierra P1 (semctl OOB). syscalls.master releng/11.0:
    //    semsys/msgsys/shmsys (0xa9-0xab), semget..shmget (0xdd-0xe7),
    //    __semctl (398=0x18e), msgctl/shmctl modernos (511/512).
    const sysv_candidates = [0xa9, 0xaa, 0xab, 0xdd, 0xde, 0xdf, 0xe0, 0xe1,
                             0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0x18e, 0x1ff, 0x200];
    for (const n of sysv_candidates)
        await rec("sysv?" + n.toString(16), sy(n, 0, 0, 0));

    // 3) KSEM (posix sems kernel, 0x190-0x198) -- test REAL con handle
    //    FreeBSD: ksem_init(semid_t *idp, unsigned int value)
    try {
        const idp = malloc(4);
        const init = sy(0x194, idp, 1);
        await rec("ksem_init", init);
        if (init.startsWith("ok:")) {
            const sem = read32(idp);
            const valp = malloc(4);
            const gv = sy(0x197, sem, valp);            // ksem_getvalue(id, *val)
            await rec("ksem_getvalue", gv);
            if (gv.startsWith("ok:")) await rec("ksem_value", "ok:" + toHex(read32(valp)));
            await rec("ksem_trywait", sy(0x193, sem));
            await rec("ksem_post",    sy(0x191, sem));
            await rec("ksem_close",   sy(0x190, sem));
        }
    } catch (e) { await rec("ksem", "EX:" + e); }

    // 3b) OSEM (Orbis, 0x225-0x22C) -- ABI desconocido; lo que no sea
    //     ENOSYS = superficie viva. trywait, nunca wait (no bloquear).
    await rec("osem_create",  sy(0x225, 0, 16, 1, 0x20000));
    await rec("osem_open",    sy(0x227, 0, 1));
    await rec("osem_trywait", sy(0x22a, 0));
    await rec("osem_post",    sy(0x22b, 0));

    // 3c) umtx_op (0x1c6): op 0 (UMTX_OP_LOCK) con umtx NULL -> EFAULT si vivo
    await rec("umtx_op", sy(SYSCALL.umtx_op, 0, 0, 0, 0, 0));

    // 4) syscalls propietarias de atención (superficie novedosa)
    await log("[probe] === bloque propietario 0x2xx (riesgo de panic asumido) ===");
    await rec("FSC2H_CTRL",  sy(0x2c4, 0, 0, 0));   // rumor kexploit privado
    await rec("IOREQ",       sy(0x2cb, 0, 0, 0));
    await rec("STREAMWRITE", sy(0x2c5, 0, 0, 0));
    await rec("procctl",     sy(0x2b1, 0, 0, 0, 0));

    // 4b) extras 0x2xx baratos (NULL args -> EFAULT si el path está vivo)
    await rec("PHYSHM_OPEN",             sy(0x275, 0, 0, 0));
    await rec("GET_PHYS_PAGE_SIZE",      sy(0x2c1));
    await rec("QUERY_MEMORY_PROTECTION", sy(0x223, 0, 0, 0, 0));
    await rec("BATCH_MAP",               sy(0x224, 0, 0, 0));
    await rec("REGMGR_CALL",             sy(0x214, 0, 0, 0));
    await rec("VIRTUAL_QUERY",           sy(0x23c, 0, 0, 0));
    await rec("NAMEDOBJ_CREATE",         sy(0x22d, 0, 0));

    // 4c) GET_SELF_AUTH_INFO (0x25f): si responde, dump authid/caps/attrs
    //     del proceso (struct 0x50) -- señal directa para el plan data-only.
    try {
        const pid = syscall(SYSCALL.getpid);
        const auth = malloc(0x50);
        const st = sy(0x25f, pid, auth);
        await rec("get_self_auth_info", st);
        if (st.startsWith("ok:")) {
            let dump = "";
            for (let i = 0; i < 0x50; i += 8)
                dump += toHex(read64(auth + BigInt(i))) + " ";
            await rec("self_auth_info", dump);
        }
    } catch (e) { await rec("self_auth_info", "EX:" + e); }

    // 5) /dev/* -- apertura (O_RDONLY = 0). notification0 = control positivo.
    //    /dev/ptmx se deja abierto para el bloque 6.
    const devs = ["/dev/null", "/dev/zero", "/dev/console", "/dev/tty", "/dev/ptmx",
                  "/dev/dsp", "/dev/hwpmc", "/dev/urandom", "/dev/random", "/dev/rnd",
                  "/dev/mem", "/dev/kmem", "/dev/gpu0", "/dev/sce_dipsw", "/dev/usbd0",
                  "/dev/crypto", "/dev/notification0"];
    let ptmxfd = -1n;
    for (const d of devs) {
        try {
            const p = alloc_string(d);
            const raw = syscall(SYSCALL.open, p, 0n);
            const fd = BigInt.asIntN(64, raw);
            await rec("open:" + d, fd < 0n ? "ERR:" + get_error_string() : "open ok fd=" + raw);
            if (fd >= 0n) {
                if (d === "/dev/ptmx") ptmxfd = fd;
                else syscall(SYSCALL.close, fd);
            }
        } catch (e) { await rec("open:" + d, "EX:" + e); }
    }

    // 6) pty (control terminal) -- CVE-2026-58093 (P4): TIOCSCTTY UAF.
    //    sys/ttycom.h 11.0: TIOCNOTTY = _IO('t',113) = 0x20007471
    //                       TIOCSCTTY  = _IO('t',97)  = 0x20007461
    if (ptmxfd >= 0n) {
        await rec("ioctl:TIOCNOTTY(0x20007471)", sy(SYSCALL.ioctl, ptmxfd, 0x20007471n, 0));
        await rec("ioctl:TIOCSCTTY(0x20007461)", sy(SYSCALL.ioctl, ptmxfd, 0x20007461n, 0));
        syscall(SYSCALL.close, ptmxfd);
    } else {
        await rec("pty", "skipped (sin /dev/ptmx)");
    }

    // 7) red: AF_ROUTE(17) + SOCK_RAW(3) -- CVE-2026-3038 (P5, rtsock)
    await rec("socket:AF_ROUTE(17,RAW)", sy(SYSCALL.socket, 17, 3, 0));
    // IPv6: control RTHDR (51, primitiva lapse quemada) + MSFILTER real
    // (74, CVE-2026-49412 P2). optval NULL -> EFAULT si el path existe.
    try {
        const raw = syscall(SYSCALL.socket, 28n, 2n, 0n); // AF_INET6, DGRAM
        const s = BigInt.asIntN(64, raw);
        await rec("socket:INET6", s < 0n ? "ERR:" + get_error_string() : "ok fd=" + raw);
        if (s >= 0n) {
            await rec("setsockopt:IPV6_RTHDR(41,51)",    sy(SYSCALL.setsockopt, s, 41, 51, 0, 0));
            await rec("setsockopt:IPV6_MSFILTER(41,74)", sy(SYSCALL.setsockopt, s, 41, 74, 0, 0));
            syscall(SYSCALL.close, s);
        }
    } catch (e) { await rec("net6", "EX:" + e); }

    // 8) señales / threads -- P3 = CVE-2026-45256 thr_kill2 (0x1e1, no 0x1b1)
    await rec("kill(0,0)",        sy(SYSCALL.kill, 0, 0));
    await rec("thr_self",         sy(0x1b0));
    await rec("thr_kill(0,0)",    sy(0x1b1, 0, 0));
    await rec("thr_kill2(0,0,0)", sy(0x1e1, 0, 0, 0));
    // rtprio_thread(RTP_LOOKUP=0, lwpid 0=self, buf) con buffer real
    try {
        const rp = malloc(4);
        await rec("rtprio_thread:LOOKUP", sy(0x1d2, 0, 0, rp));
    } catch (e) { await rec("rtprio_thread", "EX:" + e); }

    // resumen clasificado (errno FreeBSD 11: ENOSYS=78, ENOTSUP=45,
    // EPERM=1, ENOTCAPABLE=93, ECAPMODE=94)
    const isOk     = (v) => v.startsWith("ok");
    const isAbsent = (v) => v.startsWith("ERR:78 ");
    const isBlock  = (v) => v.startsWith("ERR:") && !isAbsent(v);
    const grp = (re) => ORDER.filter(k => re.test(k));
    const PROPRIE = /^(FSC2H_CTRL|IOREQ|STREAMWRITE|procctl|PHYSHM_OPEN|GET_PHYS_PAGE_SIZE|QUERY_MEMORY_PROTECTION|BATCH_MAP|REGMGR_CALL|VIRTUAL_QUERY|NAMEDOBJ_CREATE|get_self_auth_info|osem_|umtx_op|ksem_)/;

    await log("[probe] ===== RESULTADO =====");
    await log("[probe] SysV ausente (ENOSYS): " +
              grp(/^sysv\?/).filter(k => isAbsent(R[k])).length + "/" + grp(/^sysv\?/).length +
              "  -> si 17/17, P1 (semctl OOB) CERRADO en consola");
    await log("[probe] KSEM vivo: " + isOk(R["ksem_init"] || "") +
              " | OSEM create ok: " + isOk(R["osem_create"] || "") +
              " | umtx ok: " + isOk(R["umtx_op"] || ""));
    await log("[probe] /dev abiertos: " +
              grp(/^open:/).filter(k => R[k].startsWith("open ok")).map(k => k.slice(5)).join(", "));
    const propOk = grp(PROPRIE).filter(k => isOk(R[k]));
    const propBlock = grp(PROPRIE).filter(k => isBlock(R[k]));
    await log("[probe] 0x2xx/OSEM/KSEM ok: " + (propOk.join(", ") || "(ninguna)"));
    await log("[probe] 0x2xx/OSEM/KSEM bloqueadas (existen, sandbox): " + propBlock.length);
    await log("[probe] self_auth_info: " + (R["self_auth_info"] || "(no disponible)"));
    await log("[probe] leyenda: ERR:78=ENOSYS(no existe) | ERR:EPERM/EINVAL/ENOTCAPABLE=existe, sandbox | ok=llamable");
    try { send_notification("[probe] done. log en console/PC."); } catch (e) {}
})();
