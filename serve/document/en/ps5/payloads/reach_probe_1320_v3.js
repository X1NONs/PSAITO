// reach_probe_1320_v3.js -- Y2JB payload: probe de reachability fase 3 (PS5 13.20)
// --------------------------------------------------------------------------------
// Sucesor de reach_probe_1320.js (v2). NO re-pitea bloques ya resueltos en v2
// (SysV=ENOSYS, KSEM vivo, OSEM, /dev). Mide SOLO la superficie nueva que el v2
// dejo sin ejercer o ejercicio solo con args cero:
//
//   B1  sigqueue 0x1c8 (P11, CVE-2026-45259: sys_sigqueue sin check
//       IN_CAPABILITY_MODE). FreeBSD SYS_sigqueue=456=0x1c8
//       (kstuff-13/freebsd-headers/sys/syscall.h:379). Args
//       (pid, signum, value): RESEARCH/fbsd2/src110/kern_sig.c:1833-1870
//       (struct sigqueue_args + sys_sigqueue; pid<=0 -> EINVAL, signum 0 ->
//       solo p_cansignal, signum!=0 -> ksiginfo+pksignal).
//   B2  _umtx_op op=25 UMTX_OP_SHM (P7, CVE-2024-43102; aqui SOLO lifecycle
//       secuencial, SIN race/UAF). RESEARCH/fbsd2/umtx.h:99 (UMTX_OP_SHM=25),
//       :112-115 (UMTX_SHM_CREAT=1, LOOKUP=2, DESTROY=4, ALIVE=8).
//       kern_umtx.c:3895 __umtx_op_shm(td,uap) => umtx_shm(td, uap->uaddr1,
//       uap->val): obj(arg1) IGNORADO, addr-clave = uaddr1(arg4), flags =
//       val(arg3). kern_umtx.c:3849 __bitcount(flags&0xF)!=1 -> EINVAL;
//       LOOKUP sin reg -> ESRCH (kern_umtx.c:3860); CREAT/LOOKUP devuelven fd.
//   B3  IPV6_MSFILTER set/get (P2, CVE-2026-49412). Handler
//       in6p_set_source_filters: RESEARCH/fbsd2/src110/in6_mcast.c:2370
//       (dispatch set :2635, get :1737 con im6o==NULL -> EADDRNOTAVAIL).
//       struct __msfilterreq: kstuff-13/freebsd-headers/netinet/in.h:555:
//         off 0  msfr_ifindex u32 | off 4 msfr_fmode u32 | off 8 msfr_nsrcs u32
//         off 16 msfr_group sockaddr_storage[128] (align 8 por __ss_align,
//              sys/_sockaddr_storage.h:39-51) | off 144 msfr_srcs ptr
//         => sizeof = 152 = 0x98 (NO 0x88).
//       sockaddr_in6: netinet6/in6.h:123 (len=28, fam=28, port@2, flow@4,
//       addr@8, scope@24). MCAST_INCLUDE=1 (netinet/in.h:587).
//       IPV6_MSFILTER=74 (in6.h:488), IPV6_JOIN_GROUP=12/LEAVE=13 (in6.h:402),
//       ipv6_mreq = 16B addr + u32 ifindex = 20B (in6.h:521). IPPROTO_IPV6=41
//       (in.h:177). Check handlers (in6_mcast.c:2382-2420): nsrcs>max ->
//       ENOBUFS; fmode not in {1,2} -> EINVAL; ss_family!=AF_INET6 ||
//       ss_len!=28 -> EINVAL; grupo no multicast -> EINVAL; ifindex invalido
//       -> EADDRNOTAVAIL; sin join previo -> EADDRNOTAVAIL.
//   B4  propietarias 0x2xx con ARGS REALES (el v2 solo paso ceros):
//       get_self_auth_info 0x25f, IOREQ 0x2cb, PHYSHM_OPEN 0x275,
//       BATCH_MAP 0x224 (reproducibilidad del ok:0x0 con args cero),
//       MMAP_DMEM 0x274 (args cero; gemelo de PHYSHM en el playbook, el v2
//       no lo probo). Numeros Orbis: RESEARCH/orbis-syscalls-playbook.md.
//
// NO incluye (deliberadamente): rtsock RTM_GET panic-test (P5 -> payload
// aparte), OSEM_WAIT / umtx WAIT / cualquier llamada bloqueante, carrera de
// ninguna clase (B2 y B3 son lifecycle 100% secuencial).
//
// Riesgo asumido: B1 envia SIGURG (16, default-ignore, no letal ni de stop)
// al propio proceso -- ejercita kern_sigqueue completo (ksiginfo alloc +
// pksignal). B4 llama propietarias con buffers reales que el v2 nunca toco:
// si Sony no valida, podria paniquear (mismo riesgo ya aceptado en v2,
// ampliamente mitigado por EPERM/EFAULT consistentes). BATCH_MAP/MMAP_DMEM
// SOLO con args cero (no args aleatorios: semantica desconocida).
//
// v3 (2026-08-27). Interfaz Y2JB: syscall(), SYSCALL, malloc, alloc_string,
// read8/16/32/64, write8/16/32/64, toHex, log, send_notification,
// get_error_string().

(async () => {
    const R = {};
    const ORDER = [];

    const rec = async (k, v) => {
        R[k] = v; ORDER.push(k);
        try { await log("[probe3] " + k + " = " + v); } catch (e) {}
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

    const isOk     = (v) => (v || "").startsWith("ok");
    const isAbsent = (v) => (v || "").startsWith("ERR:78 ") || (v || "").startsWith("ERR:45 ");
    const isBlock  = (v) => (v || "").startsWith("ERR:") && !isAbsent(v);

    // constantes ABI (verificadas contra RESEARCH/, ver cabecera)
    const SYS_SIGQUEUE   = 0x1c8n;  // 456, syscall.h:379
    const SYS_UMTX_OP    = SYSCALL.umtx_op;              // 0x1c6 (global.js)
    const UMTX_OP_SHM    = 25n;     // umtx.h:99
    const SHM_CREAT      = 0x1n, SHM_LOOKUP = 0x2n;      // umtx.h:112-113
    const SHM_DESTROY    = 0x4n, SHM_ALIVE  = 0x8n;      // umtx.h:114-115
    const IPPROTO_IPV6   = 41n;     // in.h:177
    const IPV6_JOIN_GRP  = 12n, IPV6_LEAVE_GRP = 13n;    // in6.h:402-403
    const IPV6_MSFILTER  = 74n;     // in6.h:488
    const MSFR_SIZE      = 152n;    // sizeof(__msfilterreq) in.h:555 (0x98)
    const SIGURG         = 16n;     // signal.h:84 (default-ignore)

    // =====================================================================
    // B1 -- sigqueue (P11, CVE-2026-45259). Solo señales seguras: signum 0
    // (path de validacion, no entrega) y SIGURG (default-ignore). Nunca
    // KILL/STOP/TERM.
    // =====================================================================
    let pid = 0n;
    try { pid = syscall(SYSCALL.getpid); } catch (e) {}
    await rec("B1:getpid", "ok:" + toHex(pid));

    try {
        await rec("B1:sigqueue(self,0,0)", sy(SYS_SIGQUEUE, pid, 0, 0));
        await rec("B1:sigqueue(self,SIGURG,0)", sy(SYS_SIGQUEUE, pid, SIGURG, 0));
        await rec("B1:sigqueue(pid1,0,0)", sy(SYS_SIGQUEUE, 1, 0, 0));
    } catch (e) { await rec("B1:sigqueue", "EX:" + e); }

    // =====================================================================
    // B2 -- _umtx_op(op=UMTX_OP_SHM=25) lifecycle secuencial (P7).
    // _umtx_op(obj, op, val, uaddr1, uaddr2): obj ignorado, val=flags,
    // uaddr1=addr-clave (kern_umtx.c:3895). Sin concurrencia: no hay race
    // ni UAF trigger, solo registro/busqueda/destruccion.
    // =====================================================================
    try {
        const key = malloc(8);
        write64(key, 0n);
        const shm = (flags) => sy(SYS_UMTX_OP, 0, UMTX_OP_SHM, flags, key, 0);

        await rec("B2:shm:LOOKUP(pre)", await shm(SHM_LOOKUP));      // ESRCH esperado
        const creat = await shm(SHM_CREAT);
        await rec("B2:shm:CREAT", creat);                            // ok + fd
        await rec("B2:shm:LOOKUP(post)", await shm(SHM_LOOKUP));     // ok + fd (mismo?)
        await rec("B2:shm:ALIVE", await shm(SHM_ALIVE));             // ok esperado
        await rec("B2:shm:DESTROY", await shm(SHM_DESTROY));         // ok esperado
        await rec("B2:shm:LOOKUP(gone)", await shm(SHM_LOOKUP));     // ESRCH esperado
        await rec("B2:shm:FLAGS=0x3(2bits)", await shm(0x3n));       // EINVAL (__bitcount)
    } catch (e) { await rec("B2:shm", "EX:" + e); }

    // =====================================================================
    // B3 -- IPV6_MSFILTER (P2, CVE-2026-49412). Lifecycle secuencial:
    // socket -> get(no join) -> set(ceros) -> JOIN -> set(valido) -> LEAVE.
    // =====================================================================
    try {
        const raw = syscall(SYSCALL.socket, 28n, 2n, 0n); // AF_INET6, SOCK_DGRAM
        const s = BigInt.asIntN(64, raw);
        await rec("B3:socket:INET6", s < 0n ? "ERR:" + get_error_string() : "ok fd=" + raw);
        if (s >= 0n) {
            // (a) get sin join: handler in6_mcast.c:1737 -> EADDRNOTAVAIL si
            // esta vivo (optval NULL; optlen buffer real).
            const lenp = malloc(4);
            write32(lenp, Number(MSFR_SIZE));
            await rec("B3:getsockopt:MSFILTER(pre-join)",
                      sy(SYSCALL.getsockopt, s, IPPROTO_IPV6, IPV6_MSFILTER, 0, lenp));

            // (b) set con optval NULL -> copyin fallo (baseline del v2: EINVAL)
            await rec("B3:setsockopt:MSFILTER(NULL)",
                      sy(SYSCALL.setsockopt, s, IPPROTO_IPV6, IPV6_MSFILTER, 0, 0));

            // (c) set con buffer de sizeof(__msfilterreq)=152 a cero: pasa
            // copyin, muere en check de fmode/familia (cero) -> EINVAL.
            // Confirma que el handler hace sooptcopyin + checks.
            const zbuf = malloc(Number(MSFR_SIZE));
            for (let i = 0; i < 0x98; i += 8) write64(zbuf + BigInt(i), 0n);
            await rec("B3:setsockopt:MSFILTER(zeros)",
                      sy(SYSCALL.setsockopt, s, IPPROTO_IPV6, IPV6_MSFILTER, zbuf, MSFR_SIZE));

            // (d) struct __msfilterreq VALIDO: ifindex=1, fmode=MCAST_INCLUDE(1),
            // nsrcs=1, msfr_group=sockaddr_in6 ff02::1 (len 28, fam 28),
            // msfr_srcs -> sockaddr_in6 ::1.
            const ssf = (addr, b0, b15) => {
                // sockaddr_in6 en addr: len@0=28, fam@1=28, port@2=0,
                // flow@4=0, addr@8 (16B), scope@24=0
                write8(addr + 0n, 28); write8(addr + 1n, 28);
                write16(addr + 2n, 0); write32(addr + 4n, 0);
                write64(addr + 8n, b0); write64(addr + 16n, b15);
                write32(addr + 24n, 0);
            };
            const msfr = malloc(Number(MSFR_SIZE));
            const src  = malloc(28);
            write32(msfr + 0n,  1);            // msfr_ifindex = 1 (lo0)
            write32(msfr + 4n,  1);            // msfr_fmode = MCAST_INCLUDE
            write32(msfr + 8n,  1);            // msfr_nsrcs
            write32(msfr + 12n, 0);            // padding
            // ff02::1 -> bytes ff,02,...,01 (ultimo) => LE u64: 0x2ff y 0x0100..00
            ssf(msfr + 16n, 0x2ffn, 0x0100000000000000n);  // msfr_group @16
            write64(msfr + 144n, src);                     // msfr_srcs @144
            ssf(src, 0n, 0x0100000000000000n);             // ::1
            await rec("B3:msfr:built", "ok:" + toHex(msfr));

            // (e) JOIN_GROUP ff02::1/ifindex=1 -- ipv6_mreq: 16B addr + u32 ifindex
            const mreq = malloc(20);
            write64(mreq + 0n,  0x2ffn);                   // ff02::
            write64(mreq + 8n,  0x0100000000000000n);      // ::1
            write32(mreq + 16n, 1);                        // ipv6mr_interface
            await rec("B3:setsockopt:JOIN_GROUP",
                      sy(SYSCALL.setsockopt, s, IPPROTO_IPV6, IPV6_JOIN_GRP, mreq, 20));

            // (f) MSFILTER valido post-join (superficie P2 plena si ok)
            await rec("B3:setsockopt:MSFILTER(valid)",
                      sy(SYSCALL.setsockopt, s, IPPROTO_IPV6, IPV6_MSFILTER, msfr, MSFR_SIZE));

            // (g) limpiar: LEAVE_GROUP y cerrar
            await rec("B3:setsockopt:LEAVE_GROUP",
                      sy(SYSCALL.setsockopt, s, IPPROTO_IPV6, IPV6_LEAVE_GRP, mreq, 20));
            syscall(SYSCALL.close, s);
        }
    } catch (e) { await rec("B3:msfilter", "EX:" + e); }

    // =====================================================================
    // B4 -- propietarias 0x2xx con ARGS REALES (el v2 solo paso ceros).
    // =====================================================================
    await log("[probe3] === B4 propietarias con args reales (riesgo de panic asumido, como v2) ===");

    // get_self_auth_info (0x25f): v2 vio EFAULT con buffer 0x50. Probar 0x88.
    try {
        const bufA = malloc(0x88);
        const stA = sy(0x25f, pid, bufA);
        await rec("B4:get_self_auth_info(pid)", stA);
        const stB = sy(0x25f, 0, bufA);
        await rec("B4:get_self_auth_info(pid0)", stB);
        if (isOk(stA)) {
            let dump = "";
            for (let i = 0; i < 0x88; i += 8)
                dump += toHex(read64(bufA + BigInt(i))) + " ";
            await rec("B4:self_auth_info_dump", dump);
        }
    } catch (e) { await rec("B4:get_self_auth_info", "EX:" + e); }

    // IOREQ (0x2cb): v2 -> EFAULT con (0,0,0): desreferencia args.
    try {
        const b1 = malloc(0x100);
        const b2 = malloc(0x100);
        await rec("B4:IOREQ(0,buf,0x100)", sy(0x2cb, 0, b1, 0x100));
        await rec("B4:IOREQ(1,buf,0x100)", sy(0x2cb, 1, b1, 0x100));
        await rec("B4:IOREQ(0,buf2,0)",    sy(0x2cb, 0, b2, 0));
    } catch (e) { await rec("B4:IOREQ", "EX:" + e); }

    // PHYSHM_OPEN (0x275): v2 -> EFAULT. Variantes con path y buffer reales.
    try {
        const name = alloc_string("phys0");
        await rec("B4:PHYSHM_OPEN(name,0,0)", sy(0x275, name, 0, 0));
        const outp = malloc(8);
        await rec("B4:PHYSHM_OPEN(0,buf,0)",   sy(0x275, 0, outp, 0));
    } catch (e) { await rec("B4:PHYSHM_OPEN", "EX:" + e); }

    // BATCH_MAP (0x224): SOLO reproducibilidad del ok:0x0 del v2 con args
    // cero. NO args aleatorios (semantica de mapeo desconocida).
    await rec("B4:BATCH_MAP(0,0,0)", sy(0x224, 0, 0, 0));

    // MMAP_DMEM (0x274): gemelo de PHYSHM en el playbook;args cero, el v2
    // nunca lo ejercicio.
    await rec("B4:MMAP_DMEM(0,0,0)", sy(0x274, 0, 0, 0));

    // =====================================================================
    // Resumen clasificado por bloque
    // =====================================================================
    // errno FreeBSD 11: ENOSYS=78, ENOTSUP=45, EPERM=1, EINVAL=22,
    // EFAULT=14, ESRCH=3, EACCES=13, EADDRNOTAVAIL=47, ENOBUFS=105,
    // ECAPMODE=94
    const grp = (re) => ORDER.filter(k => re.test(k));
    const list = (ks) => ks.map(k => k.split(":").slice(-1)[0] + "=" + R[k]).join(" | ");

    await log("[probe3] ===== RESULTADO v3 =====");
    await log("[probe3] B1 sigqueue: " + list(grp(/^B1:/)));
    await log("[probe3] B1 veredicto: vivo=" + grp(/^B1:sigqueue/).filter(k => isBlock(R[k]) || isOk(R[k])).length +
              "/3 (ENOSYS total = P11 cerrada en Orbis)");
    await log("[probe3] B2 shm: " + list(grp(/^B2:/)));
    const b2absent = isAbsent(R["B2:shm:LOOKUP(pre)"] || "");
    await log("[probe3] B2 veredicto: ENOSYS/ENOTSUP=" + b2absent +
              " | CREAT ok (fd)=" + isOk(R["B2:shm:CREAT"] || "") +
              " | LOOKUP devuelve fd=" + isOk(R["B2:shm:LOOKUP(post)"] || "") +
              " | ciclo ESRCH->CREAT->ESRCH coherente=" +
              (isBlock(R["B2:shm:LOOKUP(pre)"] || "") && isBlock(R["B2:shm:LOOKUP(gone)"] || "") &&
               isOk(R["B2:shm:CREAT"] || "")));
    await log("[probe3] B3 msfilter: " + list(grp(/^B3:/)));
    await log("[probe3] B3 veredicto: handler vivo=" +
              (isBlock(R["B3:getsockopt:MSFILTER(pre-join)"] || "") || isOk(R["B3:setsockopt:MSFILTER(valid)"] || "")) +
              " | set-valido ok=" + isOk(R["B3:setsockopt:MSFILTER(valid)"] || "") +
              " (P2 plenamente alcanzable si JOIN+MSFILTER ok)");
    await log("[probe3] B4 propietarias: " + list(grp(/^B4:/).filter(k => !/dump/.test(k))));
    await log("[probe3] B4 dump auth_info: " + (R["B4:self_auth_info_dump"] || "(no ok)"));
    await log("[probe3] B4 progreso vs v2 (cero->otro errno): " +
              grp(/^B4:/).filter(k => isOk(R[k]) || (isBlock(R[k]) && !/EFAULT/.test(R[k])))
                 .map(k => k.split(":").slice(-1)[0]).join(", ") + " | (v2: EFAULT/EACCES/EPERM/ok)");
    await log("[probe3] leyenda: ERR:78=ENOSYS(no existe) ERR:45=ENOTSUP | ERR:EPERM/EINVAL/EFAULT/ESRCH/EACCES/EADDRNOTAVAIL=existe,sandbox | ok=llamable");
    try { send_notification("[probe v3] done"); } catch (e) {}
})();
