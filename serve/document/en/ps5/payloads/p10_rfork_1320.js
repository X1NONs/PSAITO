// 2026-08-27 p10_rfork_1320: probe de reachability P10 (SA-26:55.elf CVE-2026-58088 coredump) -> ?rfork vivo en sandbox Orbis 13.20?
// ABI: SYS_rfork=251=0xFB (syscall.h:221); flags sys/unistd.h:170-173: RFFDG=(1<<2)=0x4 RFPROC=(1<<4)=0x10 RFMEM=(1<<5)=0x20; L166 "operations without RFPROC not supported". Retorno tipo fork: hijo=0, padre=pid_hijo (unistd.h:545 pid_t rfork(int); kern_fork.c no disponible en arbol headers-only). SYS_exit=1 (syscall.h:10).
// Triage: RESEARCH/freebsd-sa-triage-2026-08.md §P10 (trigger = rfork(RFMEM) + mutacion de mapa entre pasadas del coredump). Canal: TCP crudo a 192.168.1.67:8081 (idiéntico diag_raw3).
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const RF_RFFDG=4n,RF_PROC=16n,RF_MEM=32n,SYS_RFORK=251n,SYS_EXIT=1n,SCHED_YIELD=331n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[p10] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[p10] PASO "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const stage=(s)=>{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);return n};
const NENOSYS=78,EINVAL=22,EPERM=1;
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
let p2=null,p3=null,p4=null,p5=null,e2=-1,e3=-1,e4=-1,e5=-1;
// PASO 1: getpid baseline
E(1,"getpid baseline");try{R(1,"pid="+I(syscall(SYSCALL.getpid)))}catch(e){R(1,"EX "+e)}
// PASO 2: rfork(RFMEM solo) - BARATA: sin RFPROC -> esperado EINVAL; ENOSYS=eliminada; EPERM/otro=SAR
E(2,"rfork(RFMEM=0x20 solo) esperado EINVAL");try{p2=I(syscall(SYS_RFORK,RF_MEM));if(p2<0)e2=EN();if(p2===0){W("[p10] HIJO (RFMEM-solo inesperado) vivo, exit");syscall(SYS_EXIT,0n)}}catch(e){R(2,"EX "+e)}
if(p2!==null&&p2<0){R(2,e2===NENOSYS?"ENOSYS: rfork ELIMINADA en Orbis":e2===EINVAL?"EINVAL: syscall EXISTE (rechazo esperado unistd.h:166)":e2===EPERM?"EPERM: SAR":"otro errno="+e2)}
// PASO 3: rfork(RFPROC|RFFDG=0x14) fork clasico COW; hijo SOLO W+exit (memoria COW propia -> W() normal es seguro)
E(3,"rfork(RFPROC|RFFDG=0x14) fork clasico");try{p3=I(syscall(SYS_RFORK,RF_PROC|RF_RFFDG));if(p3<0)e3=EN();if(p3===0){W("[p10] HIJO (fork clasico) vivo, exit");syscall(SYS_EXIT,0n)}else R(3,"ret="+p3+(p3<0?" errno="+e3:""))}catch(e){R(3,"EX "+e)}
if(p3!==null&&p3>0)R(3,"padre: ok pid_hijo="+p3+" (sin wait: zombie inocuo)");
// PASO 4: rfork(RFPROC|RFMEM=0x30) - LA FORMA DE P10 (espacio compartido). Mensaje PRE-STAGEADO en WB ANTES del rfork:
// el hijo NO toca memoria compartida (ni String, ni bucles JS) -> solo 2 syscalls raw: write(sock,WB,n)+exit.
const L4=stage("[p10] HIJO (RFMEM) vivo, exit");
E(4,"rfork(RFPROC|RFMEM=0x30) LA FORMA P10 (heap compartido)");try{p4=I(syscall(SYS_RFORK,RF_PROC|RF_MEM));if(p4<0)e4=EN();if(p4===0){syscall(4n,sock,WB,B(L4));syscall(SYS_EXIT,0n)}}catch(e){R(4,"EX "+e)}
if(p4!==null){if(p4>0)R(4,"padre: ok pid_hijo="+p4);else R(4,"ERR errno="+e4+" (¿SAR?)")}
// PASO 5 (solo si 4 ok): reproducibilidad, 2a rfork(RFPROC|RFMEM)
if(p4!==null&&p4>0){const L5=stage("[p10] HIJO (RFMEM #2) vivo, exit");
E(5,"rfork(RFPROC|RFMEM=0x30) 2a vez reproducibilidad");try{p5=I(syscall(SYS_RFORK,RF_PROC|RF_MEM));if(p5<0)e5=EN();if(p5===0){syscall(4n,sock,WB,B(L5));syscall(SYS_EXIT,0n)}}catch(e){R(5,"EX "+e)}
if(p5!==null){if(p5>0)R(5,"padre: ok pid_hijo="+p5);else R(5,"ERR errno="+e5+" (¿SAR?)")}}else{R(5,"SKIPPED (paso 4 no ok)")}
// PASO 6: veredicto
let v;
if(p2!==null&&p2<0&&e2===NENOSYS)v="rfork eliminada (ENOSYS): P10 CERRADO";
else if(p3!==null&&p3>0&&p4!==null&&p4>0&&p5!==null&&p5>0)v="RFMEM vivo x2: P10 gate ABIERTO (race de coredump posible)";
else if(p3!==null&&p3>0&&p4!==null&&p4>0)v="RFMEM vivo: P10 gate ABIERTO (no reproducido x2)";
else if(p3!==null&&p3>0)v="rfork viva solo fork COW (RFMEM falló): P10 probablemente CERRADO";
else if(p3===null||p3<0)v="rfork vetada por SAR (como thr_new): P10 CERRADO";
else v="inconcreto p2="+p2+" p3="+p3+" p4="+p4+" p5="+p5;
E(6,"getpid + veredicto");try{R(6,"pid="+I(syscall(SYSCALL.getpid)));W("[p10] COMPLETO: consola viva - "+v);N("[p10] "+v.slice(0,90))}catch(e){R(6,"EX "+e)}
// bucle corto: 20 notificaciones del veredicto, cada 3000 sched_yield (legible en pantalla)
for(let i=0;i<20;i++){N("[p10] "+v.slice(0,90));for(let j=0;j<3000;j++){syscall(SCHED_YIELD)}}
// PASO 7: close
E(7,"close(sock)");try{if(sock>=0n)syscall(SYSCALL.close,sock);R(7,"sock "+sock+" closed")}catch(e){R(7,"EX "+e)}
})();
