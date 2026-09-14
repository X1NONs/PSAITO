// 2026-08-27 rop_bisect4_1320: HALLAZGO CLAVE: los payloads muertos hicieron mmap(4MB,MAP_PRIVATE|MAP_ANONYMOUS), los vivos no -> mmap anonimo crudo MATA el proceso en Orbis 13.20 (SAR). FIX: stack del hilo via malloc (heap del motor, ya mapeado, demostrado): cero mmap/munmap.
// Tests: M=malloc(0x400000) write+read ultimo qword (sin heap -> omite el resto). T: start=ret(cob+0x31)+[&pop_rsp,A] spin -> thr_new+entrada. T2 (si T no OK): start=pop_rax(cob+0x35942,DEMOSTRADO call_rop)+misma spin. G: [&pop_rax,MARK,&pop_rdi,buf,&mov[rdi],rax,&pop_rsp,loop]->buf==MARK. S: STUB libc+0x19E34F getpid(20) sin TLS ->buf2=pid.
// LAYOUT: stack=malloc(0x400000) | [top-64..top-8]=8x chainAddr (tolerancia rsp kernel, RSP_OFFSET=0x10) | chainAddr=top-8-8*(8+Nq)<=top-72 | cadena Nq qwords, ultima=A (loopback). Hilos VIVOS a proposito (spin inocuo; no thr_kill2/munmap: heap lo gestiona el runtime). Canal: W() TCP 192.168.1.67:8081 + N() por test; polls acotados; cero lectura modulos.
(() => {
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x);const WB=malloc(512);let sock=-1n;
const N=(s)=>{try{send_notification(s);}catch(e){}};
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const CN=()=>{const s=I(syscall(SYSCALL.socket,2n,1n,0n));if(s<0n)return -1n;const a=malloc(16);write8(a,16);write8(a+1n,2);write16(a+2n,0x911Fn);write32(a+4n,0x4301A8C0n);write64(a+8n,0n);if(I(syscall(SYSCALL.connect,s,a,16n))<0n){syscall(SYSCALL.close,s);return -1n;}return s;};
try{sock=CN();if(sock<0n)sock=-1n;}catch(e){sock=-1n;}
const STK=0x400000n,MARK=0x4141414141414141n;let pid=0n;const g={};let okb=false;
if(typeof libcobalt_base!=="undefined"&&typeof libc_base!=="undefined"&&B(libcobalt_base)!==0n&&B(libc_base)!==0n){const c=B(libcobalt_base),L=B(libc_base);
g.pop_rsp=c+0x6f7c7n;g.pop_rax=c+0x35942n;g.pop_rdi=c+0x54bn;g.pop_rsi=c+0x26a5n;g.pop_rdx=c+0x81300n;g.pop_rcx=c+0x25e9n;g.pop_r8=c+0x35941n;g.pop_r9=c+0x3d9132n;g.mov_qword_rdi_rax=c+0x6fcecn;g.ret=c+0x31n;g.STUB=L+0x19E348n+7n;okb=true;}
// spawn HEAP (unica T/T2/G/S): base=malloc(Number(STK)); ArrayBuffer queda vivo en el runtime. Techo [top-8..top-64]=A x8: cualquier rsp_inicial del kernel (RSP_OFFSET 0x10) manda la 1a ret/pop_rsp a A. Cadena: A=top-8-8*(8+Nq)<=top-72, ultima=A (loopback). tf: rip=sf, stack, ct=tid.
const spawn=(sf,ch)=>{
const base=malloc(Number(STK));
if(base<=0n){W("[bisect4] malloc stack ERR");return null;}
const top=base+STK,Nq=ch.length,A=top-8n-8n*(8n+B(Nq));
ch[Nq-1]=A;
for(let i=0;i<Nq;i++)write64(A+8n*B(i),ch[i]);
for(let k=1;k<=8;k++)write64(top-8n*B(k),A); // techo: 8x chainAddr
const tp=malloc(0x68);for(let i=0;i<0x68;i+=8)write64(tp+BigInt(i),0n);const ct=malloc(8);write64(ct,0n);
write64(tp,sf);write64(tp+8n,0n);write64(tp+0x10n,base);write64(tp+0x18n,STK);write64(tp+0x30n,ct);
const tr=I(syscall(SYSCALL.thr_new,tp,B(0x68)));
if(tr<0n){W("[bisect4] thr_new ERR: "+get_error_string());return null;}
const tid=B(read32(ct));if(tid===0n){W("[bisect4] tid=0");return null;}
return{base:base,A:A,tid:tid};};
// poll acotado: 50000 yields, read64 buf cada 32. Buffers malloc PROPIOS.
const poll=(buf)=>{for(let i=0;i<50000;i++){syscall(SYSCALL.sched_yield);if(i%32===0){const v=B(read64(buf));if(v!==0n)return v;}}return B(read64(buf));};
try{
try{pid=I(syscall(SYSCALL.getpid));}catch(e){}
W("[bisect4] pid="+toHex(pid)+" cob="+(okb?toHex(B(libcobalt_base)):"NO")+" libc="+(okb?toHex(B(libc_base)):"NO")+" STUB="+(okb?toHex(g.STUB):"?"));
if(!okb){W("[bisect4] ABORT: sin bases");N("[bisect4] abort no-bases");return;}
let rM="EX",rT="EX",rT2="EX",rG="EX",rS="EX";
// TEST M: malloc(4MB) escribible: write64(mTop-8,MARK)+read64==MARK? Si no OMITE T/T2/G/S.
W("[bisect4] TEST M lanzando (malloc 4MB write+read)");
const mBase=malloc(Number(STK)),mTop=mBase+STK;
write64(mTop-8n,MARK);
if(B(read64(mTop-8n))===MARK){rM="OK";W("[bisect4] M=OK (malloc 4MB escribible)");N("[bisect4] M=OK (malloc 4MB escribible)");}
else{rM="FALLO";W("[bisect4] M=FALLO: read64!=MARK -> omito T/T2/G/S");N("[bisect4] M=FALLO: omito T/T2/G/S");}
let sf=g.pop_rsp,sfn="pop_rsp";
if(rM!=="OK"){rT="SKIP";rT2="SKIP";rG="SKIP";rS="SKIP";}else{
// TEST T: start=ret: 1a ret->[rsp_inicial]=A (relleno). [&pop_rsp,A] spin (re-alimenta). Sobrevive 15000 yields -> thr_new OK.
W("[bisect4] TEST T lanzando (start_func=ret cob+0x31)");
const cT=[g.pop_rsp,0n];
const tT=spawn(g.ret,cT);
if(!tT){rT="spawn-fallo";N("[bisect4] T=spawn-fallo");}else{
W("[bisect4] T tid="+tT.tid+" spin pop_rsp A="+toHex(tT.A));
for(let i=0;i<15000;i++)syscall(SYSCALL.sched_yield);
rT="OK";N("[bisect4] T=OK: thr_new funciona");}
// TEST T2 (si T no OK): start=pop_rax (DEMOSTRADO call_rop): pop rax<-A, ret->[rsp_inicial+8]=otra copia -> misma spin. T muerto+T2 vivo => start_func; ambos muertos => thr_new restringido.
if(rT==="OK"){rT2="SKIP";W("[bisect4] TEST T2 omitido (T OK)");}else{
W("[bisect4] TEST T2 lanzando (start_func=pop_rax cob+0x35942)");
const cT2=[g.pop_rsp,0n];
const tT2=spawn(g.pop_rax,cT2);
if(!tT2){rT2="spawn-fallo";N("[bisect4] T2=spawn-fallo");}else{
W("[bisect4] T2 tid="+tT2.tid+" spin start=pop_rax A="+toHex(tT2.A));
for(let i=0;i<15000;i++)syscall(SYSCALL.sched_yield);
rT2="OK";N("[bisect4] T2=OK: start_func era el problema");}}
// start G/S: pop_rsp si T OK; si no pop_rax si T2 OK.
sf=(rT==="OK")?g.pop_rsp:((rT2==="OK")?g.pop_rax:g.pop_rsp);sfn=(sf===g.pop_rax)?"pop_rax":"pop_rsp";
// TEST G (=B v2): [&pop_rax,MARK,&pop_rdi,buf,&mov[rdi],rax,&pop_rsp,loop] bucle MARK->buf.
W("[bisect4] TEST G lanzando (start_func="+sfn+")");
const buf=malloc(8);write64(buf,0n);
const cG=[g.pop_rax,MARK,g.pop_rdi,buf,g.mov_qword_rdi_rax,g.pop_rsp,0n];
const tG=spawn(sf,cG);
if(!tG){rG="spawn-fallo";N("[bisect4] G=spawn-fallo");}else{
W("[bisect4] G tid="+tG.tid+" bucle marker->buf A="+toHex(tG.A));
const v1=poll(buf);
if(v1===MARK){rG="OK";W("[bisect4] G=OK MARK en buf");N("[bisect4] G=OK");}
else{rG="FALLO";W("[bisect4] G=FALLO buf="+toHex(v1)+" (gadgets matan el hilo)");N("[bisect4] G=FALLO buf="+toHex(v1));}}
// TEST S (=C v2): STUB libc+0x19E34F getpid(20) SIN TLS. rax=20 Y rdi=20 (cinturon p/2 semanticas).
W("[bisect4] TEST S lanzando (start_func="+sfn+")");
const buf2=malloc(8);write64(buf2,0n);
const cS=[g.pop_rax,20n,g.pop_rdi,20n,g.pop_rsi,0n,g.pop_rdx,0n,g.pop_rcx,0n,g.pop_r8,0n,g.pop_r9,0n,g.STUB,g.pop_rdi,buf2,g.mov_qword_rdi_rax,g.pop_rsp,0n];
const tS=spawn(sf,cS);
if(!tS){rS="spawn-fallo";N("[bisect4] S=spawn-fallo");}else{
W("[bisect4] S tid="+tS.tid+" bucle getpid(20) via STUB->buf2 A="+toHex(tS.A));
const v2=poll(buf2);
if(v2!==0n){rS="OK";W("[bisect4] S=OK STUB sin TLS pid_leido="+toHex(v2)+" match="+(v2===pid));N("[bisect4] S=OK pid="+toHex(v2)+" match="+(v2===pid));}
else{rS="FALLO";W("[bisect4] S=FALLO: STUB colgado/muerto (fs=0/TLS)");N("[bisect4] S=FALLO");}}
}
const resum="[bisect4] RESUMEN: M="+rM+" T="+rT+" T2="+rT2+" G="+rG+" S="+rS+" (M=heap T=thr_new T2=start G=gadgets S=STUB)";W(resum);
// bucle resumen ~2min x40, <60ch banner
const nres=("[bisect4] M="+rM+" T="+rT+" T2="+rT2+" G="+rG+" S="+rS).slice(0,59);
for(let i=0;i<40;i++){try{send_notification(nres);}catch(e){}for(let j=0;j<3000;j++)syscall(SYSCALL.sched_yield);}
// reenvio TCP del resumen x3:
for(let a=0;a<3;a++){sock=-1n;try{sock=CN();if(sock>=0n){W(resum);syscall(SYSCALL.close,sock);sock=-1n;}}catch(e){if(sock>=0n){try{syscall(SYSCALL.close,sock);}catch(e2){}sock=-1n;}}}
}catch(e){W("[bisect4] EX fatal: "+e);N("[bisect4] abort EX");}
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
