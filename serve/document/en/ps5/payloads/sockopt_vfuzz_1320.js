// sockopt_vfuzz_1320: FUZZ de VALORES sobre opciones VIVAS del sweep 1er pase (RESEARCH/sockopt-map-2026-08-28.md). Base sockopt_sweep_1320.js (canal W() TCP crudo 192.168.1.67:8081 0x911F/0x4301A8C0 + helpers).
// Premisa (mapa §final): aceptan set=1 pero RECHAZAN 0xFFFFFFFF -> hay validacion; limites mal validados = candidatos a bug (p.ej. IPV6_MULTICAST_IF ifindex OOB). Fuzz = escalera de valores + read-back (getsockopt value-result) tras CADA set ok. Anomalias (unicas W de datos): "MISMATCH" get lee distinto de lo escrito (o get err tras set ok) | "ACEPTADO raro" set ok fuera del rango esperado. KNOWN normal: validos con read-back identico -> silencio.
// ABI: socket=0x61 setsockopt=0x69 getsockopt=0x76 close=6 yield=331. AF_INET=2(sock.h:171) AF_INET6=28(sock.h:201) SOCK_STREAM=1 SOCK_DGRAM=2. SOL_SOCKET=0xffff(sys/socket.h:161) SO_LINGER=0x80(:110) struct linger{l_onoff,l_linger}(:146-149) SO_SNDBUF=0x1001(:125) SO_RCVBUF=0x1002(:126). IPPROTO_IPV6=41(in.h:177). in6.h: UNICAST_HOPS=4(:398) MCAST_IF=9(:399) MCAST_HOPS=10(:400) PORTRANGE=14(:404) DEFAULT=0/HIGH=1/LOW=2(:547-549) RECVPKTINFO=36(:440) RECVHOPLIMIT=37(:441) RECVRTHDR=38(:442).
// Sockets: UDP_INET6 (IPV6_*) + TCP_INET (SO_*), ambos al inicio. Buffers malloc(8+) propios. Sin mmap/thr_new/rfork. ~250 syscalls acotadas. <9KB.
(()=>{
const I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const Y=331n,S_CL=6n,S_SS=0x69n,S_GS=0x76n;
const EL={1:"EPERM",2:"ENOENT",6:"ENXIO",9:"EBADF",13:"EACCES",22:"EINVAL",38:"ENOTSOCK",42:"ENOPROTOOPT",43:"EPROTONOSUPPORT",45:"EOPNOTSUPP",55:"ENOBUFS",56:"EISCONN",60:"ETIMEDOUT"};
const ELM=(e)=>EL[e]!==undefined?EL[e]:"?";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[svf] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[svf] PASO "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const U=(v)=>BigInt.asUintN(32,BigInt(v)); // JS number (admite -1) -> u32 BigInt
// canal W
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const GB=malloc(64),VB=malloc(16),LB=malloc(8); // GB buf getsockopt; VB valor setsockopt (<=8B); LB optlen value-result
const HEX=(b,n)=>{let x="";for(let i=0;i<n;i++){const v=Number(read8(b+BigInt(i)))&255;x+=(v<16?"0":"")+v.toString(16);}return x};
// stats + progreso c/10 sets
let sets=0,acc=0,rej=0,lastP=0;const AN={},ST={};
const anom=()=>{let t=0;for(const k in AN)t+=AN[k];return t};
const P10=()=>{if(sets-lastP>=10){lastP=sets;W("[svf] progreso sets="+sets+" ok="+acc+" rej="+rej+" anom="+anom());}};
const STK=(k)=>{if(!ST[k])ST[k]={s:0,a:0};return ST[k]};
const A1=(k,msg)=>{AN[k]=(AN[k]||0)+1;STK(k).a++;W("[svf] "+msg)};
const GS=(fd,lvl,opt,len)=>{for(let i=0;i<len;i++)write8(GB+BigInt(i),0);write32(LB,BigInt(len));return I(syscall(S_GS,fd,lvl,opt,GB,LB))};
// FI: fuzz de opcion int. set(valor,len) -> si ok -> getsockopt read-back -> MISMATCH si leido!=escrito; ACEPTADO raro si okP(val)=false.
const FI=(fd,lvl,opt,name,val,lbl,okP,len)=>{len=len||4;const st=STK(name);
write32(VB,U(val));
const s=I(syscall(S_SS,fd,lvl,opt,VB,BigInt(len)));sets++;st.s++;
if(s<0n){rej++;P10();return;}
acc++;
const g=GS(fd,lvl,opt,4);
if(g<0n){A1(name,"MISMATCH "+name+": set("+lbl+")=ok pero get err="+EN()+"("+ELM(EN())+")");P10();return;}
const rv=Number(read32(GB))>>>0,wv=Number(U(val))>>>0;
if(rv!==wv)A1(name,"MISMATCH "+name+": escrito="+lbl+" leido=0x"+rv.toString(16)+" ("+HEX(GB,4)+")");
else if(okP&&!okP(val))A1(name,"ACEPTADO raro "+name+": set("+lbl+")=ok (rango esperado lo excluye)");
P10();};
// P1: sockets de trabajo
E(1,"socket x2 (UDP_INET6 para IPV6_*, TCP_INET para SO_*)");
let fd6=-1n,fd4=-1n;
try{fd6=I(syscall(SYSCALL.socket,28n,2n,0n))}catch(e){fd6=-1n}
try{fd4=I(syscall(SYSCALL.socket,2n,1n,0n))}catch(e){fd4=-1n}
if(fd6<0n)fd6=-1n;if(fd4<0n)fd4=-1n;
W("[svf] UDP_INET6 fd="+fd6);W("[svf] TCP_INET fd="+fd4);
if(fd6<0n)W("[svf] UDP_INET6 MUERTO -> bloques 1-5 (IPV6) omitidos");
if(fd4<0n)W("[svf] TCP_INET MUERTO -> bloques 6-9 (SO_*) omitidos");
if(fd6<0n&&fd4<0n){N("[svf] FAIL: 0 sockets, aborto");W("[svf] PAYLOAD DONE");return;}
const V6=41n,SOL=0xffffn;
// B1: IPV6_MULTICAST_IF ifindex 0..64 (set+get c/u) -> W solo si set ok con ifx>8 (¿indices OOB?) o mismatch
W("[svf] BLOQUE 1/9 IPV6_MULTICAST_IF(9) escalera ifx=0..64 (65 sets) UDP_INET6");
if(fd6>=0n)for(let x=0;x<=64;x++)FI(fd6,V6,9n,"IPV6_MULTICAST_IF",x,"ifx="+x,(v)=>v<=8);
// B2: IPV6_PORTRANGE — validos esperados 0..2 (in6.h:547-549); ¿acepta mas?
W("[svf] BLOQUE 2/9 IPV6_PORTRANGE(14) valores 0,1,2,3,4,5,8,16,0xFF,0x7FFFFFFF,0x80000000");
const B2=[[0,"0"],[1,"1"],[2,"2"],[3,"3"],[4,"4"],[5,"5"],[8,"8"],[16,"16"],[0xFF,"0xFF"],[0x7FFFFFFF,"0x7FFFFFFF"],[0x80000000,"0x80000000"]];
if(fd6>=0n)for(let i=0;i<B2.length;i++)FI(fd6,V6,14n,"IPV6_PORTRANGE",B2[i][0],B2[i][1],(v)=>v>=0&&v<=2);
// B3: IPV6_UNICAST_HOPS — esperado 0..255 y -1=default
W("[svf] BLOQUE 3/9 IPV6_UNICAST_HOPS(4) valores -1,0,1,64,255,256,0x7FFFFFFF,0x80000000");
const B3=[[-1,"-1"],[0,"0"],[1,"1"],[64,"64"],[255,"255"],[256,"256"],[0x7FFFFFFF,"0x7FFFFFFF"],[0x80000000,"0x80000000"]];
if(fd6>=0n)for(let i=0;i<B3.length;i++)FI(fd6,V6,4n,"IPV6_UNICAST_HOPS",B3[i][0],B3[i][1],(v)=>v===-1||(v>=0&&v<=255));
// B4: IPV6_MULTICAST_HOPS
W("[svf] BLOQUE 4/9 IPV6_MULTICAST_HOPS(10) valores 1,255,256,0x7FFFFFFF");
const B4=[[1,"1"],[255,"255"],[256,"256"],[0x7FFFFFFF,"0x7FFFFFFF"]];
if(fd6>=0n)for(let i=0;i<B4.length;i++)FI(fd6,V6,10n,"IPV6_MULTICAST_HOPS",B4[i][0],B4[i][1],(v)=>v>=1&&v<=255);
// B5: booleanos RECVPKTINFO/RECVHOPLIMIT/RECVRTHDR — validos 0/1; ¿acepta >1?
W("[svf] BLOQUE 5/9 IPV6_RECVPKTINFO(36)/RECVHOPLIMIT(37)/RECVRTHDR(38) valores 0,1,2,255 (booleanos)");
const B5=[[36,"IPV6_RECVPKTINFO"],[37,"IPV6_RECVHOPLIMIT"],[38,"IPV6_RECVRTHDR"]];
const B5V=[[0,"0"],[1,"1"],[2,"2"],[255,"255"]];
if(fd6>=0n)for(let i=0;i<B5.length;i++)for(let j=0;j<B5V.length;j++)FI(fd6,V6,BigInt(B5[i][0]),B5[i][1],B5V[j][0],B5V[j][1],(v)=>v<=1);
// B6/B7: SO_SNDBUF/SO_RCVBUF ladder con read-back (¿el kernel acota? ¿acepta 0x80000000?). Plausible: 1..0x04000000.
const BF=[[1,"1"],[0x10,"0x10"],[0x400,"0x400"],[0x4000,"0x4000"],[0x10000,"0x10000"],[0x100000,"0x100000"],[0x7FFFFFFF,"0x7FFFFFFF"],[0x80000000,"0x80000000"],[0xFFFFFFFF,"0xFFFFFFFF"]];
const BFp=(v)=>v>=1&&v<=0x04000000;
W("[svf] BLOQUE 6/9 SO_SNDBUF(0x1001) ladder 1..0xFFFFFFFF con read-back TCP_INET");
if(fd4>=0n)for(let i=0;i<BF.length;i++)FI(fd4,SOL,0x1001n,"SO_SNDBUF",BF[i][0],BF[i][1],BFp);
W("[svf] BLOQUE 7/9 SO_RCVBUF(0x1002) ladder 1..0xFFFFFFFF con read-back TCP_INET");
if(fd4>=0n)for(let i=0;i<BF.length;i++)FI(fd4,SOL,0x1002n,"SO_RCVBUF",BF[i][0],BF[i][1],BFp);
// B8: SO_LINGER struct{onoff,linger} 8B — set len8 (sweep: set int4=EINVAL) + get read-back 8B
W("[svf] BLOQUE 8/9 SO_LINGER(0x80) struct{onoff,linger}: {1,0} {1,-1} {1,0x7FFFFFFF} {1,0x80000000} {0,-1} TCP_INET");
if(fd4>=0n){const B8=[[1,0,"{1,0}"],[1,-1,"{1,-1}"],[1,0x7FFFFFFF,"{1,0x7FFFFFFF}"],[1,0x80000000,"{1,0x80000000}"],[0,-1,"{0,-1}"]];
for(let i=0;i<B8.length;i++){const st=STK("SO_LINGER"),T=B8[i];
write32(VB,U(T[0]));write32(VB+4n,U(T[1]));const exp=HEX(VB,8); // struct 8B a VB + hex de referencia
const s=I(syscall(S_SS,fd4,SOL,0x80n,VB,8n));sets++;st.s++;
if(s<0n){rej++;P10();continue;}
acc++;
const g=GS(fd4,SOL,0x80n,8);
if(g<0n)A1("SO_LINGER","MISMATCH SO_LINGER set"+T[2]+"=ok pero get err="+EN()+"("+ELM(EN())+")");
else if(HEX(GB,8)!==exp)A1("SO_LINGER","MISMATCH SO_LINGER: escrito="+T[2]+" ("+exp+") leido="+HEX(GB,8));
else if(!(T[1]>=0&&T[1]<=0x7FFFFFFF))A1("SO_LINGER","ACEPTADO raro SO_LINGER "+T[2]+" (linger fuera de 0..0x7FFFFFFF)");
P10();}}
// B9: buffers a 0 — ¿acepta buffer cero? cualquier aceptacion = raro
W("[svf] BLOQUE 9/9 SO_SNDBUF/SO_RCVBUF set=0 (buffer cero) TCP_INET");
if(fd4>=0n){FI(fd4,SOL,0x1001n,"SO_SNDBUF",0,"0",()=>false);FI(fd4,SOL,0x1002n,"SO_RCVBUF",0,"0",()=>false);}
// resumen + veredicto
E(2,"resumen anomalias por opcion");
R(2,"sets="+sets+" aceptados="+acc+" rechazados="+rej+" anomalias="+anom());
for(const k in ST)W("[svf] RESUMEN "+k+": sets="+ST[k].s+" anomalias="+ST[k].a);
const fv="sockopt vfuzz: "+sets+" sets, anomalias="+anom()+(anom()===0?" (todas normal: validacion OK)":" (HAY ANOMALIAS: revisar)");
N("[svf] "+fv);
for(let i=0;i<10;i++){N("[svf] "+fv);for(let j=0;j<3000;j++)syscall(Y);}
W("[svf] PAYLOAD DONE");
if(fd6>=0n)syscall(S_CL,fd6);
if(fd4>=0n)syscall(S_CL,fd4);
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
