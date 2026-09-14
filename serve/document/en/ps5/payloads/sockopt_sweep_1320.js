// sockopt_sweep_1320: barrido setsockopt/getsockopt desde sandbox (roadmap 2.3). Canal W() TCP crudo 192.168.1.67:8081 (0x911F/0x4301A8C0). Base fs_probe_1320 (E/R/N, EN()).
// ABI: socket=0x61 setsockopt=105/0x69 (syscall.h:112) getsockopt=118/0x76 (syscall.h:125) close=6. AF_INET=2 (sock.h:171) AF_INET6=28 (sock.h:201) SOCK_STREAM=1 SOCK_DGRAM=2.
// CITAS RESEARCH/kstuff-13/freebsd-headers — sys/socket.h: SOL_SOCKET=0xffff(:161),SO_DEBUG=1(:101),SO_ACCEPTCONN=2(:102),SO_REUSEADDR=4(:103),SO_KEEPALIVE=8(:104),SO_DONTROUTE=0x10(:105),SO_BROADCAST=0x20(:106),SO_USELOOPBACK=0x40(:108),SO_LINGER=0x80(:110),SO_OOBINLINE=0x100(:111),SO_REUSEPORT=0x200(:113),SO_SNDBUF=0x1001(:125),SO_RCVBUF=0x1002(:126),SO_SNDLOWAT=0x1003(:127),SO_RCVLOWAT=0x1004(:128),SO_SNDTIMEO=0x1005(:129),SO_RCVTIMEO=0x1006(:130),SO_ERROR=0x1007(:131),SO_TYPE=0x1008(:132).
// netinet/in.h: IPPROTO_IP=0(:41),ICMP=1(:42),UDP=17(:44),RAW=255(:126),ICMPV6=58(:194),IPV6=41(:177). IP_TOS=3(:403),TTL=4(:404),RECVOPTS=5(:405),RECVRETOPTS=6(:406),RECVDSTADDR=7(:407),MULTICAST_IF=9(:410),MCAST_TTL=10(:412),MCAST_LOOP=11(:413),ADD_MSB=12(:414),DROP_MSB=13(:415),PORTRANGE=19(:421),RECVIF=20(:422),BINDANY=24(:428).
//  FIX enunciado (valores Linux): IP_TOS=3 NO 1, TTL=4 NO 2, RECVOPTS=5 NO 6, RECVRETOPTS=6 NO 7; IP_RECVTTL NO existe (24=BINDANY)->usado RECVIF=20. TCP_KEEPINIT/KEEPALIVE NO existen en tcp.h de este arbol->omitidos. IPPROTO_UDPLITE=136 NO definido aqui->valor IANA, sondeado.
// netinet/tcp.h: NODELAY=0x01(:153),MAXSEG=0x02(:155),NOPUSH=0x04(:156),NOOPT=0x08(:157),MD5SIG=0x10(:158),INFO=0x20(:159),CONGESTION=0x40(:160). netinet6/in6.h: UNICAST_HOPS=4(:398),RECVOPTS=5(:392),RECVRETOPTS=6(:393),MCAST_IF=9(:399),MCAST_HOPS=10(:400),MCAST_LOOP=11(:401),JOIN=12(:402),LEAVE=13(:403),PORTRANGE=14(:404),2292PKTINFO=19(:408),2292HOPLIMIT=20(:409),CHECKSUM=26(:417),V6ONLY=27(:418),RECVPKTINFO=36(:440),RECVHOPLIMIT=37(:441),RECVRTHDR=38(:442),HOPLIMIT=47(:461),NEXTHOP=48(:462),RTHDR=51(:465),DONTFRAG=62(:476),MSFILTER=74(:488).
// sys/errno.h: ENOENT=2(:50) ENOPROTOOPT=42(:103) EOPNOTSUPP=45(:106) ENOTSUP=45(:107). KNOWN "no existe"={42,45,2}; cualquier otro ret/errno = VIVA.
// Diseño: 3 sockets con W de fd. Por (sock,nivel,opt): getsockopt(buf128,len*)+setsockopt(=1)+setsockopt(=0xFFFFFFFF). Tablas SOL=18,IP=13,TCP=7,IPV6=21 -> 38+31+39=108 combos x3=324 syscalls. W SOLO vivas + progreso/50; muertas a contadores. W antes de bloque de nivel. Sin mmap/thr_new/rfork/read64. Acotado.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const Y=331n,S_CL=6n,S_SS=0x69n,S_GS=0x76n;
const EL={1:"EPERM",2:"ENOENT",6:"ENXIO",9:"EBADF",13:"EACCES",22:"EINVAL",38:"ENOTSOCK",42:"ENOPROTOOPT",43:"EPROTONOSUPPORT",44:"ESOCKTNOSUPPORT",45:"EOPNOTSUPP",46:"EPFNOSUPPORT",47:"EAFNOSUPPORT",48:"EADDRINUSE",55:"ENOBUFS",56:"EISCONN",60:"ETIMEDOUT"};
const ELM=(e)=>EL[e]!==undefined?EL[e]:"?";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[ssw] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[ssw] PASO "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const DEAD={42:1,45:1,2:1};
const J=(e)=>" errno="+e+"("+ELM(e)+")";
const V=(r,e)=>(r>=0n?"ok":e+"("+ELM(e)+")");
// canal W
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const GB=malloc(128),VB=malloc(8),LB=malloc(4); // GB buf getsockopt; VB valor setsockopt; LB optlen value-result (getsockopt necesita PUNTERO a socklen_t)
const HEX=(b,n)=>{let x="";for(let i=0;i<n;i++){const v=Number(read8(b+BigInt(i)))&255;x+=(v<16?"0":"")+v.toString(16);}return x};
// tablas [nivel, optname, nombre]
const L_SS=0xffffn,L_IP=0n,L_TCP=6n,L_V6=41n;
const T_SS=[[L_SS,0x1n,"SO_DEBUG"],[L_SS,0x2n,"SO_ACCEPTCONN"],[L_SS,0x4n,"SO_REUSEADDR"],[L_SS,0x8n,"SO_KEEPALIVE"],[L_SS,0x10n,"SO_DONTROUTE"],[L_SS,0x20n,"SO_BROADCAST"],[L_SS,0x40n,"SO_USELOOPBACK"],[L_SS,0x80n,"SO_LINGER"],[L_SS,0x100n,"SO_OOBINLINE"],[L_SS,0x200n,"SO_REUSEPORT"],[L_SS,0x1001n,"SO_SNDBUF"],[L_SS,0x1002n,"SO_RCVBUF"],[L_SS,0x1003n,"SO_SNDLOWAT"],[L_SS,0x1004n,"SO_RCVLOWAT"],[L_SS,0x1005n,"SO_SNDTIMEO"],[L_SS,0x1006n,"SO_RCVTIMEO"],[L_SS,0x1007n,"SO_ERROR"],[L_SS,0x1008n,"SO_TYPE"]];
const T_IP=[[L_IP,3n,"IP_TOS"],[L_IP,4n,"IP_TTL"],[L_IP,5n,"IP_RECVOPTS"],[L_IP,6n,"IP_RECVRETOPTS"],[L_IP,7n,"IP_RECVDSTADDR"],[L_IP,9n,"IP_MULTICAST_IF"],[L_IP,10n,"IP_MULTICAST_TTL"],[L_IP,11n,"IP_MULTICAST_LOOP"],[L_IP,12n,"IP_ADD_MEMBERSHIP"],[L_IP,13n,"IP_DROP_MEMBERSHIP"],[L_IP,19n,"IP_PORTRANGE"],[L_IP,20n,"IP_RECVIF"],[L_IP,24n,"IP_BINDANY"]];
const T_TCP=[[L_TCP,1n,"TCP_NODELAY"],[L_TCP,2n,"TCP_MAXSEG"],[L_TCP,4n,"TCP_NOPUSH"],[L_TCP,8n,"TCP_NOOPT"],[L_TCP,0x10n,"TCP_MD5SIG"],[L_TCP,0x20n,"TCP_INFO"],[L_TCP,0x40n,"TCP_CONGESTION"]];
const T_V6=[[L_V6,4n,"IPV6_UNICAST_HOPS"],[L_V6,5n,"IPV6_RECVOPTS"],[L_V6,6n,"IPV6_RECVRETOPTS"],[L_V6,9n,"IPV6_MULTICAST_IF"],[L_V6,10n,"IPV6_MULTICAST_HOPS"],[L_V6,11n,"IPV6_MULTICAST_LOOP"],[L_V6,12n,"IPV6_JOIN_GROUP"],[L_V6,13n,"IPV6_LEAVE_GROUP"],[L_V6,14n,"IPV6_PORTRANGE"],[L_V6,19n,"IPV6_2292PKTINFO"],[L_V6,20n,"IPV6_2292HOPLIMIT"],[L_V6,26n,"IPV6_CHECKSUM"],[L_V6,27n,"IPV6_V6ONLY"],[L_V6,36n,"IPV6_RECVPKTINFO"],[L_V6,37n,"IPV6_RECVHOPLIMIT"],[L_V6,38n,"IPV6_RECVRTHDR"],[L_V6,47n,"IPV6_HOPLIMIT"],[L_V6,48n,"IPV6_NEXTHOP"],[L_V6,51n,"IPV6_RTHDR"],[L_V6,62n,"IPV6_DONTFRAG"],[L_V6,74n,"IPV6_MSFILTER"]];
// P1: crear 3 sockets
E(1,"socket x3 (TCP_INET, UDP_INET, UDP_INET6)");
const SK=[["TCP_INET",2n,1n,0n],["UDP_INET",2n,2n,0n],["UDP_INET6",28n,2n,0n]];
const socks=[];
for(let i=0;i<3;i++){try{const fd=I(syscall(SYSCALL.socket,SK[i][1],SK[i][2],SK[i][3]));
if(fd>=0n){socks.push([SK[i][0],BigInt(fd)]);W("[ssw] "+SK[i][0]+" fd="+fd);}
else{const e=EN();W("[ssw] socket "+SK[i][0]+J(e)+" -> EXCLUIDO");}}catch(ex){W("[ssw] socket "+SK[i][0]+" EXC -> EXCLUIDO");}}
R(1,"sockets vivos: "+socks.length+"/3 ("+socks.map(s=>s[0]).join(" ")+")");
if(socks.length===0){N("[ssw] FAIL: 0 sockets, aborto");W("[ssw] PAYLOAD DONE");return;}
// P1b: sondeo de protocolos (verificacion IPPROTO_* via socket(); se cierran al instante)
E(2,"sondeo proto (socket AF_INET,SOCK_DGRAM,proto)");
const PROTO=[[0n,"IPPROTO_IP"],[1n,"IPPROTO_ICMP"],[17n,"IPPROTO_UDP"],[41n,"IPPROTO_IPV6"],[136n,"IPPROTO_UDPLITE*"],[255n,"IPPROTO_RAW"]];
let pOk=0;const pOKn=[],pBad=[];
for(let i=0;i<PROTO.length;i++){try{const fd=I(syscall(SYSCALL.socket,2n,2n,PROTO[i][0]));
if(fd>=0n){pOk++;pOKn.push(PROTO[i][1]);syscall(S_CL,fd);}
else pBad.push(PROTO[i][1]+":"+EN());}catch(ex){pBad.push(PROTO[i][1]+":EXC");}}
R(2,"protos creables "+pOk+"/6: "+pOKn.join(" ")+" | no: "+pBad.join(" ")+" (*UDPLITE no definido en header, valor IANA)");
// P2: barrido
const alive=[],cnt={};let dead=0,combos=0,tests=0,lastProg=0;
const LNM={0xffff:"SOL",0:"IP",6:"TCP",41:"IPV6"};
for(let si=0;si<socks.length;si++){
const sname=socks[si][0],fd=socks[si][1],v4=sname!=="UDP_INET6";
const tables=[[T_SS,"SOL_SOCKET"],[v4?T_IP:T_V6,v4?"IP":"IPV6"]];
if(sname==="TCP_INET")tables.push([T_TCP,"TCP"]);
for(let ti=0;ti<tables.length;ti++){
const tb=tables[ti][0],tl=tables[ti][1];
W("[ssw] BLOQUE "+sname+"/"+tl+" ("+tb.length+" opts)");
for(let oi=0;oi<tb.length;oi++){
const lv=tb[oi][0],on=tb[oi][1],nm=tb[oi][2];combos++;
for(let i=0;i<128;i++)write8(GB+BigInt(i),0);
write32(LB,128n);
const g=I(syscall(S_GS,fd,lv,on,GB,LB));const eg=EN();const glen=Number(read32(LB))&0x7fffffff;
write32(VB,1n);const s1=I(syscall(S_SS,fd,lv,on,VB,4n));const e1=EN();
write32(VB,0xFFFFFFFFn);const s2=I(syscall(S_SS,fd,lv,on,VB,4n));const e2=EN();
tests+=3;
const okG=g>=0n||!DEAD[eg],ok1=s1>=0n||!DEAD[e1],ok2=s2>=0n||!DEAD[e2];
const key=sname+"."+LNM[String(lv)]+"."+nm;
if(okG||ok1||ok2){alive.push(key);
const lvl=String(lv);cnt[lvl]=cnt[lvl]||{n:0,l:[]};cnt[lvl].n++;cnt[lvl].l.push(sname+":"+nm);
W("[ssw] VIVA "+key+" | get="+V(g,eg)+" len="+glen+" val="+HEX(GB,8)+" | set1="+V(s1,e1)+" | setFF="+V(s2,e2));}
else dead++;
if(tests-lastProg>=50){lastProg=tests;W("[ssw] progreso tests="+tests+" combos="+combos+" vivas="+alive.length+" muertas="+dead);}
}}}
R(3,"barrido: "+combos+" combos, vivas="+alive.length+" muertas="+dead);
// P3: mapa por nivel + veredicto
E(4,"mapa por nivel");
for(const k in cnt)W("[ssw] MAPA "+LNM[k]+" (lvl "+k+"): "+cnt[k].n+" vivas -> "+cnt[k].l.join(" "));
W("[ssw] MAPA muertas: "+dead+" de "+combos+" combos");
const fv="socket opts: "+alive.length+" vivas de "+combos+" ("+dead+" muertas)";
N("[ssw] "+fv);
for(let i=0;i<10;i++){N("[ssw] "+fv);for(let j=0;j<3000;j++)syscall(Y);}
W("[ssw] PAYLOAD DONE");
for(let i=0;i<socks.length;i++)syscall(S_CL,socks[i][1]);
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
