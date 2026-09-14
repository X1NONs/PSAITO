// 2026-08-28 sysctl_walk_1320: mapa del árbol sysctl visible desde el sandbox 13.20 (objetivo roadmap §2.1, RESEARCH/roadmap-kernel-2026-08.md) — lista nodos legibles prof.1 y prof.2 con su OID y tamaño; sin escrituras; bucles acotados <6000 syscalls.
// ABI: SYSCALL.sysctl=0xCA (global.js:269; SYS___sysctl=202 en RESEARCH/kstuff-13/freebsd-headers/sys/syscall.h:192). Firma __sysctl(name*,namelen,old*,oldlen*,new*,newlen) 6 args; MIB=int32 por componente (write32, exactamente como misc.js:343-353 get_title_id); retorno -1+errno (get_error_string); EAGAIN(17)=existe pero value>buffer, ENOENT(2)=no existe.
// CTL_*: VERIFICADO — el header local RESEARCH/kstuff-13/freebsd-headers/sys/sysctl.h NO define el subsistema 0: L421 CTL_UNSPEC=0 "unused", L431 CTL_MAXID=10, L449/450 KERN_OSTYPE=1/KERN_OSRELEASE=2, L51 CTL_MAXNAME=24; NEXTNAME/NAME2OID/NEXT ABSENTES en todo el árbol (grep vacío). Upstream freebsd-src stable/12 sys/sys/sysctl.h L854 CTL_SYSCTL=0 y L868-875 DEBUG=0 NAME=1 NEXT=2 NAME2OID=3 OIDFMT=4 OIDDESCR=5 OIDLABEL=6 NEXTNOSKIP=7 (idéntico en stable/13 L923/L937-944; no existe NEXTNAME en 12/13). Como el kernel Orbis puede conservar la interfaz aunque el header la oculte, el PASO 4 barre [0,c,1] para c=0..7 sin asumir numeración.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const SCHED_YIELD=331n,HEX="0123456789ABCDEF";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const MIB=malloc(64),OLD=malloc(64),OL=malloc(8);let calls=0;
// P: probe de lectura pura -> {r:ret (0 ok / -1 fail), e:errno (0 si ok), l:*oldlen tras la llamada}
const P=(a)=>{const n=a.length;for(let i=0;i<n;i++)write32(MIB+B(4*i),B(a[i]));write64(OL,64n);calls++;const r=I(syscall(SYSCALL.sysctl,MIB,B(n),OLD,OL,0n,0n));const e=r===0?0:EN();return{r:r,e:e,l:Number(BigInt.asUintN(64,read64(OL)))}};
const Q=(p)=>{const v=BigInt.asUintN(64,read64(p));let s="";for(let i=0;i<16;i++)s+=HEX[Number((v>>BigInt(60-4*i))&15n)];return"0x"+s};
const STR=(p,l)=>{let s="";for(let i=0;i<l&&i<64;i++){const c=Number(read8(p+B(i)));if(!c)break;s+=(c>=32&&c<127)?String.fromCharCode(c):"."}return s};
const done=(v)=>{W("[sysctl] COMPLETO: "+v+" (syscalls="+calls+"/"+6000+")");N("[sysctl] "+v.slice(0,90));for(let i=0;i<10;i++){N("[sysctl] "+v.slice(0,90));for(let j=0;j<2000;j++){syscall(SCHED_YIELD)}}W("[sysctl] PAYLOAD DONE");if(sock>=0n)syscall(SYSCALL.close,sock)};
W("[sysctl] walk begin pid="+I(syscall(SYSCALL.getpid))+" - mapa sysctl sandbox 13.20");
// --- PASO 1 SANITY: kern.ostype [1,1] y kern.osrelease [1,2] (sysctl.h local L449/L450)
const p1=P([1,1]);
if(p1.r!==0){done("ABORT sysctl base no responde: [1,1] errno="+p1.e);return;}
W("[sysctl] P1 [1,1] kern.ostype = "+STR(OLD,p1.l)+" (len="+p1.l+")");
const p2=P([1,2]);
W("[sysctl] P1 [1,2] kern.osrelease = "+(p2.r===0?STR(OLD,p2.l)+" (len="+p2.l+")":"errno="+p2.e+" (continua el barrido igual)"));
// --- PASO 2: barrido profundidad 1 (a=0..127). legible=ret0; existente=errno!=ENOENT (nodo/leaf protegido)
const d1ok=[],d1ex=[];
W("[sysctl] P2 d1 sweep a=0..127");
for(let a=0;a<128;a++){const p=P([a]);
if(p.r===0){d1ok.push(a);d1ex.push(a);W("[sysctl] D1 "+a+" legible len="+p.l+" q0="+(p.l>=8?Q(OLD):"-"))}
else if(p.e!==2){d1ex.push(a);W("[sysctl] D1 "+a+" existe errno="+p.e+(p.l>64?" reallen="+p.l:""))}}
W("[sysctl] P2 fin: d1 legibles="+d1ok.length+" existentes="+d1ex.length);
// --- PASO 3: barrido profundidad 2 (cap 16 candidatos existentes x b=0..255; W solo LEN + qword0 hex - el valor puede ser binario)
let d2ok=0;const cand=d1ex.slice(0,16);
W("[sysctl] P3 d2 sweep cands="+cand.join(",")+" b=0..255");
for(const a of cand){let ok=0,ex=0,big=0;for(let b=0;b<256;b++){const p=P([a,b]);
if(p.r===0){ok++;d2ok++;W("[sysctl] D2 "+a+"."+b+" len="+p.l+" q0="+(p.l>=8?Q(OLD):"-"))}
else if(p.e!==2){ex++;if(p.e===17&&big<3){big++;W("[sysctl] D2 "+a+"."+b+" existe grande reallen="+p.l)}}}
W("[sysctl] P3 "+a+".x: ok="+ok+" existente-no-legible="+ex)}
// --- PASO 4: subsistema 0 "magic" (interfaz debug sysctl; en header local NO existe, upstream 12/13: NAME=1 NEXT=2 NAME2OID=3 OIDFMT=4 OIDDESCR=5 OIDLABEL=6 NEXTNOSKIP=7). Prueba única [0,c,1] c=0..7 (nombre objetivo = kern).
W("[sysctl] P4 subsistema 0: sweep [0,c,1] c=0..7");
let mg=-1;
for(let c=0;c<8;c++){const p=P([0,c,1]);
if(p.r===0){if(mg<0)mg=c;W("[sysctl] MAGIC 0."+c+".1 len="+p.l+" q0="+(p.l>=8?Q(OLD):"-")+" str="+STR(OLD,p.l))}
else W("[sysctl] MAGIC 0."+c+".1 errno="+p.e+(p.l>64?" reallen="+p.l:""))}
// si la interfaz vive, etiquetar 20 OID top-level más con el subid que respondió (20 syscalls)
if(mg>=0){W("[sysctl] P4b etiquetas top-level con subid "+mg);for(let a=2;a<=21;a++){const p=P([0,mg,a]);W("[sysctl] TAG "+mg+"."+a+" "+(p.r===0?"len="+p.l+" "+STR(OLD,p.l):"errno="+p.e))}}
// --- RESUMEN + veredicto
const v="d1ok="+d1ok.length+" d1ex="+d1ex.length+" d2ok="+d2ok+" sub0="+(mg>=0?("VIVO c="+mg):"muerto");
done(v);
})();
