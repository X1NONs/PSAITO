// 2026-08-28 sysctl_diag_1320: diagnostico errno 32 en sysctl, sandbox 13.20 (sysctl_walk aborto en [1,1] errno=32). H-WL: Orbis solo whitelista MIBs concretos (p.ej. [1,14,35,pid] de misc.js get_title_id L340-357), el resto da 32 (codigo Sony; strerror lo revela). H-RAW: raw syscall(0xCA) mal marshalado. SIN ABORTS. Base sysctl_walk_1320. ABI: sysctl=0xCA (global.js:269), __sysctl(name,namelen,old,oldlen,new,newlen), MIB=int32, ret -1+errno via get_error_string="<errno> <strerror>" (misc.js:58).
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const SY=331n,HEX="0123456789ABCDEF";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const N=(s)=>{try{send_notification(s)}catch(e){}};
const GS=()=>{try{return String(get_error_string())}catch(e){return"?"}}; // texto crudo "<errno> <strerror>", captura inmediata (errno es global)
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const MIB=malloc(64),OLD=malloc(256),OL=malloc(8);let calls=0;
for(let i=0;i<256;i++)write8(OLD+B(i),0); // OLD a cero: el hex de un fallo no se confunde con basura
// P: probe de lectura pura, cap=oldlen de entrada (default 64) -> {r:ret,e:errno,l:*oldlen,g:strerror}
const P=(a,cap)=>{const n=a.length;for(let i=0;i<n;i++)write32(MIB+B(4*i),B(a[i]));write64(OL,cap===undefined?64n:cap);calls++;const r=I(syscall(SYSCALL.sysctl,MIB,B(n),OLD,OL,0n,0n));const l=Number(BigInt.asUintN(64,read64(OL)));if(r===0)return{r:0,e:0,l:l,g:""};const g=GS();const m=/^(\d+)/.exec(g);return{r:r,e:m?parseInt(m[1],10):-1,l:l,g:g}};
const STR=(p,l)=>{let s="";for(let i=0;i<l&&i<64;i++){const c=Number(read8(p+B(i)));if(!c)break;s+=(c>=32&&c<127)?String.fromCharCode(c):"."}return s};
const DUMP=(p,n)=>{let s="";for(let i=0;i<n;i+=8){const q=BigInt.asUintN(64,read64(p+B(i)));for(let j=0;j<16;j++)s+=HEX[Number((q>>BigInt(60-4*j))&15n)];s+=" "}return s};
// registro global: errno unico -> texto strerror; all32=true si TODO lo observado es errno 32
const ET={};let all32=true;
const REC=(p)=>{if(p.r===0){all32=false;return}if(ET[p.e]===undefined)ET[p.e]=p.g;if(p.e!==32)all32=false};
const done=(v)=>{W("[sysctl] COMPLETO: "+v+" (syscalls="+calls+")");W("[sysctl] PAYLOAD DONE");N("[sysctl] "+v.slice(0,90));for(let i=0;i<10;i++){N("[sysctl] "+v.slice(0,90));for(let j=0;j<2000;j++){syscall(SY)}}if(sock>=0n)syscall(SYSCALL.close,sock)};
// --- P1: getpid + W
const PID=I(syscall(SYSCALL.getpid));
W("[sysctl] P1 pid="+PID+" sock="+I(sock)+" - diagnostico errno 32 (sin aborts)");
// --- P2: test misc.js EXACTO (get_title_id L340-357): mib=[1,14,35,pid], namelen=4, old=malloc(0x100). misc.js usa oldlen=0x58; aqui 0x100 (mas permisiva). MIB verificado del runtime: si da 32, H-RAW cae y H-WL cobra fuerza.
W("[sysctl] P2 test1: MIB=[1,14,35,"+PID+"] namelen=4 oldlen=0x100 (replica exacta misc.js get_title_id)");
const p2=P([1,14,35,PID],256n);REC(p2);
W("[sysctl] P2 ret="+p2.r+" errno="+p2.e+" oldlen*="+p2.l+(p2.g?" ["+p2.g+"]":""));
if(p2.r===0){W("[sysctl] P2 VALOR str="+STR(OLD,p2.l)+" title@+0x10="+STR(OLD+B(16),64));W("[sysctl] P2 hex64="+DUMP(OLD,64))}
// --- P3: variantes del patron misc.js (acotan si el pid y/o la profundidad importan)
const TT=[[1,14,35],[1,14],[1,14,36,PID],[1,14,34,PID]];
for(let i=0;i<TT.length;i++){const m=TT[i];W("[sysctl] P3 test"+(i+2)+": MIB=["+m.join(",")+"] namelen="+m.length+" oldlen=0x100");const p=P(m,256n);REC(p);W("[sysctl] P3 test"+(i+2)+" ret="+p.r+" errno="+p.e+(p.r===0?" val="+STR(OLD,p.l):" ["+p.g+"]"))}
// --- P4: retest [1,1]/[1,2] con el patron misc.js (oldlen=0x100, namelen=2) -> confirma o descarta el errno 32 de la sesion anterior
const T4=[[1,1],[1,2]];
for(let i=0;i<2;i++){const m=T4[i];W("[sysctl] P4 test"+(i+1)+": MIB=["+m.join(",")+"] namelen=2 oldlen=0x100");const p=P(m,256n);REC(p);W("[sysctl] P4 test"+(i+1)+" ret="+p.r+" errno="+p.e+(p.e===32?" <- CONFIRMA errno 32":"")+(p.r===0?" val="+STR(OLD,p.l):" ["+p.g+"]"))}
// --- P5: barrido d1 COMPLETO a=0..127 namelen=1 SIN ABORT (mapa de whitelisting). W resumen por errno + lista de a con errno!=32 + valor ok (max 3)
W("[sysctl] P5 sweep d1 a=0..127 namelen=1 (corre SIEMPRE)");
const cnt={},alive=[];let okShown=0;
for(let a=0;a<128;a++){const p=P([a]);REC(p);cnt[p.e]=(cnt[p.e]||0)+1;
if(p.e!==32)alive.push(a+(p.r===0?"=ok":"=e"+p.e));
if(p.r===0&&okShown<3){okShown++;W("[sysctl] P5 OK a="+a+" len="+p.l+" hex="+DUMP(OLD,32)+" str="+STR(OLD,p.l))}}
const c32=cnt[32]||0,c2=cnt[2]||0,c0=cnt[0]||0;
W("[sysctl] P5 resumen: errno32="+c32+" errno2="+c2+" ok="+c0+" otros="+(128-c32-c2-c0)+" total=128");
W("[sysctl] P5 lista a errno!=32 ("+alive.length+"):");
for(let i=0;i<alive.length;i+=24)W("[sysctl] P5 alive: "+alive.slice(i,i+24).join(","));
// --- P6: subsistema 0 CTL_SYSCTL (ausente en header local, presente upstream 12/13): barrido [0,c] c=0..7
W("[sysctl] P6 sweep [0,c] namelen=2 c=0..7 (CTL_SYSCTL si existe)");
for(let c=0;c<8;c++){W("[sysctl] P6 test c="+c+": MIB=[0,"+c+"] namelen=2");const p=P([0,c]);REC(p);W("[sysctl] P6 c="+c+" ret="+p.r+" errno="+p.e+" oldlen*="+p.l+(p.r===0?" hex="+DUMP(OLD,32)+" str="+STR(OLD,p.l):" ["+p.g+"]"))}
// --- P7: strerror completo de cada errno unico observado (el 32 de Sony puede tener texto custom revelador)
const EK=Object.keys(ET);
W("[sysctl] P7 strerror de "+EK.length+" errno(s) unicos:");
for(let i=0;i<EK.length;i++)W("[sysctl] P7 errno "+EK[i]+" -> "+ET[EK[i]]);
// --- P7b: veredicto
let v;
if(p2.r===0)v="sysctl: whitelisted ("+alive.length+" MIBs vivos d1 + P2 ok = patron misc.js funciona)";
else if(all32)v="sysctl bloqueado blanket (todos errno 32: P2,P3,P5,P6)";
else v="P2 fail errno="+p2.e+" - NO blanket: "+alive.length+" d1 con errno!=32 (ver P5/P7)";
done(v);
})();
