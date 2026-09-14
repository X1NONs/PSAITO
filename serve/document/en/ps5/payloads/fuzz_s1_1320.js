// 2026-08-27 fuzz_s1_1320: SESION 1 de fuzzing de la superficie propietaria 0x2xx (24 variantes V1-V24) - PS5 13.20
// Plan: RESEARCH/fuzzing-0x2xx-plan.md SS2-SS3. Bloques: BATCH_MAP 0x224 (V1-V10), PHYSHM_OPEN 0x275 (V17-V20), IOREQ 0x2CB (V11-V16), get_self_auth_info 0x25F (V21-V24).
// Orden anti-muerte SS3.5: controles V1/V17 primero; sospechosas V5/V20 al final de su bloque; V8 (prot RWX) AL FINAL DEL TODO. Oracle 0xA5 pre/post en buffers malloc PROPIOS (nunca modulos; vetados mmap/thr_new/rfork).
// Canal: TCP crudo a 192.168.1.67:8081 identico a p10_rfork_1320. Si el proceso muere, la ultima linea recibida identifica la variante culpable. Ultima linea = "PAYLOAD DONE" (tanda completa).
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const SYS_EXIT=1n,SCHED_YIELD=331n;
const S_BATCH_MAP=0x224n,S_PHYSHM_OPEN=0x275n,S_IOREQ=0x2CBn,S_AUTH_INFO=0x25Fn;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[fuzz] "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[fuzz] "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
// --- canal TCP crudo 192.168.1.67:8081 (idéntico p10/diag_raw3) ---
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[fuzz] SESION 1 0x2xx - 24 variantes (plan SS3)");
const pid=I(syscall(SYSCALL.getpid));
// --- oraculo: ANTES de cada syscall se llena el buffer con patron (touch + fingerprint);
// DESPUES se leen los primeros 0x40 bytes con read64 y SOLO si algo difiere del patron
// (escritura del kernel detectada) se vuelcan los qwords por W(). ---
const HX=(v)=>{let x=BigInt.asUintN(64,BigInt(v)),s="";for(let i=0;i<8;i++){s="0123456789abcdef"[Number(x&0xffn)]+s;x>>=8n}return s};
const arm=(b,p,sz)=>{try{let n=sz<0x80?sz:0x80;for(let i=0;i<n;i++)write8(b+BigInt(i),p)}catch(e){}};
const oracle=(b,t,p,sz)=>{try{let n=sz<0x40?sz:0x40;const q0=BigInt(p)*0x0101010101010101n;let h="",d=false;
  for(let i=0;i<n;i+=8){const q=BigInt.asUintN(64,BigInt(read64(b+BigInt(i))));h+=HX(q)+" ";if(q!==q0)d=true}
  if(d)W(t+": "+h.trim())}catch(e){W(t+": LECTURA FAULT (¿kernel desmapeo el buffer?)")}};
// --- runner de variante: E -> arm(pre) -> syscall -> R -> oracle(post). Registra resumen. ---
// errnos ya vistos el 27/08 en esta superficie: 22 EINVAL, 13 EFAULT, 2 ENOENT -> "nuevo" = fuera del set.
let nOK=0;const news=[],res=[];const KNOWN={2:1,13:1,22:1};
const V=(tag,desc,num,args,ors)=>{
  E(tag,desc);
  if(ors)for(const o of ors)arm(o.b,o.p,o.s);
  let out;
  try{
    const raw=syscall(B(num),...args.map((a)=>B(a)));
    const r=I(raw);
    if(r<0n){const e=EN();out="errno="+e;res.push(tag+"=e"+e);if(!KNOWN[e])news.push(tag+":e"+e)}
    else{nOK++;out="ok:0x"+r.toString(16);res.push(tag+"=ok0x"+r.toString(16));if(r!==0n)news.push(tag+":ok0x"+r.toString(16))}
  }catch(e){out="EX:"+e;res.push(tag+"=EX")}
  R(tag,out);
  if(ors)for(const o of ors)oracle(o.b,o.t,o.p,o.s);
  return out;
};
// ================= BLOQUE BATCH_MAP 0x224 (V1-V10) =================
// V1 CONTROL: debe reproducir ok:0x0 (2/2 el 27/08); si no, el entorno cambio y la sesion se anula.
const v1=V("V1","BATCH_MAP(0,0,0) CONTROL",S_BATCH_MAP,[0n,0n,0n],null);
if(!v1.startsWith("ok"))W("[fuzz] V1 ANOMALIA: entorno cambiado");
let b=malloc(0x4000);V("V2","BATCH_MAP(buf,0x1000,3)",S_BATCH_MAP,[b,0x1000n,3n],[{b:b,t:"V2 oracle",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V3","BATCH_MAP(buf,0x1000,0)",S_BATCH_MAP,[b,0x1000n,0n],[{b:b,t:"V3 oracle",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V4","BATCH_MAP(buf,0x40000,3) len 256KB",S_BATCH_MAP,[b,0x40000n,3n],[{b:b,t:"V4 oracle",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V6","BATCH_MAP(buf,0,3) len 0",S_BATCH_MAP,[b,0n,3n],[{b:b,t:"V6 oracle",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V7","BATCH_MAP(0,buf,3) addr NULL",S_BATCH_MAP,[0n,b,3n],[{b:b,t:"V7 oracle",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V9","BATCH_MAP(buf+0x1000,0x1000,3) sin page-align",S_BATCH_MAP,[b+0x1000n,0x1000n,3n],[{b:b+0x1000n,t:"V9 oracle",p:0xA5,s:0x3000}]);
const big=malloc(0x8000);const bufA=(big+0x3FFFn)&~0x3FFFn;
V("V10","BATCH_MAP(bufA 0x4000-align,0x1000,3)",S_BATCH_MAP,[bufA,0x1000n,3n],[{b:bufA,t:"V10 oracle",p:0xA5,s:0x4000}]);
// V5 AL FINAL del bloque: arg2 como PUNTERO (par in/out src->dst?) - sospechosa.
const v5b2=malloc(0x4000),v5b=malloc(0x4000);
V("V5","BATCH_MAP(buf2,buf,3) arg2=PUNTERO",S_BATCH_MAP,[v5b2,v5b,3n],[{b:v5b2,t:"V5 oracle-b1",p:0xA5,s:0x4000},{b:v5b,t:"V5 oracle-b2",p:0xA5,s:0x4000}]);
// ================= BLOQUE PHYSHM_OPEN 0x275 (V17-V20) =================
let nm=alloc_string("phys0");b=malloc(0x4000);
V("V17","PHYSHM_OPEN(phys0,buf,0) CONTROL",S_PHYSHM_OPEN,[nm,b,0n],[{b:b,t:"V17 oracle",p:0xA5,s:0x4000}]);
nm=alloc_string("phys0");b=malloc(0x4000);
V("V18","PHYSHM_OPEN(phys0,buf,0x1000) arg3=tam",S_PHYSHM_OPEN,[nm,b,0x1000n],[{b:b,t:"V18 oracle",p:0xA5,s:0x4000}]);
nm=alloc_string("");b=malloc(0x4000);
V("V19","PHYSHM_OPEN(nombre-vacio,buf,0)",S_PHYSHM_OPEN,[nm,b,0n],[{b:b,t:"V19 oracle",p:0xA5,s:0x4000}]);
// V20 AL FINAL del bloque: orden de args invertido (truco que dio ENOENT en auth_info).
nm=alloc_string("phys0");b=malloc(0x4000);
V("V20","PHYSHM_OPEN(buf,phys0,0) ORDEN INVERTIDO",S_PHYSHM_OPEN,[b,nm,0n],[{b:b,t:"V20 oracle",p:0xA5,s:0x4000}]);
// ================= BLOQUE IOREQ 0x2CB (V11-V16) =================
b=malloc(0x4000);V("V11","IOREQ(1,buf,0x10)",S_IOREQ,[1n,b,0x10n],[{b:b,t:"V11 oracle",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V12","IOREQ(1,buf,4)",S_IOREQ,[1n,b,4n],[{b:b,t:"V12 oracle",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V13","IOREQ(2,buf,0x100)",S_IOREQ,[2n,b,0x100n],[{b:b,t:"V13 oracle",p:0xA5,s:0x4000}]);
// V14: buf2 = buffer DISTINTO con patron 0x5C; se oraclean AMBOS (buf 0xA5 de control
// y buf2 0x5C pasado como arg) para detectar cual escribe el kernel.
const v14b=malloc(0x4000),v14b2=malloc(0x4000);
V("V14","IOREQ(1,buf2,0x100) buf2 patron 0x5C",S_IOREQ,[1n,v14b2,0x100n],[{b:v14b2,t:"V14 oracle-buf2(5C)",p:0x5C,s:0x4000},{b:v14b,t:"V14 oracle-buf(A5)",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V15","IOREQ(1,buf,0)",S_IOREQ,[1n,b,0n],[{b:b,t:"V15 oracle",p:0xA5,s:0x4000}]);
b=malloc(0x4000);V("V16","IOREQ(3,buf,0x100)",S_IOREQ,[3n,b,0x100n],[{b:b,t:"V16 oracle",p:0xA5,s:0x4000}]);
// ================= BLOQUE get_self_auth_info 0x25F (V21-V24) =================
// ABI (pid,buf) confirmado por diferencial el 27/08; sweep de tamano de buffer propio.
let ab=malloc(0x128);V("V21","AUTH_INFO(pid,buf 0x128)",S_AUTH_INFO,[B(pid),ab],[{b:ab,t:"V21 oracle",p:0xA5,s:0x128}]);
ab=malloc(0x200);V("V22","AUTH_INFO(pid,buf 0x200)",S_AUTH_INFO,[B(pid),ab],[{b:ab,t:"V22 oracle",p:0xA5,s:0x200}]);
ab=malloc(0x40);V("V23","AUTH_INFO(pid,buf 0x40)",S_AUTH_INFO,[B(pid),ab],[{b:ab,t:"V23 oracle",p:0xA5,s:0x40}]);
ab=malloc(0x1000);V("V24","AUTH_INFO(pid,buf 0x1000)",S_AUTH_INFO,[B(pid),ab],[{b:ab,t:"V24 oracle",p:0xA5,s:0x1000}]);
// ================= V8: prot RWX - AL FINAL DEL TODO (jackpot check) =================
// Si BATCH_MAP da exec (prot=7 RWX) donde jitshm_create da EPERM -> jackpot directo.
b=malloc(0x4000);
const v8=V("V8","BATCH_MAP(buf,0x1000,7) PROT RWX JACKPOT-CHECK",S_BATCH_MAP,[b,0x1000n,7n],[{b:b,t:"V8 oracle",p:0xA5,s:0x4000}]);
if(v8.startsWith("ok"))W("[fuzz] V8 JACKPOT: batch_map prot=7 devolvio OK - posible exec fuera de jitshm");
// ================= RESUMEN =================
W("[fuzz] RESUMEN: "+nOK+" ok, "+news.length+" nuevos, "+res.join(" "));
const vt=("[fuzz] S1 0x2xx: "+nOK+"ok "+news.length+"nuevos"+(news.length?" ["+news.join(" ")+"]":" (nada nuevo)")).slice(0,90);
N(vt);
for(let i=0;i<150;i++){N("["+(150-i)+"] "+vt);for(let j=0;j<3000;j++){syscall(SCHED_YIELD)}}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
