// 2026-08-28 fuzz_s3_1320: SESION 3 - replay EXACTO de la secuencia de la sesion 1 (V1..V14, mismo orden y preparacion) para reproducir el ok:0x0 de IOREQ V14 - PS5 13.20
// H-PRIMING: en S1 V14 venia DETRAS de 16 llamadas previas (V1-V13,V17-V20 en orden real S1) - alguna dej6 estado que habilito el ok; S2 lanzo V2' en frio -> EINVAL.
// H-CONTENT: en S1 buf2 tenia 0x5C SOLO en los primeros 0x80 (arm con cap) y contenido malloc (zeros) mas alla; S2 lleno los 0x4000 COMPLETOS -> layouts distintos.
// Replay con arm de SOLO 0x80 como S1 -> V14-replay ok = H-PRIMING; EINVAL -> desempate V14b/V14c/V14d (layout exacto / fill completo / campo@0x80). KNOWN={2,13,14,22}. Vetados mmap/thr_new/rfork; bucles acotados; ultima linea "PAYLOAD DONE".
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const SCHED_YIELD=331n;
const S_BATCH_MAP=0x224n,S_PHYSHM_OPEN=0x275n,S_IOREQ=0x2CBn;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[fuzz3] "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[fuzz3] "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
// --- canal TCP crudo 192.168.1.67:8081 (identico fuzz_s1/fuzz_s2/p10) ---
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[fuzz3] SESION 3 replay S1 V1-V14 - H-PRIMING (estado previo) vs H-CONTENT (layout >0x80)");
// --- arm/oraculo EXACTOS de la sesion 1: arm CAPADO a 0x80 (NO el fill completo de S2),
// oraculo = primeros 0x40 bytes contra el qword del patron con el que se armo el buffer. ---
const HX=(v)=>{let x=BigInt.asUintN(64,BigInt(v)),s="";for(let i=0;i<8;i++){s="0123456789abcdef"[Number(x&0xffn)]+s;x>>=8n}return s};
const arm=(b,p,sz)=>{try{let n=sz<0x80?sz:0x80;for(let i=0;i<n;i++)write8(b+BigInt(i),p)}catch(e){}};
const oracle=(b,t,p,sz)=>{try{let n=sz<0x40?sz:0x40;const q0=BigInt(p)*0x0101010101010101n;let h="",d=false;
  for(let i=0;i<n;i+=8){const q=BigInt.asUintN(64,BigInt(read64(b+BigInt(i))));h+=HX(q)+" ";if(q!==q0)d=true}
  if(d)W(t+": "+h.trim())}catch(e){W(t+": LECTURA FAULT (¿kernel desmapeo el buffer?)")}};
// --- runner de variante identico a las sesiones 1/2: E -> arm(pre, cap 0x80) -> syscall -> R -> oracle(post). ---
let nOK=0;const news=[],res=[];const KNOWN={2:1,13:1,14:1,22:1};
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
const BUF=0x4000;
// ============ REPLAY de la secuencia S1 en el ORDEN EXACTO de ejecucion de fuzz_s1 (V14 al final, tras V13) ============
// Buffers malloc(0x4000) PROPIOS por variante, armados con 0xA5 solo en los primeros 0x80 (cap de arm), resto tal cual malloc.
const v1=V("V1","REPLAY BATCH_MAP(0,0,0) CONTROL",S_BATCH_MAP,[0n,0n,0n],null);
if(!v1.startsWith("ok"))W("[fuzz3] ANOMALIA: V1 no reproduce ok - entorno cambiado");
let b=malloc(BUF);V("V2","REPLAY BATCH_MAP(buf,0x1000,3)",S_BATCH_MAP,[b,0x1000n,3n],[{b:b,t:"V2 oracle",p:0xA5,s:BUF}]);
b=malloc(BUF);V("V3","REPLAY BATCH_MAP(buf,0x1000,0)",S_BATCH_MAP,[b,0x1000n,0n],[{b:b,t:"V3 oracle",p:0xA5,s:BUF}]);
b=malloc(BUF);V("V4","REPLAY BATCH_MAP(buf,0x40000,3) len 256KB",S_BATCH_MAP,[b,0x40000n,3n],[{b:b,t:"V4 oracle",p:0xA5,s:BUF}]);
b=malloc(BUF);V("V6","REPLAY BATCH_MAP(buf,0,3) len 0",S_BATCH_MAP,[b,0n,3n],[{b:b,t:"V6 oracle",p:0xA5,s:BUF}]);
b=malloc(BUF);V("V7","REPLAY BATCH_MAP(0,buf,3) addr NULL",S_BATCH_MAP,[0n,b,3n],[{b:b,t:"V7 oracle",p:0xA5,s:BUF}]);
b=malloc(BUF);V("V9","REPLAY BATCH_MAP(buf+0x1000,0x1000,3) sin page-align",S_BATCH_MAP,[b+0x1000n,0x1000n,3n],[{b:b+0x1000n,t:"V9 oracle",p:0xA5,s:0x3000}]);
const big=malloc(0x8000);const bufA=(big+0x3FFFn)&~0x3FFFn;
V("V10","REPLAY BATCH_MAP(bufA 0x4000-align,0x1000,3)",S_BATCH_MAP,[bufA,0x1000n,3n],[{b:bufA,t:"V10 oracle",p:0xA5,s:BUF}]);
// V5 al final del bloque BATCH_MAP (orden real S1): arg2 como PUNTERO - sospechosa.
const v5b2=malloc(BUF),v5b=malloc(BUF);
V("V5","REPLAY BATCH_MAP(buf2,buf,3) arg2=PUNTERO",S_BATCH_MAP,[v5b2,v5b,3n],[{b:v5b2,t:"V5 oracle-b1",p:0xA5,s:BUF},{b:v5b,t:"V5 oracle-b2",p:0xA5,s:BUF}]);
// Bloque PHYSHM_OPEN (orden real S1: va ANTES del bloque IOREQ - forma parte del priming).
let nm=alloc_string("phys0");b=malloc(BUF);
V("V17","REPLAY PHYSHM_OPEN(phys0,buf,0) CONTROL",S_PHYSHM_OPEN,[nm,b,0n],[{b:b,t:"V17 oracle",p:0xA5,s:BUF}]);
nm=alloc_string("phys0");b=malloc(BUF);
V("V18","REPLAY PHYSHM_OPEN(phys0,buf,0x1000) arg3=tam",S_PHYSHM_OPEN,[nm,b,0x1000n],[{b:b,t:"V18 oracle",p:0xA5,s:BUF}]);
nm=alloc_string("");b=malloc(BUF);
V("V19","REPLAY PHYSHM_OPEN(nombre-vacio,buf,0)",S_PHYSHM_OPEN,[nm,b,0n],[{b:b,t:"V19 oracle",p:0xA5,s:BUF}]);
nm=alloc_string("phys0");b=malloc(BUF);
V("V20","REPLAY PHYSHM_OPEN(buf,phys0,0) ORDEN INVERTIDO",S_PHYSHM_OPEN,[b,nm,0n],[{b:b,t:"V20 oracle",p:0xA5,s:BUF}]);
// Bloque IOREQ: V11 V12 V13 y LA JUGADA V14 (buf2 = 0x5C SOLO en los primeros 0x80, como S1 - resto tal cual malloc).
b=malloc(BUF);V("V11","REPLAY IOREQ(1,buf,0x10)",S_IOREQ,[1n,b,0x10n],[{b:b,t:"V11 oracle",p:0xA5,s:BUF}]);
b=malloc(BUF);V("V12","REPLAY IOREQ(1,buf,4)",S_IOREQ,[1n,b,4n],[{b:b,t:"V12 oracle",p:0xA5,s:BUF}]);
b=malloc(BUF);V("V13","REPLAY IOREQ(2,buf,0x100)",S_IOREQ,[2n,b,0x100n],[{b:b,t:"V13 oracle",p:0xA5,s:BUF}]);
const v14b=malloc(BUF),v14b2=malloc(BUF);
const r14=V("V14","REPLAY IOREQ(1,buf2,0x100) LA JUGADA: buf2 0x5C solo 0x80, tras 16 llamadas previas",S_IOREQ,[1n,v14b2,0x100n],[{b:v14b2,t:"V14 oracle-buf2(5C)",p:0x5C,s:BUF},{b:v14b,t:"V14 oracle-buf(A5)",p:0xA5,s:BUF}]);
// ============ RAMA DE DESEMPATE H-CONTENT (solo si V14-replay NO reproduce) ============
let r14b="skip",r14c="skip",r14d="skip";
if(!r14.startsWith("ok")){
  W("[fuzz3] V14-replay NO reproduce ("+r14+") -> desempate H-CONTENT: V14b/V14c/V14d");
  // V14b: layout EXACTO de S1 FORZADO: 0x5C en los primeros 0x80 (lo pone arm() del runner) + ceros EXPLICITOS escritos
  // con bucle write8 en 0x80..0x3FFF (nada de basura de malloc). Si ok -> H-CONTENT: el kernel valida la zona >0x80.
  const c1=malloc(BUF);for(let i=0x80;i<BUF;i++)write8(c1+BigInt(i),0);
  r14b=V("V14b","IOREQ(1,buf,0x100) 5C[0..0x80)+CEROS explicitos despues (layout S1 forzado)",S_IOREQ,[1n,c1,0x100n],[{b:c1,t:"V14b oracle(5C)",p:0x5C,s:BUF}]);
  // V14c: 0x5C en los 0x4000 COMPLETOS (layout de la sesion 2). V14b=ok + V14c=e22 -> el kernel exige zeros despues del 0x80.
  const c2=malloc(BUF);for(let i=0;i<BUF;i++)write8(c2+BigInt(i),0x5C);
  r14c=V("V14c","IOREQ(1,buf,0x100) 5C en TODO el 0x4000 (layout sesion 2)",S_IOREQ,[1n,c2,0x100n],[{b:c2,t:"V14c oracle(5C)",p:0x5C,s:BUF}]);
  // V14d: 0x5C en 0..0x80 + 2 qwords 0x5C5C5C5C5C5C5C5C en offset 0x80/0x88 + ceros despues -> sondeo de campo:
  // si e22 con solo 16 bytes de 5C tras el 0x80 -> hay un campo near-0x80 que debe ser cero.
  const c3=malloc(BUF);for(let i=0;i<BUF;i++)write8(c3+BigInt(i),0);
  write64(c3+0x80n,0x5C5C5C5C5C5C5C5Cn);write64(c3+0x88n,0x5C5C5C5C5C5C5C5Cn);
  r14d=V("V14d","IOREQ(1,buf,0x100) 5C[0..0x80)+2 qwords 5C en 0x80 + ceros (sondeo campo)",S_IOREQ,[1n,c3,0x100n],[{b:c3,t:"V14d oracle(5C)",p:0x5C,s:BUF}]);
}
// ============ VEREDICTO AUTOMATICO ============
let verdict="";
if(r14.startsWith("ok"))verdict="H-PRIMING: el estado previo habilita el ok (bisectar en sesion 4)";
else if(r14b.startsWith("ok"))verdict="H-CONTENT: layout exacto requerido (zona >0x80 validada)";
else verdict="el ok de sesion 1 fue efimero/estado externo (no reproducible con layout S1)";
W("[fuzz3] VEREDICTO: "+verdict);
if(!r14.startsWith("ok")){
  if(r14b.startsWith("ok")&&r14c.startsWith("ok"))W("[fuzz3] refine: V14b=V14c=ok -> ni zeros ni 5C totales gatean: el EINVAL del replay viene de la BASURA de malloc >0x80 (contenido concreto) u orden/estado");
  if(r14b.startsWith("ok")&&r14c==="errno=22")W("[fuzz3] refine: V14b=ok V14c=e22 -> el kernel exige ZEROS despues del 0x80 (el fill completo de S2 fue la causa)");
  if(!r14b.startsWith("ok")&&r14c.startsWith("ok"))W("[fuzz3] refine: V14c=ok V14b!=ok -> exige 5C TAMBIEN mas alla del 0x80: hipotesis invertida, S2 y S1 difieren en otra cosa");
  if(r14b==="errno=22"&&r14c==="errno=22")W("[fuzz3] refine: V14b y V14c ambos e22 -> ningun layout >0x80 salva: refuerza H-PRIMING/estado externo sobre H-CONTENT");
  if(r14d.startsWith("ok"))W("[fuzz3] refine: V14d=ok -> 2 qwords 5C en 0x80 se toleran: no hay campo critico justo tras el 0x80");
  else W("[fuzz3] refine: V14d!=ok -> 16 bytes 5C en 0x80 rompen el ok: campo near-0x80 que debe ser cero");
}
// ================= RESUMEN =================
W("[fuzz3] RESUMEN: "+nOK+" ok, "+news.length+" nuevos, "+res.join(" "));
const vt=("[fuzz3] S3 replay: "+nOK+"ok "+news.length+"nuevos "+verdict).slice(0,90);
N(vt);
for(let i=0;i<150;i++){N("["+(150-i)+"] "+vt);for(let j=0;j<3000;j++){syscall(SCHED_YIELD)}}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
