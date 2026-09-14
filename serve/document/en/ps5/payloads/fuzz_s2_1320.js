// 2026-08-28 fuzz_s2_1320: SESION 2 de fuzzing - AISLAMIENTO de la variable ganadora de IOREQ 0x2CB - PS5 13.20
// Plan: RESEARCH/fuzzing-0x2xx-plan.md SS3.6 (matriz V1'-V8'). Sesion 1 (SS5): IOREQ(1,buf2[0x5C],0x100)=ok:0x0 UNICA ganadora de 24;
// (1,buf[0xA5],0x10/4/0) y (2/3,buf[0xA5],0x100) = EINVAL. Dos hipotesis en conflicto:
//   A) arg3=0x100 es el valor magico requerido (el patron del buffer es irrelevante).
//   B) el kernel LEE y VALIDA el CONTENIDO del buffer (0x5C pasa, 0xA5/zeros no).
// 8 variantes sobre IOREQ 0x2CB. Buffers malloc(0x4000) PROPIOS por variante, pre-rellenados COMPLETOS con su patron
// (arm() extendido: sin cap de 0x80 - se llenan los 0x4000, cubriendo de sobra los 0x100 que el kernel pudiera leer).
// ORDEN: V2' CONTROL POSITIVO PRIMERO (si no reproduce el ok -> entorno cambiado -> sesion invalida, se aborta la tanda)
// -> V1' LA CLAVE (0xA5+0x100: ok=A, e22=B) -> V3' V4' V5' V6' -> V7' V8'. Oracle post compara contra el patron EXACTO de cada buffer.
// KNOWN={2,13,14,22} (correccion de bookkeeping SS5: EFAULT(14) ya visto). Canal TCP crudo 192.168.1.67:8081 identico a fuzz_s1.
// Anti-muerte SS2.3: vetados mmap/thr_new/rfork/read64-de-modulos; W() ANTES de cada syscall; bucles acotados. Ultima linea = "PAYLOAD DONE".
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const SYS_EXIT=1n,SCHED_YIELD=331n;
const S_IOREQ=0x2CBn;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[fuzz2] "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[fuzz2] "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
// --- canal TCP crudo 192.168.1.67:8081 (identico fuzz_s1/p10) ---
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[fuzz2] SESION 2 IOREQ 0x2CB - 8 variantes V1'-V8' (plan SS3.6): A=arg3 0x100 magico vs B=kernel valida contenido");
const pid=I(syscall(SYSCALL.getpid));
// --- oraculo: el buffer ya viene PRE-RELENADO con su patron exacto por arm(); tras la syscall se leen
// los primeros 0x40 bytes y SOLO si algun qword difiere del qword del patron EXACTO de ese buffer
// (escritura del kernel detectada) se vuelcan por W(). Cada oracle lleva el patron con el que se armo su buffer. ---
const HX=(v)=>{let x=BigInt.asUintN(64,BigInt(v)),s="";for(let i=0;i<8;i++){s="0123456789abcdef"[Number(x&0xffn)]+s;x>>=8n}return s};
// arm() EXTENDIDO (cambio SS2): parámetro de longitud completa - llena sz bytes ENTEROS (los 0x4000 del
// buffer), no solo 0x80. Los buffers quedan pre-rellenados COMPLETOS con su patron: touch + fingerprint.
const arm=(b,p,sz)=>{try{const n=BigInt(sz);for(let i=0n;i<n;i++)write8(b+i,p)}catch(e){}};
const oracle=(b,t,p,sz)=>{try{let n=sz<0x40?sz:0x40;const q0=BigInt(p)*0x0101010101010101n;let h="",d=false;
  for(let i=0;i<n;i+=8){const q=BigInt.asUintN(64,BigInt(read64(b+BigInt(i))));h+=HX(q)+" ";if(q!==q0)d=true}
  if(d)W(t+": "+h.trim())}catch(e){W(t+": LECTURA FAULT (¿kernel desmapeo el buffer?)")}};
// --- runner de variante (identico fuzz_s1): E -> arm(pre, llenado COMPLETO) -> syscall -> R -> oracle(post). ---
// errnos ya vistos 27-28/08: 2 ENOENT, 13 EACCES, 14 EFAULT (S1 auth_info), 22 EINVAL -> "nuevo" = fuera del set.
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
// ============ V2' CONTROL POSITIVO - SE EJECUTA PRIMERO DE TODAS (debe reproducir el ok:0x0 de V14/S1) ============
const b2=malloc(BUF);
const r2=V("V2'","IOREQ(1,buf[0x5C],0x100) CONTROL POSITIVO - debe reproducir ok de sesion 1",S_IOREQ,[1n,b2,0x100n],[{b:b2,t:"V2' oracle(5C)",p:0x5C,s:BUF}]);
const envOk=r2.startsWith("ok");
if(!envOk)W("[fuzz2] ANOMALIA: V2' NO reproduce el ok de la sesion 1 - el entorno cambio - se aborta la tanda");
// ============ V1' LA CLAVE (solo si el control positivo vale) y resto de la matriz ============
let r1="skip",r3="skip",r4="skip",r5="skip",r6="skip",r7="skip",r8="skip";
if(envOk){
  const b1=malloc(BUF);
  r1=V("V1'","IOREQ(1,buf[0xA5],0x100) LA CLAVE ok->A(arg3 magico) e22->B(kernel valida contenido)",S_IOREQ,[1n,b1,0x100n],[{b:b1,t:"V1' oracle(A5)",p:0xA5,s:BUF}]);
  const b3=malloc(BUF);
  r3=V("V3'","IOREQ(1,buf[0x5C],0x10) patron ganador con arg3 pequeno",S_IOREQ,[1n,b3,0x10n],[{b:b3,t:"V3' oracle(5C)",p:0x5C,s:BUF}]);
  const b4=malloc(BUF);
  r4=V("V4'","IOREQ(1,buf[0x00],0x100) todo ceros con arg3 magico",S_IOREQ,[1n,b4,0x100n],[{b:b4,t:"V4' oracle(00)",p:0x00,s:BUF}]);
  const b5=malloc(BUF);
  r5=V("V5'","IOREQ(1,buf[0x5C],0x80) arg3 intermedio (por debajo de 0x100)",S_IOREQ,[1n,b5,0x80n],[{b:b5,t:"V5' oracle(5C)",p:0x5C,s:BUF}]);
  const b6=malloc(BUF);
  r6=V("V6'","IOREQ(1,buf[0x5C],0x200) arg3 mayor (por encima de 0x100)",S_IOREQ,[1n,b6,0x200n],[{b:b6,t:"V6' oracle(5C)",p:0x5C,s:BUF}]);
  const b7=malloc(BUF);
  r7=V("V7'","IOREQ(4,buf[0x5C],0x100) tipo 4 con shape ganador",S_IOREQ,[4n,b7,0x100n],[{b:b7,t:"V7' oracle(5C)",p:0x5C,s:BUF}]);
  const b8=malloc(BUF);
  r8=V("V8'","IOREQ(5,buf[0x5C],0x100) tipo 5 con shape ganador",S_IOREQ,[5n,b8,0x100n],[{b:b8,t:"V8' oracle(5C)",p:0x5C,s:BUF}]);
}
// ============ VEREDICTO AUTOMATICO ============
let verdict="";
if(!envOk)verdict="entorno cambiado, sesion invalida";
else if(r1.startsWith("ok"))verdict="hipotesis A (arg3=0x100 es el gate)";
else if(r1==="errno=22")verdict="hipotesis B (el kernel valida contenido)";
else verdict="indefinido (V1' dio "+r1+")";
W("[fuzz2] VEREDICTO: "+verdict);
if(envOk){
  // Refinimiento con V3'-V8' (SS3.6 lectura combinada).
  if(r3.startsWith("ok"))W("[fuzz2] refine: V3'=ok -> con patron 5C arg3=0x10 basta: 0x100 NO es valor exacto (refuerza B / umbral?)");
  else W("[fuzz2] refine: V3'!=ok -> con patron 5C sigue haciendo falta arg3=0x100");
  if(r4.startsWith("ok"))W("[fuzz2] refine: V4'=ok -> ceros pasan con arg3=0x100: el contenido NO gatea (apoya A)");
  else W("[fuzz2] refine: V4'!=ok -> ceros fallan con arg3=0x100 (apoya B)");
  if(r5.startsWith("ok"))W("[fuzz2] refine: V5'(0x80)=ok -> arg3 = umbral/len minimo, no valor exacto");
  if(r6.startsWith("ok"))W("[fuzz2] refine: V6'(0x200)=ok -> arg3 admite >0x100: umbral<=0x100 o len in/out");
  if(!r5.startsWith("ok")&&!r6.startsWith("ok"))W("[fuzz2] refine: V5' y V6' ambos fallan -> 0x100 es VALOR EXACTO requerido");
  if(r7.startsWith("ok"))W("[fuzz2] refine: V7'(tipo4)=ok -> el gate es (tipo,arg3): otro tipo comparte shape (no contenido)");
  if(r8.startsWith("ok"))W("[fuzz2] refine: V8'(tipo5)=ok -> el gate es (tipo,arg3): otro tipo comparte shape (no contenido)");
}
// ================= RESUMEN =================
W("[fuzz2] RESUMEN: "+nOK+" ok, "+news.length+" nuevos, "+res.join(" "));
const vt=("[fuzz2] S2 IOREQ: "+nOK+"ok "+news.length+"nuevos "+verdict).slice(0,90);
N(vt);
for(let i=0;i<150;i++){N("["+(150-i)+"] "+vt);for(let j=0;j<3000;j++){syscall(SCHED_YIELD)}}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
