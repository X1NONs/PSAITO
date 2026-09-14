// 2026-09-11 aio_reach_1320: sonda Fase 1 cadena BAGAGWA (RESEARCH/bagagwa-aio-multi-wait-uaf-2026-09-06.md).
// Objetivo: decidir si la familia AIO 0x295-0x2B0 + el leak 0x2D7 (syscall 727 GET_AIO_DEBUG_REQUEST_INFO,
// ausente del playbook) son LLAMABLES desde el sandbox Y2JB 13.20. Gate previo a cualquier spray:
// si el SAR/violación veto AIO -> la cadena muere aquí. Solo reachability + ABI shapes: NO intenta el UAF,
// no toca osem (ya cubierto en osem_campaign), NO duerme salvo PASO 5 marcado (hang = dato).
// Base osem_campaign_1320 (canal W() TCP crudo 192.168.1.67:8081 0x911F/0x4301A8C0, helpers SC/EN/HX).
// Reglas: args siempre buffers malloc propios, W ANTES (args) y DESPUES (ret/errno) de cada syscall,
// sin mmap/thr_new/rfork/read64 de modulos, bucles acotados, <8KB. ENOSYS(78)=no existe; resto=viva.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const Y=331n;
const A_INIT=0x29En,A_CREATE=0x29Cn,A_SUBMIT=0x295n,A_SUBCMD=0x29Dn,A_WAIT=0x297n,A_POLL=0x298n,
 A_CANCEL=0x29An,A_DEL=0x296n,A_GET=0x299n,A_MLOCK=0x2B0n,A_SUSP=0x13Bn,A_DEBUG=0x2D7n;
const EL={1:"EPERM",2:"ENOENT",9:"EBADF",12:"ENOMEM",14:"EFAULT",16:"EBUSY",17:"EEXIST",22:"EINVAL",28:"ENOSPC",35:"EAGAIN",63:"ENAMETOOLONG",78:"ENOSYS",93:"ENOTCAPABLE",94:"ECAPMODE"};
const ELM=(e)=>EL[e]!==undefined?EL[e]:"?";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[aio] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[aio] PASO "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const J=(e)=>" errno="+e+"("+ELM(e)+")";
const FX=(v)=>"0x"+B(v).toString(16);
const HX=(b,n)=>{let x="";for(let i=0;i<n;i++){const v=Number(read8(b+BigInt(i)))&255;x+=(v<16?"0":"")+v.toString(16)+" "}return x};
const VS=(q)=>q.ex?"EX":(q.r>=0n?"ok0x"+q.r.toString(16):"e"+q.e);
const VIVA=(q)=>!q.ex&&!(q.r===-1n&&q.e===78);
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[aio] inicio - canal "+(sock>=0n?"OK":"MUERTO")+" - familia AIO 0x29x + DEBUG 0x2D7 (bagagwa fase 1)");
const SC=(tag,sc,args,desc)=>{const p=tag+(desc?" "+desc:"")+" ("+args.map(FX).join(",")+")";W(p+" ...");
 const o={r:-9999n,e:-1,ex:false};
 try{o.r=I(syscall(sc,...args.map((a)=>B(a))));if(o.r<0n)o.e=EN();}catch(err){o.ex=true;W(p+" -> EXCEPCION "+err);return o;}
 W(p+" -> "+(o.r>=0n?"ret=0x"+o.r.toString(16)+" OK":o.r+J(o.e)));
 return o;};
const SUM=[];
// ===== PASO 1: ceniza cero-args de la familia (existencia: ret>=0 o errno!=78 => viva) =====
E(1,"cero-args familia AIO completa + 0x2D7");
const FAM=[["INIT",A_INIT],["CREATE",A_CREATE],["SUBMIT",A_SUBMIT],["SUBCMD",A_SUBCMD],
 ["POLL",A_POLL],["CANCEL",A_CANCEL],["DELETE",A_DEL],["GET_DATA",A_GET],["MLOCK",A_MLOCK],["SUSPEND",A_SUSP]];
const v1={};
for(const f of FAM){const q=SC("AIO_"+f[0]+"_0x"+f[1].toString(16),f[1],[0n,0n,0n],"(0,0,0)");v1[f[0]]=q;}
const r1=FAM.map(f=>f[0]+"="+(v1[f[0]].ex?"EX":(v1[f[0]].r>=0n?"OK":(v1[f[0]].e===78?"muerta":"viva-e"+v1[f[0]].e))));
R(1,r1.join(" "));SUM.push("FAMILIA: "+r1.join(" "));
const anyAIO=FAM.some(f=>VIVA(v1[f[0]]));
W("[aio] GATE AIO: "+(anyAIO?"AL MENOS UNA VIVA -> continuar":"TODAS 78/EX -> cadena bagagwa CERRADA por SAR"));
// ===== PASO 2: shapes AIO_INIT / AIO_CREATE (solo si la familia responde) =====
if(anyAIO){
 E(2,"shapes INIT 0x29E y CREATE 0x29C (ABI hipotesis, oracle centinela)");
 const OB=malloc(16);write64(OB,0x0BADC0DE0BADC0DEn);write64(OB+8n,0x0BADC0DE0BADC0DEn);
 const qi1=SC("INIT_0x29E",A_INIT,[0n],"(flags=0)");
 const qi2=SC("INIT_0x29E",A_INIT,[1n],"(flags=1)");
 const qi3=SC("INIT_0x29E",A_INIT,[OB],"(opt=buf centinela)");
 let ch=false;try{ch=read64(OB)!==0x0BADC0DE0BADC0DEn||read64(OB+8n)!==0x0BADC0DE0BADC0DEn}catch(e){}
 W("oracle INIT optbuf: "+HX(OB,16)+" "+(ch?"CAMBIADO (out-param existe)":"IGNIDO"));
 const qc1=SC("CREATE_0x29C",A_CREATE,[0n,0n],"(NULL,0)");
 const qc2=SC("CREATE_0x29C",A_CREATE,[OB,0n],"(buf,0)");
 const qc3=SC("CREATE_0x29C",A_CREATE,[OB,1n],"(buf,1)");
 R(2,"init: "+VS(qi1)+"/"+VS(qi2)+"/"+VS(qi3)+(ch?" +bufCAMBIADO":"")+" | create: "+VS(qc1)+"/"+VS(qc2)+"/"+VS(qc3));
 SUM.push("SHAPES init="+VS(qi1)+"/"+VS(qi2)+"/"+VS(qi3)+" create="+VS(qc1)+"/"+VS(qc2)+"/"+VS(qc3));
}else{E(2,"shapes INIT/CREATE");R(2,"SKIPPED (familia muerta)");SUM.push("SHAPES: skipped")}
// ===== PASO 3: 0x2D7 GET_AIO_DEBUG_REQUEST_INFO (el leak del paste) =====
E(3,"DEBUG 0x2D7 shapes (paste: req_id en [1,0x228], req_id>>16<0x80; hipotesis (req_id, out*) y (req_id, idx, out*))");
const LB=malloc(0x40);for(let i=0n;i<0x40n;i+=8n)write64(LB+i,0xDEADBEEF00000000n+i);
const d1=SC("DEBUG_0x2D7",A_DEBUG,[0n,0n],"(0,0)");
const d2=SC("DEBUG_0x2D7",A_DEBUG,[1n,LB],"(1,buf)");
const d3=SC("DEBUG_0x2D7",A_DEBUG,[1n,0n,LB],"(1,0,buf)");
const d4=SC("DEBUG_0x2D7",A_DEBUG,[0x10001n,LB],"(0x10001=1<<16|1,buf)");
const d5=SC("DEBUG_0x2D7",A_DEBUG,[0x800001n,LB],"(0x800001=idx>=0x80,buf) fuera-limite");
let leak="no";for(let i=0n;i<0x40n;i+=8n){try{if(read64(LB+i)!==0xDEADBEEF00000000n+i)leak="SI"}catch(e){leak="fault"}}
W("oracle buf 0x2D7 post-barrido: "+(leak==="SI"?"CAMBIADO -> kernel escribio, leak VIVO: ":"ignido ")+HX(LB,48));
const rd3=VS(d3);
R(3,"0x2D7: "+VS(d1)+"/"+VS(d2)+"/"+rd3+"/"+VS(d4)+"/"+VS(d5)+" | escritura detectada: "+leak);
SUM.push("DEBUG0x2D7: "+VS(d1)+"/"+VS(d2)+"/"+rd3+"/"+VS(d4)+"/"+VS(d5)+" leak="+leak);
// ===== PASO 4: MULTI_POLL grid num/mode (no bloqueante) =====
if(VIVA(v1["POLL"])){
 E(4,"POLL 0x298 grid (num,mode,0) sin contexto valido - forma de los args");
 const G=[];
 for(const a of [[0n,0n],[1n,0n],[1n,1n],[1n,2n],[2n,0n],[2n,1n]]){const q=SC("POLL_0x298",A_POLL,[a[0],a[1],0n],"(num="+a[0]+",mode="+a[1]+",0)");G.push(a[0]+","+a[1]+"="+VS(q));if(q.r>=0n)W(">>> POLL OK con num="+a[0]+" mode="+a[1]+" -> arg0 NO es puntero a array de ids o el sandbox permite AIO real");}
 R(4,G.join(" "));SUM.push("POLL: "+G.join(" "));
}else{E(4,"POLL grid");R(4,"SKIPPED (POLL sin senal de vida)");SUM.push("POLL: skipped")}
// ===== PASO 5: MULTI_WAIT minimo - RIESGO DE HANG documentado =====
// (fix 2026-09-11: v1 no tiene clave WAIT - FAM no la incluye - VIVA(undefined)
// lanzaba TypeError y mataba el payload antes del veredicto)
if(anyAIO||(v1["WAIT"]&&VIVA(v1["WAIT"]))){
 E(5,"WAIT 0x297 x2 con num invalido/1 - SI EL PAYLOAD SE CUELGA AQUI, la ultima W delat el formato que bloquea (dato valioso, la consola NO se cae)");
 const w1=SC("WAIT_0x297",A_WAIT,[0n,0n,0n],"(0,0,0)");
 const w2=SC("WAIT_0x297",A_WAIT,[1n,0n,0n],"(1,0,0)");
 R(5,"wait: "+VS(w1)+"/"+VS(w2));SUM.push("WAIT: "+VS(w1)+" "+VS(w2));
}else{E(5,"WAIT");R(5,"SKIPPED (WAIT muerta y familia sin vida)");SUM.push("WAIT: skipped")}
// ===== PASO 6: veredicto =====
E(6,"resumen + veredicto");
for(const l of SUM)W("[aio] RES "+l);
const vivas=FAM.filter(f=>VIVA(v1[f[0]])).map(f=>f[0]);
const v=(anyAIO?("AIO VIVA desde sandbox: ["+vivas.join(",")+"] -> FASE SOCKET+AIO OK, pasar a leak 0x2D7="+leak+" y groom osem"):"AIO MUERTA (todas ENOSYS/EX) -> bagagwa no alcanzable desde Y2JB, buscar otro contexto")+" | 0x2D7="+leak+" | wait/poll shapes: "+(SUM[3]||"?");
W("[aio] VEREDICTO: "+v);
N(("[aio] "+v).slice(0,120));
for(let i=0;i<10;i++){N(("[aio] "+v).slice(0,120));for(let j=0;j<3000;j++)syscall(Y);}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
