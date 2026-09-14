// 2026-08-28 osem_campaign_1320: campana ABI familia OSEM 0x225-0x22C (8 syscalls: CREATE/DELETE/OPEN/CLOSE/?0x229 no test./TRYWAIT/POST/CANCEL) - roadmap-kernel §2.4: matriz shapes x errnos, mismo metodo IOREQ. Base p10_rfork_1320 (canal W() TCP crudo 192.168.1.67:8081 0x911F/0x4301A8C0, helpers E/R/N/EN()).
// ABI hipotética citada del ledger: CREATE = patron sceKernelCreateSema clasico (name*,attr,init_val,max_val,opt*) 5 args | DELETE/TRYWAIT/POST/CANCEL(id) | OPEN(name,flags). Evidencia previa: CREATE(0,16,1,0x20000)->EINVAL, OPEN(0,1)->EFAULT (desref name), TRYWAIT/POST(0,0)->EINVAL; KSEM 0x194 init(idp*,value) usa id OUT-PARAM -> hipotesis alt: CREATE(name,0,1,1,opt=buf_out_id).
// Reglas: nombres via alloc_string("osemN") (NULL solo donde la shape lo pide), buffers propios con oracle, W ANTES (args) y DESPUES (ret/errno) de cada syscall, sin mmap/thr_new/rfork/read64 de modulos, bucles acotados, <8KB.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const Y=331n,MAXV=0x7FFFFFFFn;
const S_CR=0x225n,S_DL=0x226n,S_OP=0x227n,S_CL=0x228n,S_TW=0x22An,S_PO=0x22Bn,S_CA=0x22Cn;
const EL={1:"EPERM",2:"ENOENT",9:"EBADF",11:"EDEADLK",12:"ENOMEM",14:"EFAULT",16:"EBUSY",17:"EEXIST",22:"EINVAL",28:"ENOSPC",35:"EAGAIN",63:"ENAMETOOLONG",78:"ENOSYS"};
const ELM=(e)=>EL[e]!==undefined?EL[e]:"?";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[osem] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[osem] PASO "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const J=(e)=>" errno="+e+"("+ELM(e)+")";
const FX=(v)=>"0x"+B(v).toString(16);
const HX=(b,n)=>{let x="";for(let i=0;i<n;i++){const v=Number(read8(b+BigInt(i)))&255;x+=(v<16?"0":"")+v.toString(16)+" "}return x};
const VS=(q)=>q.ex?"EX":(q.r>=0n?"ok0x"+q.r.toString(16):"e"+q.e);
// canal W
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[osem] inicio - canal "+(sock>=0n?"OK":"MUERTO")+" - OSEM 0x225-0x22C shapes x errnos");
const NM0=alloc_string("osem0"),NM1=alloc_string("osem1");
const SUM=[];
// runner: W ANTES con args (crash => la ultima W delat la shape), syscall, W DESPUES con ret/errno.
const SC=(tag,sc,args,desc)=>{const p=tag+(desc?" "+desc:"")+" ("+args.map(FX).join(",")+")";W(p+" ...");
 const o={r:-9999n,e:-1,ex:false};
 try{o.r=I(syscall(sc,...args.map((a)=>B(a))));if(o.r<0n)o.e=EN();}catch(err){o.ex=true;W(p+" -> EXCEPCION "+err);return o;}
 W(p+" -> "+(o.r>=0n?"ret=0x"+o.r.toString(16)+" OK":o.r+J(o.e)));
 return o;};
// ===== PASO 1: shapes CREATE 0x225, en orden =====
E(1,"CREATE 0x225 x7 shapes hipotesis (name*,attr,init,max,opt*)");
const CS=[["S1","(nm,0,1,1,0) basica",[NM0,0n,1n,1n,0n]],
["S2","(nm,0x10,1,MAX,0) attr 0x10",[NM0,0x10n,1n,MAXV,0n]],
["S3","(NULL,0,1,1,0) name NULL",[0n,0n,1n,1n,0n]],
["S4","(nm,0,0,0,0) init0/max0",[NM0,0n,0n,0n,0n]],
["S5","(nm,0x10,MAX,MAX,0) init=max",[NM0,0x10n,MAXV,MAXV,0n]],
["S6","4args (nm,0,1,1) sin opt",[NM0,0n,1n,1n]],
["S7","(nm1,0,1,1,0) repite osem1",[NM1,0n,1n,1n,0n]]];
let okShape=null,createId=null;const cerrs=[];
for(const s of CS){const q=SC("CREATE_"+s[0],S_CR,s[2],s[1]);
 cerrs.push(s[0]+"="+(q.r>=0n?"OK":"e"+q.e));
 if(q.r>=0n&&createId===null){okShape=s;createId=q.r;
  W(">>> CREATE_"+s[0]+" PRIMER OK: ret=0x"+q.r.toString(16)+" (posible id/cap). Ultimo arg de esta shape = 0 (NO buffer) -> sin oracle out aqui, ret registrado como id.");}}
R(1,"create: "+cerrs.join(" ")+(createId!==null?" | first_ok con id=0x"+createId.toString(16):" | NINGUN ok"));
const all22=createId===null&&cerrs.length===7&&cerrs.every(c=>c.endsWith("=e22"));
SUM.push("CREATE(0x225): "+cerrs.join(" "));
// ===== PASO 2: cadena ciclo de vida (solo si CREATE dio ret>=0) =====
let chain="SKIPPED (ningun CREATE dio id)";
if(createId!==null){
 E(2,"cadena ciclo de vida con id=0x"+createId.toString(16));
 const qd=SC("DELETE_0x226",S_DL,[createId],"(id)");
 const qc=SC("CREATE_"+okShape[0]+"_RETRY",S_CR,okShape[2],"(recreate para dejar uno vivo)");
 if(qc.r>=0n){
  W("recreate ok: id_vivo=0x"+qc.r.toString(16));
  const qt=SC("TRYWAIT_0x22A",S_TW,[qc.r],"(id_vivo)");
  const qp=SC("POST_0x22B",S_PO,[qc.r],"(id_vivo)");
  const qz=SC("CLOSE_0x228",S_CL,[qc.r],"(id_vivo)");
  chain="del="+VS(qd)+" recreate=ok tw="+VS(qt)+" post="+VS(qp)+" close="+VS(qz);
 }else chain="del="+VS(qd)+" recreate="+VS(qc)+" (TRYWAIT/POST/CLOSE skip: sin id vivo)";
 R(2,chain);
}else{E(2,"cadena ciclo de vida");R(2,"SKIPPED (ningun CREATE dio id)")}
SUM.push("CADENA: "+chain);
// ===== PASO 3: hipotesis out-param (ningun CREATE dio id) =====
let outpDesc="n/a (create dio id)";
if(createId===null){
 E(3,"hipotesis out-param: CREATE(nm,0,1,1,opt=buf_out_id) + oracle optbuf");
 R(3,"errnos por shape: "+cerrs.join(" ")+" | todos 22(EINVAL)? "+(all22?"SI":"NO"));
 const OB=malloc(8);write64(OB,0x0BADC0DE0BADC0DEn);
 const qo=SC("CREATE_outparam",S_CR,[NM0,0n,1n,1n,OB],"(opt=malloc(8) con centinela)");
 let v=0n,fault=false;
 try{v=BigInt.asUintN(64,BigInt(read64(OB)))}catch(err){fault=true}
 const post=fault?"LECTURA FAULT":(HX(OB,8)+" "+(v===0x0BADC0DE0BADC0DEn?"IGNIDO (kernel no escribio -> no out-param ahi)":"CAMBIADO !! (kernel escribio optbuf -> out-param existe, contenido arriba)"));
 W("oracle optbuf post-call: "+post);
 outpDesc=VS(qo)+" buf="+(fault?"fault":(v===0x0BADC0DE0BADC0DEn?"ignido":"CAMBIADO:"+HX(OB,8)));
 SUM.push("OUTPARAM: "+outpDesc);
}else{E(3,"hipotesis out-param");R(3,"SKIPPED (CREATE ya dio id con opt=0)")}
// ===== PASO 4: shapes OPEN 0x227 =====
E(4,"OPEN 0x227 x3: (nm,0) | (nm,1) | (NULL,0) - S1 previo: (0,1)->EFAULT sugiere desref name");
const o1=SC("OPEN_0x227",S_OP,[NM0,0n],"(nm,0)");
const o2=SC("OPEN_0x227",S_OP,[NM0,1n],"(nm,1)");
const o3=SC("OPEN_0x227",S_OP,[0n,0n],"(NULL,0)");
R(4,"open: "+VS(o1)+" / "+VS(o2)+" / "+VS(o3));
SUM.push("OPEN(0x227): nm,0="+VS(o1)+" nm,1="+VS(o2)+" NULL,0="+VS(o3));
// ===== PASO 5: resto de la familia con id=1 e id=0 =====
E(5,"familia con id=1 e id=0 (aunque CREATE no haya dado id) - buscar errnos distintos de 22");
const FIVE=[["TRYWAIT",S_TW],["POST",S_PO],["CANCEL",S_CA],["DELETE",S_DL],["CLOSE",S_CL]];
const byId={};
for(const idv of [1n,0n]){const rr=[];
 for(const f of FIVE){const q=SC(f[0]+"_0x"+f[1].toString(16),f[1],[idv],"(id="+idv+")");rr.push(f[0]+"="+VS(q));}
 byId[Number(idv)]=rr;R(5,"id="+idv+": "+rr.join(" "));}
SUM.push("ID1: "+byId[1].join(" "));
SUM.push("ID0: "+byId[0].join(" "));
// ===== PASO 6: resumen + veredicto =====
E(6,"resumen + veredicto");
for(const l of SUM)W("[osem] RES "+l);
const cdesc=createId!==null?("OK id=0x"+createId.toString(16)):(all22?"EINVAL(22) x7":cerrs.join(" "));
const v="OSEM: create="+cdesc+" | outp="+outpDesc+" | open="+VS(o1)+"/"+VS(o2)+"/"+VS(o3)+" | id1=["+byId[1].join(" ")+"] id0=["+byId[0].join(" ")+"]";
W("[osem] VEREDICTO: "+v);
N(("[osem] "+v).slice(0,120));
for(let i=0;i<10;i++){N(("[osem] "+v).slice(0,120));for(let j=0;j<3000;j++)syscall(Y);}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
