// 2026-08-28 osem2_1320: SESION 2 OSEM - ciclo de vida DUAL id/nombre 0x225-0x22C: T1 dup-create | T2 open-tras-create | T3 doble-delete id+nombre (candidato double-free) | T4 valores extremos | T5 nombres limite | T6 gate CLOSE. Base osem_campaign_1320 (canal W() TCP crudo 192.168.1.67:8081 0x911F/0x4301A8C0, runner SC(tag,sc,args,desc) con W antes/despues).
// Hallazgos SESION 1: CREATE(0x225) shape ganadora (name*,0,1,1,0) 4-5 args = OK id REAL=0x61ab (attr=0x10 o MAX grandes -> EINVAL; 4-args y "osem1" tambien ok) | DELETE(0x226,id)=ok, recreate=ok | CLOSE(0x228,id)=e1 EPERM (gate) | TRYWAIT(0x22A)/POST(0x22B) sobre id vivo=e22 EINVAL.
// Clave ses2: OPEN(0x227,name,0)=ESRCH en ses1 solo porque corrio TRAS el delete -> busca por NOMBRE; explotar dualidad id/nombre. Reglas: W antes+despues de cada syscall, limpieza final DELETE ids vivos, sin mmap/thr_new/rfork/read64 modulos, bucles acotados, <9KB.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const Y=331n,MAXV=0x7FFFFFFFn;
const S_CR=0x225n,S_DL=0x226n,S_OP=0x227n,S_CL=0x228n,S_TW=0x22An;
const EL={1:"EPERM",2:"ENOENT",3:"ESRCH",14:"EFAULT",16:"EBUSY",17:"EEXIST",22:"EINVAL",63:"ENAMETOOLONG"};
const ELM=(e)=>EL[e]||"?";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[osem2] PASO "+n+": "+s),R=(n,v)=>W("[osem2] PASO "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const J=(e)=>" errno="+e+"("+ELM(e)+")";
const FX=(v)=>"0x"+B(v).toString(16);
const VS=(q)=>q.ex?"EX":(q.r>=0n?"ok0x"+q.r.toString(16):"e"+q.e);
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[osem2] inicio - canal "+(sock>=0n?"OK":"MUERTO")+" - sesion2 ciclo dual id/nombre");
const SUM=[];
// runner: W ANTES, syscall, W DESPUES ret/errno.
const SC=(tag,sc,args,desc)=>{const p=tag+(desc?" "+desc:"")+" ("+args.map(FX).join(",")+")";W(p+" ...");
 const o={r:-9999n,e:-1,ex:false};
 try{o.r=I(syscall(sc,...args.map((a)=>B(a))));if(o.r<0n)o.e=EN();}catch(err){o.ex=true;W(p+" -> EXCEPCION "+err);return o;}
 W(p+" -> "+(o.r>=0n?"ret=0x"+o.r.toString(16)+" OK":o.r+J(o.e)));
 return o;};
// vivos para limpieza + CREATE shape ganadora (nm,0,1,1,0)
const ALIVE=[];
const kill=(id)=>{for(const a of ALIVE){if(a.id===id)a.dead=true}};
const alive=(id)=>{for(const a of ALIVE){if(a.id===id)return !a.dead}return false};
const CR=(tag,nm,desc)=>{const q=SC(tag,S_CR,[nm,0n,1n,1n,0n],desc);if(q.r>=0n)ALIVE.push({id:q.r,dead:false});return q;};
// ===== T1: CREATE duplicado mismo nombre =====
E(1,"T1 CREATE duplicado 'dup0' - colision de namespace?");
const NMD=alloc_string("dup0");
const t1a=CR("T1.CREATE_A",NMD,"(dup0,0,1,1,0) primera vez");
const t1b=CR("T1.CREATE_B",NMD,"(dup0,0,1,1,0) 2da vez");
let dupV="no";
if(t1a.r>=0n&&t1b.r>=0n){
 dupV=(t1a.r===t1b.r)?"same_id":"2ids_mismo_nombre";
  W("[osem] T1 AMBOS OK idA=0x"+t1a.r.toString(16)+" idB=0x"+t1b.r.toString(16)+(t1a.r===t1b.r?" -> mismo id devuelto (duplicado idempotente)":" -> DOS ids DISTINTOS mismo nombre = COLISION NAMESPACE"));
}else W("[osem] T1 sin duplicado vivo: A="+VS(t1a)+" B="+VS(t1b));
R(1,"dup-names="+dupV+" A="+VS(t1a)+" B="+VS(t1b));
SUM.push("T1 dup-names="+dupV+" A="+VS(t1a)+" B="+VS(t1b));
// ===== T2: OPEN tras CREATE (objeto VIVO) =====
E(2,"T2 OPEN tras CREATE 'open0' - ses1 abrio tras delete; ahora el objeto esta vivo");
const NMO=alloc_string("open0");
const t2c=CR("T2.CREATE",NMO,"(open0,0,1,1,0)");
const t2o=SC("T2.OPEN",S_OP,[NMO,0n],"(open0,0) CON OBJETO VIVO");
let openV=t2o.r>=0n?"abre":"e"+t2o.e;
if(t2o.r>=0n){
 const same=t2c.r>=0n&&t2o.r===t2c.r;
 openV=same?"abre_id_igual":"abre_handle_distinto";
  W("[osem] T2 OPEN OK handle=0x"+t2o.r.toString(16)+" vs id_create="+(t2c.r>=0n?"0x"+t2c.r.toString(16):"sin_id")+(same?" -> handle==id (reexpone mismo id)":" -> handle!=id: DOBLE HANDLE sobre el MISMO objeto"));
}else W("[osem] T2 OPEN no abrio con objeto vivo: "+VS(t2o));
R(2,"opens="+openV);
SUM.push("T2 open-tras-create="+openV+" create="+VS(t2c)+" open="+VS(t2o));
// ===== T3: doble DELETE id+nombre - cadena double-free CONDICIONAL =====
// ⚠ si CRASHEA = hallazgo double-free REAL potential; la ultima W antes del silencio identifica el paso.
E(3,"T3 doble DELETE id+nombre 'dbl0' - del(id) x2, OPEN(nombre), del(handle)=double-free?, TRYWAIT post-free");
const NMB=alloc_string("dbl0");
const t3c=CR("T3.CREATE",NMB,"(dbl0,0,1,1,0)");
let ddV="skip(create_fallo)",t3sum="create="+VS(t3c);
if(t3c.r>=0n){
  const t3d1=SC("T3.DELETE1_id",S_DL,[t3c.r],"(id 1ra vez)");if(t3d1.r>=0n)kill(t3c.r);
  const t3d2=SC("T3.DELETE2_id",S_DL,[t3c.r],"(MISMO id 2da vez - esperado ESRCH)");
  const t3o=SC("T3.OPEN_nombre",S_OP,[NMB,0n],"(dbl0,0) TRAS DELETE por id - nombre vivo?");
  t3sum="del1="+VS(t3d1)+" del2="+VS(t3d2)+" open="+VS(t3o);
  if(t3o.r>=0n){
   W("[osem] T3 !! OPEN('dbl0') dio handle=0x"+t3o.r.toString(16)+" tras DELETE(id) -> NOMBRE VIVO: ventana id/nombre");
   const t3d3=SC("T3.DELETE3_handle",S_DL,[t3o.r],"(DELETE del handle re-abierto = INTENTO DOBLE LIBERACION)");
   ddV=t3d3.r>=0n?"double_free_OK":"df_e"+t3d3.e;
   const t3t=SC("T3.TRYWAIT_muerto",S_TW,[t3o.r],"(handle muerto post-free - si muere aqui => doble free REAL)");
   t3sum+=" del_handle="+VS(t3d3)+" trywait_postfree="+VS(t3t);
  }else{ddV="name_dead_ok";W("[osem] T3 nombre 'dbl0' MUERTO tras delete (open="+VS(t3o)+") -> sin ventana por nombre; del2="+VS(t3d2))}
 }
 R(3,"double-del="+ddV);
SUM.push("T3 double-del="+ddV+" ["+t3sum+"]");
// ===== T4: valores extremos CREATE (validacion init/max) =====
E(4,"T4 valores extremos CREATE - init=0 | max=0 | init>max | negativos int32 (0xFFFFFFFFn y -1n)");
const EXT=[["V1_init0","x1","init=0,max=1",[0n,0n,1n,0n]],
["V2_max0","x2","init=1,max=0",[0n,1n,0n,0n]],
["V3_initGtMax","x3","init=0x7FFFFFFF max=1",[0n,MAXV,1n,0n]],
["V4_neg32","x4","init=max=0xFFFFFFFF(int32-1)",[0n,0xFFFFFFFFn,0xFFFFFFFFn,0n]],
["V5_neg1lit","x5","init=max=-1n literal",[0n,-1n,-1n,0n]]];
const ev=[];
for(const t of EXT){const q=SC("T4."+t[0],S_CR,[alloc_string(t[1])].concat(t[3]),"("+t[2]+")");
 if(q.r>=0n)ALIVE.push({id:q.r,dead:false});
 ev.push(t[0]+"="+(q.r>=0n?"OK:0x"+q.r.toString(16):"e"+q.e+"("+ELM(q.e)+")"));}
const extV=ev.join(" ");
R(4,"extremos: "+extV);
SUM.push("T4: "+extV);
// ===== T5: nombre largo (200) y vacio =====
E(5,"T5 nombre 200 chars y nombre vacio");
let LN="";for(let i=0;i<200;i++)LN+="A";
const t5l=CR("T5.LONG",alloc_string(LN),"(200xA,0,1,1,0)");
const t5z=CR("T5.EMPTY",alloc_string(""),"(\"\",0,1,1,0)");
const nmV="long200="+(t5l.r>=0n?"OK:0x"+t5l.r.toString(16):"e"+t5l.e+"("+ELM(t5l.e)+")")+" empty="+(t5z.r>=0n?"OK:0x"+t5z.r.toString(16):"e"+t5z.e+"("+ELM(t5z.e)+")");
W("[osem] T5: "+nmV+(t5l.r>=0n?" -> 200 chars ACEPTADO":" -> limite rechaza (errno arriba)"));
R(5,nmV);
SUM.push("T5 "+nmV);
// ===== T6: CLOSE del vivo - gate EPERM =====
E(6,"T6 CLOSE del vivo 'keep0' - si TRYWAIT sigue e22, unico close funcional = DELETE; confirmar gate EPERM");
const NMK=alloc_string("keep0");
const t6c=CR("T6.CREATE",NMK,"(keep0,0,1,1,0)");
let clV="create_fallo";
if(t6c.r>=0n){
 const t6t=SC("T6.TRYWAIT",S_TW,[t6c.r],"(id_vivo - CLOSE solo si da ok)");
 if(t6t.r>=0n){const q=SC("T6.CLOSE_postwait",S_CL,[t6c.r],"(CLOSE tras TRYWAIT ok)");clV="trywait=ok close="+VS(q);if(q.r>=0n)kill(t6c.r);}
 else{const q=SC("T6.CLOSE_directo",S_CL,[t6c.r],"(id_vivo directo - ses1 dio e1)");
  clV="trywait=e"+t6t.e+" close="+VS(q)+(q.e===1?" CONFIRMA GATE EPERM en CLOSE(0x228)":"");}
 if(alive(t6c.r)){const qd=SC("T6.DELETE_final",S_DL,[t6c.r],"(unico cierre funcional)");if(qd.r>=0n)kill(t6c.r);clV+=" delete="+VS(qd);}
}
R(6,"close="+clV);
SUM.push("T6 close="+clV);
// ===== limpieza: DELETE de ids vivos =====
E(7,"LIMPIEZA: DELETE ids vivos restantes ("+ALIVE.filter(a=>!a.dead).length+" vivos)");
const cln=[];
for(const a of ALIVE){if(a.dead)continue;const q=SC("CLEAN.DELETE",S_DL,[a.id],"(id=0x"+a.id.toString(16)+")");cln.push("0x"+a.id.toString(16)+"="+VS(q));}
R(7,"cleanup: "+(cln.length?cln.join(" "):"nada vivo"));
SUM.push("CLEAN: "+(cln.length?cln.join(" "):"nada"));
// ===== resumen + veredicto + cuenta atras =====
E(8,"resumen + veredicto");
for(const l of SUM)W("[osem2] RES "+l);
const v="OSEM2: dup-names="+dupV+" opens="+openV+" double-del="+ddV;
W("[osem2] VEREDICTO: "+v+" | "+extV+" | "+nmV+" | "+clV);
N(("OSEM2: dup-names="+dupV+" opens="+openV+" double-del="+ddV).slice(0,120));
for(let i=100;i>=1;i--){N(("OSEM2 T-"+i+" dup="+dupV+" open="+openV+" ddel="+ddV).slice(0,120));for(let j=0;j<1200;j++)syscall(Y);}
W("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock)}catch(e){}
})();
