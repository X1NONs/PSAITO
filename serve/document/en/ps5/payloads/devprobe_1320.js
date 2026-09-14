// 2026-08-28 devprobe_1320: ¿es alcanzable desde el sandbox 13.20 el servicio-kernel de decrypt de PUPs? Probe de nodos crypto/pup del devfs NUNCA testeados el 27/08 (los 17 nodos previos no incluían ninguno).
// Base de estilo y canal: p10_rfork_1320.js (W() = TCP crudo síncrono a 192.168.1.67:8081; sockaddr 0x911F:0x4301A8C0). Análisis que motiva la lista: RESEARCH/pup-decrypt-analysis.md — zecoxao/ps5-pup-decrypt abre /dev/pup_update0 (O_RDWR) e ioctl-ea _IOWR('D',1..6) (source/decrypt.c + encryptsrv.c, verificados on-line 2026-08-28). "encryptsrv" es el módulo interno del repo, NO un nodo; se prueba igualmente como candidato barato.
// ABI: SYSCALL.open=0x5(path,flags) SYSCALL.close=0x6(fd) (global.js:254-256); O_RDONLY=0 (mismo patrón que reach_probe_1320.js); errno vía get_error_string() (misc.js:58). Controles: /dev/notification0 (abre, sesión 27/08) y /dev/crypto (ENOENT conocido).
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const SCHED_YIELD=331n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const N=(s)=>{try{send_notification(s)}catch(e){}};
const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1}catch(e){return -1}};
const EM=(e)=>e===2?"ENOENT":e===1?"EPERM":e===13?"EACCES":"errno="+e;
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
W("[dev] devprobe begin pid="+I(syscall(SYSCALL.getpid))+" - probes crypto/pup devfs");
const cands=["/dev/pup_update0","/dev/pup_update","/dev/encryptsrv","/dev/encrypt_srv","/dev/scrypto","/dev/secmgr","/dev/pupsvc","/dev/updatesrv","/dev/crypto0","/dev/sce_sec_apprm","/dev/updsvc","/dev/encsrv","/dev/notification0","/dev/crypto"];
const open_ok=[];
for(const d of cands){
W("DEV: "+d+" - open");
try{const p=alloc_string(d);const fd=I(syscall(SYSCALL.open,p,0n));
if(fd>=0n){W("DEV: "+d+" - ABIERTO fd="+fd+" [EXTRA: el servicio EXISTE y abre en RDONLY]");const c=I(syscall(SYSCALL.close,fd));W("DEV: "+d+" - close ret="+c);if(d!=="/dev/notification0")open_ok.push(d)}
else{const e=EN();W("DEV: "+d+" - fallo fd="+fd+" ("+EM(e)+")")}}
catch(e){W("DEV: "+d+" - EX "+e)}}
const n=open_ok.length;
const v=n>0?(n+" dispositivos crypto abribles: "+open_ok.join(",")):"ninguno abrible (crypto/pup ausentes del devfs del sandbox)";
W("[dev] COMPLETO: "+v);
N("[dev] "+v.slice(0,90));
for(let i=0;i<10;i++){N("[dev] "+v.slice(0,90));for(let j=0;j<2000;j++){syscall(SCHED_YIELD)}}
W("[dev] PAYLOAD DONE");
if(sock>=0n)syscall(SYSCALL.close,sock);
})();
