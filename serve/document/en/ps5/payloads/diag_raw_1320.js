// 2026-08-27 diag-mem por TCP CRUDO sync (write), no log().
// log() encola en rAF y muere con el proceso (XOM/SAR); write() sync sale ya.
// 10 pasos identicos a diag_mem_1320_min.js; solo cambia canal.
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[diag] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[diag] PASO "+n+" result: "+v);
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
let Rd=-1n,Wr=-1n,Sh=0n,F5={f:null};
E(1,"getpid (baseline runtime vivo)");try{const p=I(syscall(SYSCALL.getpid));R(1,"pid="+p)}catch(e){R(1,"EX "+e)}
E(2,"pipe(fds)");try{const f=malloc(8),r=I(syscall(SYSCALL.pipe,f));if(r<0n)R(2,"ERR "+get_error_string());else{Rd=BigInt.asIntN(32,read32(f));Wr=BigInt.asIntN(32,read32(f+4n));Sh=malloc(16);R(2,"ok Rd="+Rd+" Wr="+Wr)}}catch(e){R(2,"EX "+e)}
const Pr=(a)=>{if(Wr<0n)return{d:"SIN PIPE",f:null};const r=I(syscall(SYSCALL.write,Wr,a,1n));if(r<0n){let s="errno?";try{s=get_error_string()}catch(x){s="errstr EX "+x}return{d:"ERR "+s,f:/^14(\s|$)/.test(s)||/EFAULT/.test(s)}}try{syscall(SYSCALL.read,Rd,Sh,1n)}catch(x){}return{d:"legible "+r+"B",f:false}}
E(3,"control pipe-probe heap malloc (esperado ok)");try{const c=malloc(64);write64(c,0x4141414141414141n);if(Wr<0n)R(3,"SKIPPED sin pipe");else{const p=Pr(c);R(3,p.d+(p.f?" -> METODO ROTO":" -> ok"))}}catch(e){R(3,"EX "+e)}
E(4,"leer global libc_base (sin leer)");try{if(typeof libc_base==="undefined")R(4,"libc_base NO EXISTE");else R(4,"libc_base="+toHex(B(libc_base)))}catch(e){R(4,"EX "+e)}
E(5,"pipe-probe write(pipeWr, libc_base, 1)");try{if(typeof libc_base==="undefined")R(5,"SKIPPED");else{const a=B(libc_base),p=Pr(a);F5.f=p.f;R(5,p.d+(p.f===true?" -> NO LEGIBLE (EFAULT)":p.f===false?" -> LEGIBLE":""))}}catch(e){R(5,"EX "+e)}
E(6,"read64(libc_base) (si PASO 5 sin EFAULT)");try{if(typeof libc_base==="undefined")R(6,"SKIPPED");else if(F5.f===true)R(6,"SKIPPED (P5=EFAULT)");else{const q=read64(B(libc_base));R(6,toHex(q)+((q&0xffffffffn)===0x464c457fn?" ELF OK":" NO ELF"))}}catch(e){R(6,"EX "+e)}
E(7,"pipe-probe libc_base+0x4000 (+read64 si legible)");try{if(typeof libc_base==="undefined")R(7,"SKIPPED");else{const a=B(libc_base)+0x4000n,p=Pr(a);let x="";if(p.f===false){try{x=" | read64="+toHex(read64(a))}catch(e){x=" | read64 EX "+e}}R(7,p.d+" en "+toHex(a)+x)}}catch(e){R(7,"EX "+e)}
E(8,"eboot_base / libstarboard_base (sin leer)");try{const P=[];try{P.push("eb="+(typeof eboot_base==="undefined"?"NO EXISTE":toHex(B(eboot_base))))}catch(e){P.push("eb EX "+e)}try{P.push("sb="+(typeof libstarboard_base==="undefined"?"NO EXISTE":toHex(B(libstarboard_base))))}catch(e){P.push("sb EX "+e)}R(8,P.join("|"))}catch(e){R(8,"EX "+e)}
E(9,"getpid final + send_notification");try{const p=I(syscall(SYSCALL.getpid));R(9,"pid="+p);W("[diag] COMPLETO: consola viva");try{send_notification("[diag] done")}catch(e){}}catch(e){R(9,"EX "+e)}
E(10,"close(pipeRd), close(pipeWr)");try{if(Rd>=0n)syscall(SYSCALL.close,Rd);if(Wr>=0n)syscall(SYSCALL.close,Wr);if(sock>=0n)syscall(SYSCALL.close,sock);R(10,"fds cerrados ("+Rd+","+Wr+","+sock+")")}catch(e){R(10,"EX "+e)}
})();
