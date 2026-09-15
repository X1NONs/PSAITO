// worker_ping_1340.js — positive control: worker echo x5 over ~10s. No reads/writes/hijack.
// Survives => workers+OOM fine, hijack writes are the killer. Dies => environmental.
(async () => {
  const say = async (s) => { try { await log("[wping] " + s); } catch(e){} };
  let worker = null;
  try{
    worker = new Worker("payloads/worker_slave.js");
  }catch(e){ await say("ABORT create"); return; }
  for(let i=0;i<5;i++){
    let ok = false;
    try{
      await Promise.race([new Promise((res)=>{worker.onmessage=()=>res(1);worker.postMessage(i);}),
        new Promise((_,rej)=>setTimeout(()=>rej(new Error("t/o")),2000))]);
      ok = true;
    }catch(e){}
    await say("ping"+i+" "+(ok?"ECHO":"TIMEOUT"));
    await new Promise((r)=>setTimeout(r,1500));
  }
  await say("DONE worker alive 10s+");
  try{ send_notification("wping done"); }catch(e){}
})();
