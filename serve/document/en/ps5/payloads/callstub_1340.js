// callstub_1340.js — DIRECT-mode stub calls via PS5call (no pivot, no ROP).
// Uses X1NON-verified stub RVAs + validated libkernelBase from handoff.
// 0-arg/small-arg calls only: getpid (expect pid), aio_init(0,0) (expect -1/EFAULT, NOT ENOSYS).
(async () => {
  const say = async (s) => { try { await log("[cs1340] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  await say("begin mode=" + (PS5.mode||"?") + " libk=" + hx(PS5.libkernelBase||0) + " fw=" + (PS5.fw||"?"));
  const LK = Number(PS5.libkernelBase);
  if(!(LK > 0x800000000 && LK < 0x900000000)){ await say("no libkernel base, stop"); return; }
  const call0 = (rva) => {
    const t = LK + rva;
    try { const r = PS5call(t, 0, 0, ""); return {ok:true, r:String(r)}; }
    catch(e){ return {ok:false, e:String(e&&e.message||e).slice(0,80)}; }
  };
  // X1NON-verified RVAs (same as your table)
  const R = { getpid:0x1b860, aio_init:0x1d2e0, socketpair:0x1b400, write:0x1b640, close:0x1d200 };
  for(const [n,rva] of Object.entries(R)){
    const q = call0(rva);
    await say(n+"(base+0x"+rva.toString(16)+") -> "+(q.ok?q.r:"THREW "+q.e));
  }
  await say("DONE — getpid=number means stub-call path works; aio_init refused (not ENOSYS) means AIO reachable");
  try{ send_notification("cs1340 done"); }catch(e){}
})();
