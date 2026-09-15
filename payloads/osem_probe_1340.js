// osem_probe v4 — v1 shape (proven: 4x -1 + verdict arrive). No __error (its call/read kills tab).
(async () => {
  const say = async (s) => { try { await log("[osem] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const LK = Number(PS5.libkernelBase||0);
  const OSEM_CREATE = 0x1c070;
  const out = [];
  for(let i=0;i<4;i++){
    const tag = "WAKE000"+i;
    const np = malloc(tag.length+1);
    for(let j=0;j<tag.length;j++) write8(np+BigInt(j), tag.charCodeAt(j)&255);
    write8(np+BigInt(tag.length), 0);
    let r;
    try { r = String(PS5call(LK+OSEM_CREATE, Number(np), 0, "")); }
    catch(e){ r = "THREW"; }
    out.push(tag+"="+r+"@"+hx(np));
  }
  await say("creates: "+out.join(" "));
  await say("VERDICT: all -1 clean (stub alive, args need full caller) | any id>=0 means reclaim LIVE");
  try{ send_notification("osem v4 done"); }catch(e){}
})();
