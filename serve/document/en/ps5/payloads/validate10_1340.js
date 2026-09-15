// validate10 — 10 single reads at X1NON-verified gadget RVAs (mapped .text).
// If these survive, WebKit reads are safe at known addrs and we scan outward
// from one for pivot. If this kills the tab, on-console WebKit reading is dead.
(async () => {
  const say = async (s) => { try { await log("[v10] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const WK = Number(PS5.webkitBase||0);
  await say("begin wk="+hx(WK));
  const G = {ret:0xc7,poprdi:0x288b2,poprsi:0x1ee7a,poprdx:0xfa7a2,poprcx:0x80597,poprax:0x3c98e,poprsp:0xa1138,popr8:0x8ce7c,popr9:0x80596,store:0x3881f};
  const EXP = {ret:0xc3,poprdi:0x5f,poprsi:0x5e,poprdx:0x5a,poprcx:0x59,poprax:0x58,poprsp:0x5c,popr8:0x41,popr9:0x41,store:0x48};
  const res = [];
  for(const [n,rva] of Object.entries(G)){
    let v;
    try { v = (Number(read8(WK+rva))&255).toString(16); }
    catch(e){ v = "THREW"; }
    res.push(n+"="+v+"(exp"+EXP[n].toString(16)+")");
  }
  await say("reads: "+res.join(" "));
  await say("VERDICT: all-exp-match => WebKit reads safe at known RVAs, scan outward next | THREW/fault => on-console reading dead");
  try{ send_notification("v10 done"); }catch(e){}
})();
