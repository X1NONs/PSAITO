// slotdump_1340.js — map the fake UCollator for hidden arg slots.
// Own-arena reads only (DIRECT-safe). No libkernel/WebKit-text touches.
(async () => {
  const say = async (s) => { try { await log("[slot] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  await say("begin mode="+(PS5.mode||"?"));
  // Arena base: bridge keeps heap/arena internals private; derive via malloc proximity.
  // malloc returns arena-backed pointers; two mallocs reveal base+offsets relatively.
  const m1 = malloc(8), m2 = malloc(8);
  await say("m1="+hx(m1)+" m2="+hx(m2)+" delta="+(Number(BigInt(m1)-BigInt(m2))));
  // Known layout (bridge.js): fakeCollator=arena+0x100, fakeVtable=arena+0x300.
  // Arena backing unknown here; scan backwards from m1 for "ROP1" sentinel at +0xf00 is overkill.
  // Instead: correlate test — PS5call writes [B+0x48]=rdi mirror. We cannot read B directly,
  // but read64(m1 +/- small) neighbourhood may overlap arena heap (0x2000..0x8000) — dump it.
  const words = [];
  for(let i=0n;i<16n;i++){ try{ words.push(read64(m1+i*8n).toString(16)); }catch(e){ words.push("FAULT"); break; } }
  await say("heap16 @m1: "+words.join(" "));
  // Marker test: write canary via bridge, re-read (proves R/W path, no slots needed)
  try{
    write64(m1, 0x1122334455667788n);
    const back = read64(m1);
    await say("rw-selftest "+(back===0x1122334455667788n?"PASS":"MISMATCH "+hx(back)));
  }catch(e){ await say("rw-selftest THREW"); }
  await say("NOTE: fake-object base addrs are bridge-internal; requesting bridge expose B/V addrs next (1-line change) for direct slot dump.");
  try{ send_notification("slotdump done"); }catch(e){}
})();
