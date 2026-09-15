// bagagwa_kex_1340.js — from-scratch KEX for 13.40 (replaces partial UAF demo).
// Runs on webkit DIRECT stub-calls (PS5call, no pivot needed).
// Stages use only primitives proven live: 0/1-arg stub calls + R/W + malloc.
// Anything needing full-arg ROP is probed, logged BLOCKED, and skipped —
// no hangs, no panics by default. Destructive UAF fire is gated behind
// CONFIRM=1 (URL ?confirm=1) AND full-arg path available.
// Kernel data offsets wired from payloads/kex_data_1340.js.
(async () => {
  const say = async (s) => { try { await log("[kex] " + s); } catch(e){} };
  const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch(e){ return "?"; } };
  const Q = (()=>{ try{ return new URLSearchParams(location.search); }catch(e){ return {get:()=>null}; } })();
  const CONFIRM = Q.get("confirm")==="1" || Q.get("CONFIRM")==="1";

  await say("begin fw="+(PS5.fw||"?")+" mode="+(PS5.mode||"?")+" libk="+hx(PS5.libkernelBase||0)+" confirm="+CONFIRM);
  const KD = {OFFSET_KERNEL_DATA:0x00CB0000,OFFSET_KERNEL_ALLPROC:0x03589E80,OFFSET_KERNEL_SECURITY_FLAGS:0x01A49064,OFFSET_KERNEL_ROOTVNODE:0x03DE7510,OFFSET_KERNEL_BUS_DATA_DEVICES:0x02D481E8};
  await say("kdata="+(KD?("allproc="+hx(KD.OFFSET_KERNEL_ALLPROC)+" secflags="+hx(KD.OFFSET_KERNEL_SECURITY_FLAGS)+" rootvnode="+hx(KD.OFFSET_KERNEL_ROOTVNODE)):"MISSING"));

  const LK = Number(PS5.libkernelBase||0);
  if(!(LK>0x800000000&&LK<0x900000000)){ await say("ABORT no libkernel base"); return; }
  const stub = (rva, rdi=0, rcx=0, req="") => {
    try { return {ok:true, r:String(PS5call(LK+rva, rdi, rcx, req))}; }
    catch(e){ return {ok:false, e:String(e&&e.message||e).slice(0,60)}; }
  };

  // S0: webkit proof (must pass — proven live before)
  const g = stub(0x1b860);
  await say("S0 getpid -> "+(g.ok?g.r:"THREW "+g.e));
  if(!g.ok){ await say("ABORT webkit stub-call broken"); return; }

  // S1: only init is garbage-safe (proven ret=0 live x3). Other AIO calls take
  // integer count/mode args that land on string-garbage rsi -> huge num ->
  // kernel walks garbage -> panic. They stay SKIPPED until full-arg caller.
  {
    const q = stub(0x1d2e0);
    await say("S1 init="+(q.ok?q.r:"T:"+q.e)+" submit/subcmd/wait/cancel/del=SKIPPED(garbage-num-unsafe) debug727=NOSTUB");
  }

  // S2: 727 leak — needs (req_id, out=OUR buffer). rsi is string-garbage in
  // DIRECT mode, so a real leak is BLOCKED. Probe documents it, no fake success.
  await say("S2 727 leak: BLOCKED — out-pointer must be our malloc, DIRECT gives string-garbage rsi. Need full-arg caller (pivot or Y2JB call).");

  // S3: UAF fire — needs 5-arg wait(ids,num,states,mode,timeout) with real
  // arena pointers. BLOCKED for same reason. Gate destructive path anyway.
  if(!CONFIRM){
    await say("S3 UAF fire: SKIPPED (need ?confirm=1 AND full-arg path). No crash by default. Webkit stays alive.");
  } else if(PS5.mode!=="ROP" || PS5.stubMode!==false){
    await say("S3 UAF fire: REFUSED — confirm=1 set but no classic ROP (mode="+PS5.mode+"). Firing with garbage pointers would panic needlessly.");
  } else {
    await say("S3 UAF fire: classic ROP present — UNIMPLEMENTED in this scaffold (next: port witness/reclaim here).");
  }

  // S4: priv-esc plan (needs arbitrary kernel R/W first — not yet)
  await say("S4 priv-esc: pending kernel R/W. With R/W: allproc walk (+"+hx(KD?KD.OFFSET_KERNEL_ALLPROC:0)+"), secflags clear (+"+hx(KD?KD.OFFSET_KERNEL_SECURITY_FLAGS:0)+"), rootvnode (+"+hx(KD?KD.OFFSET_KERNEL_ROOTVNODE:0)+").");
  await say("VERDICT: webkit STABLE + stub-calls LIVE. Kex blocked on full-arg caller. Next milestone: pivot RVAs (offline) or full-arg call primitive.");
  try{ send_notification("kex scaffold done"); }catch(e){}
})();
