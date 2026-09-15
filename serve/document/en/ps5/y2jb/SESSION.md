# Y2JB session log (13.40, YT loader :50000, Mac logserver :8080)
Rule: fresh YT relaunch per run series; bases first every boot (ASLR).

## 2026-09-15
- calltest: PASS repeatedly. aio_init=-1(safe), pipe2=0 real fds (27/29, 29/31,
  30/31 across runs), kqueue fd, done. Proves full-arg syscall() path live.
- aioprobe (init matrix [0,0..1,1]): app crash, zero output. Suspect combo [1,0].
- aioreal (valid structs): app crash, zero output. Bisect halves also silent.
- ar_trace (paced): implicated submit; full trace never completed pre-panic.
- 01_sanity (in-repo): PASS (init/pipe/kqueue/done). Missing checkLogServer
  fixed after silent run (log endpoint never configured).
- 02_kex_dry: popup then app death before first POST (async log queue outrun).
- 03_trace (paced micro-steps): CLEAN through pipe2. LK=0x81d92c000 live.
- 04_submit (init+pipe+submit): dies at submit, "struct-ready" last line.
- 05_bundle (one-send all): bases LK=0x83a42c000, init=0, pipe=0 rfd=27,
  kqueue=31, then submit? kills YT. No THREW (native fault, not JS).
- fire_dry.js (assembled head+engine, DRY_RUN): built, never sent (YT burned).

## Standing conclusions
- Y2JB full-arg syscall() works (pipe2/kqueue real results, repeatedly).
- submit(0x295,0,req,1) with lapse-era req layout (fd@0,data@8,len@16)
  crashes the loader process on 13.40. Layout likely moved; engine structs
  (shadow-synced, y2jb_bagagwa.js) remain the untested alternative.
- Never observed: kernel panic (all deaths are app-level), ENOSYS on AIO,
  any [ar]/submit success line.
