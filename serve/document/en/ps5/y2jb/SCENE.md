# Scene status vs our 13.40 box (checked 2026-09-15)
- Full public jailbreak max: **12.70** (Y2JB+P2JB). Nothing public above.
- 13.40: userland only (Y2JB 1.6 supports it; our browser SSV works).
  No public kex. Gezine's zero-day NOT patched at 13.60 — but private.
- Cinebreak (BD-J -> Poopsploit/NetControl -> kexp): offsets listed to 13.52,
  but NetControl bug vintage is 2022-era (<=12.00 class). Offsets != working.
- CSSFontFace (ntfargo): PS5 exploitable only <=8.60. Dead for 13.40.
- Jordy sandbox escape: test page 11.60, maybe newer; needs per-fw offsets.
- New <=13.60 UAF (Sep): lab analysis only, no trigger details.
- Y2JB has per-AppVer ROP sets (01.009.202 vs 01.009.253/min-fw-13.40)
  with DIFFERENT libcobalt gadget RVAs. Know your YT AppVer before trusting
  any ROP table.
- Rule: STAY on 13.40, disable auto-updates. Updating can only close doors.
