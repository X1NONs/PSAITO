# PSAITO

> **Experimental research project for educational and research purposes
> only.** Use exclusively on hardware you own and control. No warranty of
> any kind; you are responsible for how you use it. This project does not
> enable piracy or access to content you are not entitled to.

PSAITO is an experimental WebKit research toolkit for PlayStation 5 system
software **09.00 → 13.60**, created by **Wamphyre** as a study of browser
engine memory management. It demonstrates how far a purely web-based
runtime environment can be characterized and instrumented for analysis.

After the demonstration completes, PSAITO provides a small JavaScript
runtime API (`malloc`, `read/write`, `syscall`, notifications) plus an
on-screen payload panel, so analysis routines (`.js` probes) can be loaded
and executed directly from GitHub — no PC, cables or extra tooling needed.
The default routine is `bagagwa_uaf_1320.js` (the BAGAGWA `aio_multi_wait`
mode 0 UAF); other probes can be selected from the panel.

## Usage (PS5)

1. On the PS5, set the Internet connection to **manual DNS**:
   - Primary DNS: `62.210.38.117`
   - Secondary DNS: `0.0.0.0`
2. Open the PS5 web browser (guide entry point).
3. Visit the toolkit URL: **<https://wamphyre.github.io/PSAITO/>**
4. Press **Launch** — wait for the runtime panel; the default probe starts
   automatically and prints its results.

> **Warning**: the default auto-run is `bagagwa_uaf_1320.js`, which **fires a
> kernel UAF** and can hang/panic the console. For a first, non-destructive
> check use `?auto=hello_1320.js` (canary) or `?auto=aio_reach_1320.js`
> (AIO reachability gate).

Optional URL params (all of them propagate from `index.html` to `runtime.html`):
append them to <https://wamphyre.github.io/PSAITO/>, e.g.
`https://wamphyre.github.io/PSAITO/?max=3&rd=3000&auto=hello_1320.js`.
- `?auto=<file.js>` — auto-run routine (`auto=0` disables; default
  `bagagwa_uaf_1320.js`)
- `?pb=<base>` — payload base URL (default same-origin `payloads/`)
- `?logserver=<url>` — remote log endpoint (see **Console log** below)
- `?rop=0` — force bridge **DIRECT** mode (skip libkernel .text gadget scan)
- `?log=0` / `?log=1` — force disable/enable remote log
- `?max=<n>` — attempt ceiling (**default 5**; `0` = endless). The exploit
  retries on failure; each attempt reallocates ~100-200 MB, so an endless loop
  saturates WebKit's process memory and the system shows a repeated
  "not enough memory" dialog that hides the on-screen log. Keep the default
  (or lower) while testing.
- `?rd=<ms>` — delay between attempts (default 50 ms)
- `?n=<count>` — drain allocations per attempt (default 512, min 64)
- `?cap=<ms>` / `?gap=<ms>` — capture/compose delays (default 50 ms + gap)
- `?lines=<n>` — `#scr` history kept on screen (default 200)

### On-console log & USB

The bridge **and** the payloads write to the on-screen panel (`#plg`), to the
main runtime log (`#scr`) and to a full in-memory buffer that is not truncated.
The panel is **visible from the start** (state `waiting for bridge…`) and does
not depend on the exploit succeeding, so the log controls stay reachable even
if the exploit loops on memory failures. It exposes `RUN`, `RESET`, `STOP`,
`DOWNLOAD LOG` and `CLEAR`; plus a fixed **DOWNLOAD LOG** button at the bottom
right of the screen (independent of the panel). `STOP` halts the retry loop
without reloading.

- **DOWNLOAD LOG** — downloads the whole buffer as `psaito_log_<timestamp>.txt`
  (via `Blob` + `a[download]`); lands in the console's download area.
- **CLEAR** — clears the buffer.

The buffer is also mirrored to `localStorage`, so it survives a page/app restart
(Y2JB startup may reload the tab). On reopen the previous log is replayed at the
top of the panel. The exploit's own log (`#scr`) is captured into the same
buffer via a MutationObserver.

Both `#scr` and the panel `#plg` keep a long history and scroll independently
(200+ and 1000 lines kept on screen). Scrolling uses **sticky auto-follow**: new
lines only snap to the bottom if you are already at the bottom, so you can
scroll up and read earlier output while the exploit keeps logging.

Writing the log to a **USB drive** is not possible from the browser sandbox:
`payloads/usb_probe_1320.js` probes 24 USB/mount paths (`/mnt/usb*`, `/media`,
`/external`, …) and, without a kernel escape (which this toolkit does not
attempt), the sandbox never exposes them. Run it to confirm on your firmware;
the verdict is printed to the panel.

## Console execution (13.00 → 13.60) — procedure

This section is the operational checklist for a real console run. Two pieces
matter beyond the toolkit itself: a **remote log endpoint** on your PC and the
**offset profile** the exploit will try. All 13.XX offsets (WebKit GOT,
libkernel `gd`/`nt`, exports) are **X1NON-verified** — see section 4.

### 0. Publish

The toolkit is a static site; serve the contents of this directory from the
**root** of your GitHub Pages deployment. No PC server is needed for the site
itself (the PS5 loads it over the system browser).

### 1. Remote log (recommended; the on-screen log is lossy)

The exploit and the bridge POST each log line to a `log_server.py` on your PC.
Run it before launching (no dependencies, Python 3 stdlib only):

```
python3 DEMO/log_server.py      # listens on 0.0.0.0:8080, prints timestamped lines
python3 DEMO/log_server.py 9000 # optional: alternate port
```

Allow inbound TCP 8080 through your PC firewall, and make sure the PC and the
PS5 are on the same LAN.

The default endpoint is `http://<page-host>:8080/log`, which resolves to the
PC only if the PC is the DNS/page host. **With GitHub Pages the page host is
`*.github.io`, so you MUST pass your PC IP explicitly**:

```
?logserver=http://<PC-IP>:8080/log
```

The setting propagates from `index.html` to `runtime.html`, or can be set
directly on the runtime URL. Without it, logs still go to screen (`#scr`) and
notifications, but the XHR just 404s silently.

### 2. First run: validate the exploit before payloads

Launch with the canary as the auto-run to confirm the WebKit exploit completes
and the bridge boots:

```
https://wamphyre.github.io/PSAITO/?log=1&logserver=http://<PC-IP>:8080/log&auto=hello_1320.js&max=3&rd=3000
```

Expected: `runtime.html` shows `*** SUCCESS ***`, the panel appears with
`fw 13.xx · mode ROP` (or `ROP (X1NON stubs)` / `DIRECT`), and the PC log
receives `BRIDGE-BOOT fw=13.xx ...`. `hello_1320.js` then logs
`getpid ok = 0x...`.

### 3. Second run: the real payload

PSAITO is **two sequential stages**: (1) the WebKit exploit in `exploit.js`
gets the browser-process RW primitive and publishes `window.__PS5_CTX` +
`onUserland()`; (2) the payload runs inside that runtime and uses `syscall()`.
A payload **cannot run before stage 1 succeeds** — `onBridgeReady` (and the
auto-run 1.5 s later) only fires after `*** SUCCESS ***`.

Once the canary passes, the default (`bagagwa_uaf_1320.js`) fires the BAGAGWA
`aio_multi_wait` mode 0 UAF (see 3b). A lighter alternative to first confirm
AIO reachability is `aio_reach_1320.js`:

```
https://wamphyre.github.io/PSAITO/?log=1&logserver=http://<PC-IP>:8080/log&max=3&rd=3000&auto=aio_reach_1320.js
```

`aio_reach` prints `PASO` lines and a final `VEREDICTO: AIO VIVA` /
`AIO MUERTA (todas ENOSYS/EX)`. If `AIO MUERTA`, the BAGAGWA chain is dead from
the Y2JB sandbox and only the reachability result matters.

### 3b. BAGAGWA UAF (`bagagwa_uaf_1320.js`)

Once AIO is reachable, `bagagwa_uaf_1320.js` **fires** the deterministic
`aio_multi_wait` **mode 0** UAF (`syscall 0x297` / 663): with `num >= 2` it links
the same waiter node onto N request lists, overwriting `node->owner`; cleanup
unlinks it only from the last, so the others keep `req->waiters` pointing to
freed memory. The waker is the write primitive (`[r15+0x20]` 32-bit write,
`[r15]`/`[r15+8]` arbitrary 32-bit decrements, `mtx_lock` on `[r15+0x10]`).

The payload then **reclaims the freed zone and re-reads two witness objects**
(a `0x70` block matching the num=2 waiter array, and a `0x60` osem-sized block
with a sentinel refcount at `+0x54`) to detect whether the UAF had any
observable effect. It does **not** implement the 727 leak or the osem
conversion — those are only meaningful once a witness confirms the effect.
(Note: syscall 727 has **no libkernel wrapper**, so it is not callable in
X1NON stub mode at all; the leak would require classic ROP or another vector.)

AIO requests are created against a **pending-read fd**: a `socketpair`
(`syscall 53`, stub available) whose empty end is the read target — `fd 0`
does not exist in the browser sandbox, and a completed read would leave no
live waiters. In stub mode the payload pre-checks that every stub it needs
exists and aborts cleanly otherwise.

**Destructive**: phase 3 can hang or panic the console. Run with a single
attempt and read the `VERDICT` line.

```
https://wamphyre.github.io/PSAITO/?log=1&logserver=http://<PC-IP>:8080/log&auto=bagagwa_uaf_1320.js&max=1
```

Possible verdicts: `PRIMITIVO VIVO` (the decrement hit), `EFECTO DETECTADO`
(a witness changed), or `sin efecto observable` (latent/invisible UAF).

### 4. Offset profiles (13.XX) — X1NON-verified

All 13.XX offsets are confirmed by
[X1NON-PSJB](https://github.com/X1NONs/X1NON-PSJB) (`offsets/13.XX/`): `hc`,
`gd` 0x1d6fa, `nt` 0x48b0, exports (`gpe` 0x1b860 / `cle` 0x274e0 / `ere`
0xf7d0) and the two GOT families — identical `wk_gadgetmap` and
`syscall_map` across 13.00→13.60. `offsets.mjs` still rotates two GOT
profiles per attempt as a safety net:

| profile | gps (getpid slot) | cls (close slot) | firmware family |
|---|---|---|---|
| 0 (13.00/13.20) | `0x3352238` | `0x3352228` | 13.00/13.20 tries this first |
| 1 (13.40/13.60) | `0x334e238` | `0x334e228` | 13.40/13.60 tries this first |

The exploit tries its **own family first** (`profilesFor` puts the firmware's
own entry at index 0), then rotates `(attempt-1) % 2`; the 3-way consistency
check of the libkernel base (getpid/close/error pointing to the same
page-aligned base) rejects the wrong one. If it never passes, watch
`KERNEL-BASE` / `VALIDATION-MISMATCH` lines in the log to see which profile
validated.

### 5. ROP vs DIRECT mode

`bridge.js` needs gadgets in libkernel `.text` to run arbitrary `syscall()`.
Two safety nets were added for console:
- A **1-byte probe** of `libkernelBase` before scanning. If the region faults
  (protected post-init), the bridge falls back to **DIRECT** instead of killing
  the process. `PS5.notes` will show `rop-probe-threw:...`.
- `?rop=0` forces DIRECT unconditionally.

Additionally, if the exploit publishes an out-of-band `libkernelBase` (the
common 13.x symptom when interpolated GOT offsets fail the 3-way check), the
bridge now logs the per-import candidates (`kbase-candidates: getpid=...,close=...`)
and **recovers** from whichever candidate lies in band and is page-aligned
(`kbase-recovered-from:getpid`), so a single wrong offset no longer forces
DIRECT. If none is valid, the panel shows a `DIAG DIRECT MODE` block with the
raw `webkitBase` / `libkernelBase` values and the reason.

**X1NON 13.XX fallback (`modules/offsets13x.js`)**: verified offsets from
[X1NON-PSJB](https://github.com/X1NONs/X1NON-PSJB) (raw files under
`offsets/13.XX/`, generator `sim/gen-offsets13x.mjs`). If the libkernel
gadget scan fails, the bridge switches to **stub mode**: ROP gadgets are taken
from the X1NON `wk_gadgetmap` (validated byte-by-byte inside WebKit, which is
readable), each syscall is executed by jumping to its **libkernel C stub**
(`syscall_map` — execution only, libkernel is never read), and `pivot`/`save`
are located by a targeted scan of WebKit `.text`. The badge then shows
`mode ROP (X1NON stubs)` and `SYSCALL_STUBS` is exposed to payloads. This is
what makes `syscall()` (and therefore BAGAGWA) available even when libkernel
`.text` cannot be read.

When DIRECT, `syscall()` throws and syscall-based payloads (BAGAGWA, AIO) cannot
fire — only `notify`/`nativeCall` probes work.

With GitHub Pages the page origin is `github.io`, and `exploit.js` disables
remote logging by default in that case. **Always pass `?log=1` together with
`?logserver=...`** so the exploit's own `mark()` lines reach the PC:

```
?log=1&logserver=http://<PC-IP>:8080/log
```

(Bridge/menu logs use `httpLog`, which does not check the origin, so they are
sent regardless.)

## Notes

- 13.XX offsets are **X1NON-verified** (including `gd`/`nt`). What remains
  unverified per-firmware is whether the WebKit SSV bug survived patching and
  whether the sandbox still reaches the AIO syscalls — the payload verdicts
  answer both. A single attempt may restart the browser tab — that is expected
  during testing.
- The site uses a service worker (`psaito-v3`). After a repo update, give
  Pages 1-2 minutes and reload; the SW self-updates on navigation. Payloads
  and logs are never cached.
- The Y2JB/exploit startup is flaky: if `SOMETHING WENT WRONG` or a hang
  occurs, close and reopen the app. A hard reset is safe (it does not touch the
  installed backup).
- The on-screen exploit log (`#scr`) is the source of truth in-console; the PC
  log is for offline analysis and survives a crash.

## Credits

- WebKit research baseline: **[mansoor0x](https://github.com/mansoor0x/POC)** — see `NOTICE.md`
- PSAITO (runtime bridge, panel, UI, probes): **Wamphyre**
- 13.XX offset tables (gadgets + syscall stubs): **[X1NONs/X1NON-PSJB](https://github.com/X1NONs/X1NON-PSJB)**

## 13.40 status: problem faced + what is needed (ciel branch)

Tested live on 13.40 hardware, results reproduced across many runs.

### What works
- WebKit userland exploit passes first-try with the `0x334e238` GOT family
  (`KERNEL-BASE pass`, `NOTIFY-NATIVE-CALL-PASS`). Requires `go=1` plus the
  firmware's own offset profile on every attempt; single-profile lock beats
  rotation, `max=3 n=256` beats the post-exploit memory dialog.
- DIRECT bridge boots reliably and payloads run. Stub-calls through
  `nativeCall` work with verified stub RVAs: `getpid` returns a real pid,
  `aio_init` returns 0 (AIO family alive, not ENOSYS).
- Worker-thread discovery is fully green: libc base via GOT slot
  `0x334E098-0x5D9E0`, worker handshake, thread-list walk (`0x6C218`,
  first entry already a `0x80000` stack), return-slot fingerprint
  (`LK+0x1FD01`, count exactly 1, stable offset `0x7FB68`).

### The problem
Full-arg syscalls (everything the kex needs: `wait`, `727`-out,
`osem_create`, `socketpair`) need a stack pivot the bridge does not have.
`nativeCall` controls only `rdi`+`rcx`; garbage in integer slots panics
(proven: `wait` with garbage `num` kills the tab).
- Any `.text` read kills the tab: libkernel (1 byte) and WebKit (first
  byte). XOM is enforced — no on-console gadget discovery, no classic ROP.
- Worker-thread hijack is set up perfectly every run (genuine slot,
  in-stack frame pointer, live fingerprint) but dies on entry: the
  carried-over `pop rsp 0xA1138` does not execute on real 13.40 WebKit.
  Alignment, OOM timing, and thread identity were each isolated and ruled
  out (ping control survives 10s+; fast verdicts; `attempt=1` runs).
- 19 blind `pop rsp` candidates swept (table value, fine deltas,
  `±0x4000`, older-gen values): all miss. The 13.40 gadget tables are
  13.20 carryovers (byte-identical hashes); `hc` matches but code
  addresses are unverified on-console by construction.

### What is needed
1. One true 13.40 code RVA (`pop rsp` minimum) from decrypted 13.40
   WebKit — not obtainable self-serve (PUP decrypt needs a hacked box,
   inner SELF stays AES-locked, no public dumps past 6.xx).
2. Everything downstream is already built: kex scaffold, kernel data
   offsets, reclaim/leak/priv-esc staging, Y2JB full-arg path.
