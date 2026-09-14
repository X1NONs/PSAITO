// usb_probe_1320.js — USB storage access probe from the sandbox.
// Goal: find out whether the PS5 browser/app sandbox can SEE and WRITE to a
// USB drive, so the toolkit log could be stored there.
//
// What it does:
//   P1  open(O_RDONLY|O_DIRECTORY) over candidate USB paths
//   P2  for the ones that open, getdirentries(0x1000) to list contents
//   P3  tries to create <usb>/psaito_usb/psaito_log.txt and write a marker
//   P4  verdict + cleanup
//
// ABI (see fs_probe_1320.js): open5 close6 read3 write4 unlink10 mkdir136
// rmdir137 getdirentries196. fcntl: O_RDONLY0 O_DIRECTORY0x20000 O_CWT0x601.
// Logging: bridge log() (screen #plg + TCP) and W() to the TCP channel if any.
(() => {
    const B = (x) => BigInt(x), I = (x) => BigInt.asIntN(64, x);
    const S_RD = 3n, S_WR = 4n, S_OP = 5n, S_CL = 6n, S_UNL = 10n,
        S_MK = 136n, S_RM = 137n, S_GDE = 196n;
    const O_RDONLY = 0n, O_DIR = 0x20000n, O_CWT = 0x601n;
    const Y = 331n;

    const say = (s) => { try { log("[usb] " + s); } catch (e) {} };
    const N = (s) => { try { send_notification(("[usb] " + s).slice(0, 120)); } catch (e) {} };

    const EL = { 1: "EPERM", 2: "ENOENT", 13: "EACCES", 17: "EEXIST",
        20: "ENOTDIR", 21: "EISDIR", 22: "EINVAL", 30: "EROFS",
        63: "ENAMETOOLONG", 66: "ENOTEMPTY", 78: "ENOSYS", 93: "ENOTCAPABLE",
        94: "ECAPMODE" };
    const EN = () => { try { const m = /^(\d+)/.exec(get_error_string()); return m ? parseInt(m[1], 10) : -1; } catch (e) { return -1; } };
    const J = (e) => " errno=" + e + "(" + (EL[e] || "?") + ")";
    const STR = (b, n) => { let x = ""; for (let i = 0; i < n; i++) { const v = Number(read8(b + BigInt(i))) & 255; if (v >= 32 && v < 127) x += String.fromCharCode(v); } return x; };

    const PATHBUF = malloc(512);
    const DB = malloc(0x1000);
    const BP = malloc(8);
    const MSG = malloc(64);
    const PS = (b, s) => { let n = 0; for (; n < s.length && n < 255; n++) write8(b + BigInt(n), s.charCodeAt(n) & 255); write8(b + BigInt(n), 0); return b; };

    say("begin - USB/storage probe pid=" + I(syscall(SYSCALL.getpid)));

    // ---------------------------------------------------------------- P1
    const PATHS = [
        "/mnt", "/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3",
        "/mnt/ext0", "/mnt/ext1", "/mnt/sda0", "/mnt/sda1",
        "/usb", "/usb0", "/usb1", "/media", "/media/usb0",
        "/mnt/usb/", "/external", "/external/usb0", "/ext0",
        "/data/usb0", "/user/usb0", "/host", "/app0", "/data", "/temp",
    ];
    say("P1: open(O_RDONLY|O_DIRECTORY) over " + PATHS.length + " paths");
    const vis = [];
    for (const p of PATHS) {
        let fd;
        try { fd = I(syscall(S_OP, PS(PATHBUF, p), O_RDONLY | O_DIR)); }
        catch (e) { say("P1 " + p + " EX " + e); continue; }
        if (fd < 0n) {
            const e = EN();
            say("P1 " + p + J(e) + (e === 93 || e === 94 ? " [sandbox cap]" : ""));
        } else {
            say("P1 " + p + " -> fd=" + fd + " OK");
            vis.push(p);
            try { syscall(S_CL, fd); } catch (e) {}
        }
    }
    say("P1 visible " + vis.length + "/" + PATHS.length + ": " + (vis.join(" ") || "(none)"));

    // ---------------------------------------------------------------- P2
    say("P2: getdirentries on the ones that opened");
    let listOK = 0;
    for (const p of vis) {
        let fd;
        try { fd = I(syscall(S_OP, PS(PATHBUF, p), O_RDONLY | O_DIR)); }
        catch (e) { continue; }
        if (fd < 0n) { say("P2 reopen " + p + J(EN())); continue; }
        write64(BP, 0n);
        let r;
        try { r = I(syscall(S_GDE, fd, DB, 0x1000n, BP)); }
        catch (e) { say("P2 " + p + " EX " + e); try { syscall(S_CL, fd); } catch (e2) {} continue; }
        if (r > 0n) {
            listOK++;
            const n = Number(r) > 128 ? 128 : Number(r);
            say("P2 " + p + " n=" + r + " entries='" + STR(DB, n).replace(/[^\x20-\x7e]/g, ".") + "'");
        } else if (r === 0n) {
            say("P2 " + p + " empty dir");
        } else {
            say("P2 " + p + J(EN()));
        }
        try { syscall(S_CL, fd); } catch (e) {}
    }
    say("P2 listable: " + listOK);

    // ---------------------------------------------------------------- P3
    // Writes are attempted ONLY on paths that look like external storage.
    // Never on /app0, /data, /temp, /host (they belong to the sandbox).
    const WRITE_OK = [];
    const EXTERNAL = vis.filter((p) => /usb|ext|media|mnt\/sd|external/i.test(p) && p !== "/external");
    if (EXTERNAL.length === 0) {
        say("P3: no external path visible -> no write candidate");
    } else {
        say("P3: attempting to write in " + EXTERNAL.join(", "));
        for (const d of EXTERNAL) {
            const dir = d.replace(/\/$/, "") + "/psaito_usb";
            try {
                say("P3 mkdir " + dir);
                let m = I(syscall(S_MK, PS(PATHBUF, dir), 0x1ffn));
                if (m < 0n) {
                    const e = EN();
                    if (e === 17) say("P3 mkdir EEXIST: reusing");
                    else { say("P3 mkdir" + J(e) + " -> next"); continue; }
                } else say("P3 mkdir ok");
            } catch (e) { say("P3 mkdir EX " + e); continue; }

            const file = dir + "/psaito_log.txt";
            let fd;
            try { fd = I(syscall(S_OP, PS(PATHBUF, file), O_CWT)); }
            catch (e) { say("P3 open EX " + e); continue; }
            if (fd < 0n) { say("P3 open " + file + J(EN())); continue; }

            const line = "PSAITO usb log test pid=" + I(syscall(SYSCALL.getpid)) + " fw=" + (PS5.fw || "?") + "\n";
            PS(MSG, line);
            let w = -1n;
            try { w = I(syscall(S_WR, fd, MSG, BigInt(line.length))); } catch (e) { say("P3 write EX " + e); }
            say("P3 write(" + line.length + ") -> " + w);
            try { syscall(S_CL, fd); } catch (e) {}

            if (w >= 0n) {
                WRITE_OK.push(file);
                say("P3 *** USB WRITE OK at " + file + " ***");
                break;
            }
        }
    }

    // ---------------------------------------------------------------- P4
    say("P4: verdict + cleanup");
    for (const d of EXTERNAL) {
        const dir = d.replace(/\/$/, "") + "/psaito_usb";
        try {
            syscall(S_UNL, PS(PATHBUF, dir + "/psaito_log.txt"));
            syscall(S_RM, PS(PATHBUF, dir));
        } catch (e) {}
    }

    let v;
    if (WRITE_OK.length) v = "USB WRITABLE: " + WRITE_OK[0];
    else if (listOK) v = "USB visible (listable) but NOT writable";
    else if (vis.length) v = "USB visible " + vis.length + " paths but cannot list/write";
    else v = "USB NOT visible from sandbox (0/" + PATHS.length + " paths)";
    say("VERDICT: " + v);
    N(v);

    for (let i = 0; i < 6; i++) { N(v.slice(0, 90)); for (let j = 0; j < 2000; j++) { try { syscall(Y); } catch (e) {} } }
    say("PAYLOAD DONE");
})();