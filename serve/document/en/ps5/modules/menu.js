// 2026-09-11 menu.js — panel de payloads sobre el userland de mansoor0x.
// Al completarse el exploit (onBridgeReady) se habilita: lista de payloads
// conocidas + nombre custom + URL arbitraria, se sirven por HTTP desde el
// MISMO origen (pb= base, por defecto "payloads/") y se evaluan en el mismo
// contexto JS que ya tiene la API del bridge (malloc/syscall/read/write/log).
"use strict";
(function (global) {
    const QP = new URLSearchParams(location.search);
    let pb = QP.get("pb") || "payloads/";
    if (!pb.endsWith("/")) pb += "/";

    // [PSAITO] payload por defecto tras el exploit: Bagagwa UAF (aio_multi_wait mode 0).
    // ?auto=<archivo.js> lo cambia; ?auto=0 lo desactiva.
    const DEF_PAYLOAD = "bagagwa_uaf_1320.js";
    let auto = QP.get("auto");
    if (auto === null) auto = DEF_PAYLOAD;
    let autoTimer = 0;

    const KNOWN = [
        "hello_1320.js",
        "aio_reach_1320.js",
        "bagagwa_uaf_1320.js",
        "osem_campaign_1320.js",
        "osem2_1320.js",
        "netcontrol_poc_1320.js",
        "netctl5_variants_1320.js",
        "devprobe_1320.js",
        "fs_probe_1320.js",
        "usb_probe_1320.js",
    ];

    let css = document.createElement("style");
    css.textContent =
        "#pnl{position:fixed;right:8px;top:56px;width:340px;max-height:80vh;" +
        "overflow:auto;background:#060a10;border:1px solid #0d1825;border-radius:6px;" +
        "padding:10px;font-family:Consolas,monospace;font-size:11px;color:#c0d0e8;" +
        "z-index:50;display:none}" +
        "#pnl button{background:#0057e0;color:#fff;border:0;border-radius:4px;" +
        "padding:6px 10px;font-weight:600;cursor:pointer;margin:2px}" +
        "#pnl input{width:150px;background:#030508;color:#c0d0e8;" +
        "border:1px solid #0d1825;border-radius:4px;padding:4px}" +
        "#plg{background:#030508;border:1px solid #0d1825;border-radius:4px;" +
        "height:280px;overflow:auto;white-space:pre-wrap;padding:6px;margin-top:6px;" +
        "-webkit-overflow-scrolling:touch}" +
        "#pnl .h{color:#e8f0ff;font-weight:700;letter-spacing:.1em}" +
        // Boton flotante de descarga: siempre visible aunque el panel se oculte
        // o el exploit se cuelgue. Rescata el log en cualquier estado.
        "#dlfab{position:fixed;right:8px;bottom:8px;z-index:60;" +
        "background:#555f00;color:#fff;border:0;border-radius:4px;" +
        "padding:8px 12px;font:600 11px Consolas,monospace;cursor:pointer;" +
        "box-shadow:0 2px 10px rgba(0,0,0,.6)}";
    document.head.appendChild(css);

    const pnl = document.createElement("div");
    pnl.id = "pnl";
    pnl.innerHTML =
        '<span class="h">PSAITO · PAYLOADS</span> ' +
        '<span id="pmode">—</span><br>' +
        '<select id="psel"></select> <input id="pcustom" placeholder="o archivo.js">' +
        '<div><button id="prun">RUN</button>' +
        '<button id="pstop" style="background:#552222">RESET</button>' +
        '<button id="pstop2" style="background:#7a1f1f">STOP</button>' +
        '<button id="plogdl" style="background:#555f00">DOWNLOAD LOG</button>' +
        '<button id="plogclr" style="background:#333">CLEAR</button></div>' +
        'URL: <input id="purl" style="width:290px" placeholder="http://host/payload.js">' +
        '<div><button id="purlrun" style="background:#00764f">RUN URL</button></div>' +
        '<div id="plg">ready.</div>';
    document.body.appendChild(pnl);
    // El panel se muestra DESDE YA (no solo tras onBridgeReady): si el exploit
    // entra en bucle de fallos o satura memoria, los botones de log siguen
    // accesibles. Arranca en estado "waiting".
    pnl.style.display = "block";
    pnl.querySelector("#pmode").textContent = "waiting for bridge…";

    // Boton flotante de rescate: descarga el log sin depender del panel.
    const dlfab = document.createElement("button");
    dlfab.id = "dlfab";
    dlfab.textContent = "DOWNLOAD LOG";
    document.body.appendChild(dlfab);

    const sel = pnl.querySelector("#psel");
    if (auto && auto !== "0" && KNOWN.indexOf(auto) < 0)
        KNOWN.unshift(auto);
    for (const k of KNOWN) {
        const o = document.createElement("option");
        o.textContent = k;
        sel.appendChild(o);
        if (k === auto) sel.value = k;
    }

    // Buffer de log completo (no se trunca) ademas del panel visible.
    const LOG_CAP = 20000;
    const STORE_KEY = "psaito:log";
    const logBuf = [];
    // Persistencia: el arranque de Y2JB puede reiniciar la pestana y el log en
    // memoria se perderia. Se guarda en localStorage (con throttle) para poder
    // verlo/descargarlo al reabrir. No guarda si el almacenamiento falla.
    let storeTimer = 0, storeDirty = false;
    try {
        const saved = localStorage.getItem(STORE_KEY);
        if (saved) {
            const lines = saved.split("\n");
            for (const l of lines) logBuf.push(l);
        }
    } catch (e) {}
    function persistLog() {
        storeDirty = true;
        if (storeTimer) return;
        storeTimer = setTimeout(() => {
            storeTimer = 0;
            if (!storeDirty) return;
            storeDirty = false;
            try { localStorage.setItem(STORE_KEY, logBuf.join("\n")); } catch (e) {}
        }, 500);
    }
    function logAll(s) {
        s = String(s);
        logBuf.push(s);
        if (logBuf.length > LOG_CAP) logBuf.splice(0, logBuf.length - LOG_CAP);
        persistLog();
    }

    // El exploit escribe su propio log en #scr (screenLine), NO via log() del
    // bridge. Sin capturarlo, el boton de descarga perderia justo el log de
    // intentos/reintentos. Un observer copia cada cambio de #scr al buffer.
    let scrLast = "";
    function captureScr() {
        try {
            const scr = document.getElementById("scr");
            if (!scr) return;
            const txt = scr.textContent || "";
            if (txt === scrLast) return;
            // El bloque de #scr solo guarda las ultimas SCREEN_LINES lineas; se
            // anaden al buffer las que sean nuevas respecto a lo ya visto.
            if (scrLast && txt.startsWith(scrLast)) {
                const delta = txt.slice(scrLast.length).replace(/^\n+/, "");
                if (delta) logAll("[scr] " + delta);
            } else if (!scrLast) {
                const first = txt.replace(/^Waiting for exploit to start…\s*/, "").trim();
                if (first) logAll("[scr] " + first);
            } else {
                logAll("[scr] " + txt.split("\n").slice(-1)[0]);
            }
            scrLast = txt;
        } catch (e) {}
    }
    const SI = (typeof setInterval === "function") ? setInterval
        : (typeof global.setInterval === "function" ? global.setInterval : null);
    try {
        const scrEl = document.getElementById("scr");
        if (scrEl && window.MutationObserver) {
            new MutationObserver(captureScr).observe(scrEl,
                { childList: true, characterData: true, subtree: true });
        } else if (SI) {
            SI(captureScr, 1000);
        }
    } catch (e) { if (SI) SI(captureScr, 1000); }
    function glog(s) {
        logAll(s);
        const d = pnl.querySelector("#plg");
        // Scroll pegajoso: solo baja si el usuario ya estaba al final.
        const atBottom = d.scrollHeight - d.scrollTop - d.clientHeight < 24;
        d.textContent = (d.textContent + "\n" + s).split("\n").slice(-1000).join("\n");
        if (atBottom) d.scrollTop = d.scrollHeight;
    }
    global.__psaitoLog = () => logBuf.join("\n");
    global.__psaitoAppend = (s) => logAll(s);
    function downloadLog() {
        try {
            const stamp = new Date().toISOString().replace(/[:.]/g, "-");
            const name = "psaito_log_" + stamp + ".txt";
            const blob = new Blob([logBuf.join("\n")], { type: "text/plain" });
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = name;
            a.style.display = "none";
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 5000);
            glog("== log downloaded: " + name + " ==");
        } catch (e) { glog("!! download not supported: " + e); }
    }
    function fetchText(url, cb) {
        try {
            const x = new XMLHttpRequest();
            x.open("GET", url, true);
            x.onload = () => cb(x.status === 200 ? null : "http" + x.status, x.responseText);
            x.onerror = () => cb("network", null);
            x.send();
        } catch (e) { cb("throw:" + e, null); }
    }
    function runSource(name, src) {
        glog("== run " + name + " (" + src.length + "B) ==");
        try {
            (0, eval)(src);
            glog("== end " + name + " (no synchronous throw) ==");
        } catch (e) {
            glog("!! ERROR " + name + ": " + (e && e.message || e));
        }
    }
    function runFile(name) {
        fetchText(pb + encodeURIComponent(name), (err, src) => {
            if (err) { glog("!! fetch " + name + ": " + err); return; }
            runSource(name, src);
        });
    }
    function runNamed() {
        runFile((pnl.querySelector("#pcustom").value.trim()) || sel.value);
    }


    function stopExploit() {
        try {
            if (typeof global.__psaitoStop === "function") {
                global.__psaitoStop();
                glog("!! exploit stopped by user (retry loop halted).");
            } else {
                glog("!! __psaitoStop not available (exploit not armed?).");
            }
        } catch (e) { glog("!! stop failed: " + e); }
    }

    pnl.querySelector("#prun").addEventListener("click", runNamed);
    pnl.querySelector("#plogdl").addEventListener("click", downloadLog);
    dlfab.addEventListener("click", downloadLog);
    pnl.querySelector("#pstop2").addEventListener("click", stopExploit);
    pnl.querySelector("#plogclr").addEventListener("click", () => {
        logBuf.length = 0;
        try { localStorage.removeItem(STORE_KEY); } catch (e) {}
        pnl.querySelector("#plg").textContent = "log cleared.";
    });
    pnl.querySelector("#purlrun").addEventListener("click", () => {
        const u = pnl.querySelector("#purl").value.trim();
        if (!u) return;
        fetchText(u, (err, src) => {
            if (err) { glog("!! fetch url: " + err); return; }
            runSource(u.split("/").pop(), src);
        });
    });
    pnl.querySelector("#pstop").addEventListener("click", () => {
        if (autoTimer) { clearTimeout(autoTimer); autoTimer = 0; }
        pnl.querySelector("#plg").textContent = "reset (reload to re-exploit).";
        try { sessionStorage.removeItem("userland-loader-handoff-1:passed"); } catch (e) {}
        setTimeout(() => location.reload(), 200);
    });

    // Replay the persisted log from a previous run, if any.
    function replaySaved() {
        if (!logBuf.length) return;
        const d = pnl.querySelector("#plg");
        if (d.textContent.indexOf("--- previous run log ---") >= 0) return;
        d.textContent = "--- previous run log ---\n"
            + logBuf.join("\n") + "\n--- end previous log ---";
        d.scrollTop = d.scrollHeight;
    }

    global.onBridgeReady = function (ps5) {
        pnl.style.display = "block";
        pnl.querySelector("#pmode").textContent =
            "fw " + ps5.fw + " · mode " + ps5.mode +
            (ps5.mode === "ROP" ? (ps5.stubMode ? " (X1NON stubs)" : "") : " (! syscall no-op)");
        glog("bridge ready. heap=arena+0x2000..0x8000 pb=" + pb);
        if (ps5.notes && ps5.notes.length) glog("notes: " + ps5.notes.join(" | "));
        if (ps5.mode !== "ROP") {
            glog("============ DIAG DIRECT MODE ============");
            glog("syscall() unavailable -> bagagwa/aio cannot fire.");
            glog("webkitBase = " + (ps5.webkitBase === null ? "null" : "0x" + Number(ps5.webkitBase).toString(16)));
            glog("libkernel  = " + (ps5.libkernelBase === null ? "null" : "0x" + Number(ps5.libkernelBase).toString(16)));
            glog("notes      = " + (ps5.notes && ps5.notes.length ? ps5.notes.join(" | ") : "(none)"));
            glog("most likely: 13.x offsets (gps/cls/ers) did not validate");
            glog("=> rop-no-libkernel-base. Both offset profiles were tried.");
            glog("=========================================");
        }
        replaySaved();
        if (auto && auto !== "0") {
            glog("auto-run in 1.5s: " + auto + "  (?auto=0 disables)");
            autoTimer = setTimeout(() => runFile(auto), 300);
        }
    };

    // [Mods console] Watchdog: if the exploit never reaches SUCCESS
    // (onBridgeReady), the panel stays hidden and there is no way to diagnose
    // from the console. After 60s show the real state and a hint.
    setTimeout(function () {
        if (!global.PS5 || !global.PS5.ready) {
            pnl.style.display = "block";
            pnl.querySelector("#pmode").textContent = "no bridge (exploit did not complete)";
            replaySaved();
            glog("!! bridge did not arrive within 60s. The WebKit exploit did not reach SUCCESS.");
            glog("   the exploit retries on its own; check #scr (exploit log) and the banner.");
            glog("   if it stays the same, close and reopen the app (Y2JB startup is flaky).");
        }
    }, 60000);
})(window);
