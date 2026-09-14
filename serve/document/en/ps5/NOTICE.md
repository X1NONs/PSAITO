# NOTICE — procedencia del userland base

Este proyecto se publica como **PSAITO** por **wamphyre**. La GUI muestra la
marca PSAITO; la autoria del exploit WebKit subyacente se conserva en
creditos (GUI y este aviso).

Directorio `USERLAND/` basado en el POC publico de **mansoor0x**:
<https://github.com/mansoor0x/POC> (commit `c38fc5670dda8a750381091c4ad808fe9ad60480`, main, 2026).

- El repositorio upstream **no declara licencia** (solo README). Este proyecto es
  **experimental, educativo y de investigacion**, uso privado en consola propia;
  no redistribuir el POC como propio ni empaquetarlo para terceros.
- Autoria del exploit WebKit (WebKit SSV/type-confusion + primitiva notify):
  mansoor0x. Los unicos offsets/constantes verificados en consola por el autor
  upstream parecen ser los de la familia 11.xx/12.xx (ver notas
  `offline-verified-fw=11.60` en el codigo); el resto es interpolacion.

## Modificaciones nuestras (PSAITO)

Sobre el baseline anterior (marcadas en el codigo con `Mods PSAITO` /
fechas 2026-09-11):

- `modules/exploit.js` (motor de investigacion WebKit): arena 0x1000 -> 0x10000; conservar la ventana RW
  (carrier `candidate`, `rwView`) tras el SUCCESS en vez de destruirla;
  handoff `window.__PS5_CTX` + callback `globalThis.onUserland()`.
- `modules/bridge.js` (nuevo): API compatible con el loader Y2JB sobre las
  primitivas del POC — `malloc/free`, `read8/16/32/64`, `write8/16/32/64`,
  `syscall` (ROP propio con gadgets escaneados en libkernel .text), `notify`,
  `get_error_string`, `log`, `SYSCALL`.
- `modules/menu.js` (nuevo): panel de payloads (HTTP same-origin + URL
  arbitraria, `?pb=` configurable), log en pantalla.
- Rebranding GUI a PSAITO (marca wamphyre, credito mansoor0x visible); sw.js de
  rutas relativas para GitHub Pages.
- Avisos de proyecto experimental/educativo en README y GUI.
- `runtime.html` (antes exploit.html) / `index.html` / `sw.js`: carga bridge+menu, `pb` param,
  no-cache de `/payloads/` y `/log/`.
- `sim/`: simulador Node del entorno post-handoff (mini-CPU x86 + kernel
  fake ORBIS) para probar bridge y payloads sin consola.
- `payloads/`: copia real de `../DEMO/payloads` (sin symlinks, compatible
  con GitHub Pages).
- Rotacion de perfiles de offsets (`offsets.mjs:profilesFor` + listas
  `gps/cls/ers/gpe/cle/ere/gd/notify` en `exploit.js`): un perfil por
  intento para firmwares interpolados (13.60 prueba `0x334e2xx` y
  `0x33522xx`); la consistencia 3-via del libkernel base rechaza el errado.

## Modificaciones para ejecución en consola (2026-09-12, preparación)

- **Log remoto unificado con el runtime Y2JB** (`exploit.js:mark`,
  `bridge.js:httpLog`): antes ambos hacían `XHR GET log/<linea>` contra el
  propio host (404 en GitHub Pages → telemetría perdida). Ahora usan
  `POST` a `http://<host-pagina>:8080/log` (el `DEMO/log_server.py` del PC),
  configurable con `?logserver=` / `window.LOG_SERVER`. `exploit.js` además
  expone `?log=1` para forzar el log (en GitHub Pages el origen `github.io`
  lo desactiva por defecto).
- **Sonda ROP no destructiva** (`bridge.js:ropProbe`): el escaneo de gadgets
  leía 0x44000 bytes del `.text` de libkernel, que post-init puede estar
  protegido (SIGSEGV del proceso). Ahora se hace una lectura de 1 byte; si
  falla, el bridge cae a **DIRECT** (solo notify/nativeCall) en vez de matar
  la consola. `?rop=0` fuerza DIRECT.
- **Tabla `SYSN` corregida contra Orbis** (`bridge.js`): los números previos
  eran FreeBSD genéricos/ inventados y faltaban `kill`, `getuid`, `thr_self`,
  `umtx_op`, `sysctl`, `dlsym`, etc. Ahora replica la tabla del runtime Y2JB
  1.7 (`DEMO/download0/.../global.js`).
- **Watchdog del panel** (`menu.js`): si `onBridgeReady` no llega en 60 s, el
  panel se muestra igualmente con una pista de diagnóstico (el exploit
  reintenta; el arranque de Y2JB es flaky).
- **`index.html` propaga `?auto=` y `?logserver=`** a `runtime.html` (antes
  solo `pb`), para poder fijar el payload de auto-arranque y el log desde la
  URL de entrada.
- **`sw.js`**: versión de caché `psaito-v2` (evita servir módulos viejos
  cacheados tras actualizar offsets/exploit).
