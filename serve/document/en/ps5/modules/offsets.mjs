/**
 * offsets.mjs — PS5 WebKit Userland Exploit Offsets
 * mansoor0x · 2026
 *
 * Keys:
 *   hc   host constructor offsets (array, 3 candidates)
 *   gd   natural trampoline / gadget offset
 *   nt   notify entry offset
 *   gps  getpid slot
 *   gpe  getpid export offset
 *   cls  close slot
 *   cle  close export offset
 *   ers  error slot
 *   ere  error export offset
 */

export const OFFSETS = {
  "09.00":{"hc":["0x34f98","0x35808","0x35900"],"gd":"0x1cb9a","nt":"0x4590","gps":"0x33c1960","gpe":"0x1ad00","cls":"0x33c1950","cle":"0x26b40","ers":"0x33c1958","ere":"0xf160"},
  "09.20":{"hc":["0x34f98","0x35808","0x35900"],"gd":"0x1cb9a","nt":"0x4590","gps":"0x33c1960","gpe":"0x1ad00","cls":"0x33c1950","cle":"0x26b40","ers":"0x33c1958","ere":"0xf160"},
  "09.40":{"hc":["0x34f98","0x35808","0x35900"],"gd":"0x1cb9a","nt":"0x4590","gps":"0x33c1970","gpe":"0x1ad00","cls":"0x33c1960","cle":"0x26b40","ers":"0x33c1968","ere":"0xf160"},
  "09.60":{"hc":["0x34f98","0x35808","0x35900"],"gd":"0x1cb9a","nt":"0x4590","gps":"0x33c1970","gpe":"0x1ad00","cls":"0x33c1960","cle":"0x26b40","ers":"0x33c1968","ere":"0xf160"},
  "10.00":{"hc":["0x2c00","0x5178","0x5690"],"gd":"0x1cdfa","nt":"0x45c0","gps":"0x35cd750","gpe":"0x1af60","cls":"0x35cd740","cle":"0x26940","ers":"0x35cd748","ere":"0xf0d0"},
  "10.01":{"hc":["0x2c00","0x5178","0x5690"],"gd":"0x1cdfa","nt":"0x45c0","gps":"0x35cd750","gpe":"0x1af60","cls":"0x35cd740","cle":"0x26940","ers":"0x35cd748","ere":"0xf0d0"},
  "10.20":{"hc":["0x2c00","0x5178","0x5690"],"gd":"0x1cdfa","nt":"0x45c0","gps":"0x35cd750","gpe":"0x1af60","cls":"0x35cd740","cle":"0x26940","ers":"0x35cd748","ere":"0xf0d0"},
  "10.40":{"hc":["0x2c00","0x5178","0x5690"],"gd":"0x1cdfa","nt":"0x45c0","gps":"0x35cd750","gpe":"0x1af60","cls":"0x35cd740","cle":"0x26940","ers":"0x35cd748","ere":"0xf0d0"},
  "10.60":{"hc":["0x2c00","0x5178","0x5690"],"gd":"0x1cdfa","nt":"0x45c0","gps":"0x35cd750","gpe":"0x1af60","cls":"0x35cd740","cle":"0x26940","ers":"0x35cd748","ere":"0xf0d0"},
  "11.00":{"hc":["0x1e0d8","0x1e320","0x1f368"],"gd":"0x1d11a","nt":"0x4740","gps":"0x34f57b8","gpe":"0x1b280","cls":"0x34f57a8","cle":"0x26e70","ers":"0x34f57b0","ere":"0xf340"},
  "11.20":{"hc":["0x1e0d8","0x1e320","0x1f368"],"gd":"0x1d11a","nt":"0x4740","gps":"0x34f57b8","gpe":"0x1b280","cls":"0x34f57a8","cle":"0x26e70","ers":"0x34f57b0","ere":"0xf340"},
  "11.40":{"hc":["0x1e0d8","0x1e320","0x1f368"],"gd":"0x1d11a","nt":"0x4740","gps":"0x34f57b8","gpe":"0x1b280","cls":"0x34f57a8","cle":"0x26e70","ers":"0x34f57b0","ere":"0xf340"},
  "11.60":{"hc":["0x1e0d8","0x1e320","0x1f368"],"gd":"0x1d11a","nt":"0x4740","gps":"0x34f57b8","gpe":"0x1b280","cls":"0x34f57a8","cle":"0x26e70","ers":"0x34f57b0","ere":"0xf340"},
  "12.00":{"hc":["0x3a888","0x3aad0","0x3bb18"],"gd":"0x1d66a","nt":"0x48b0","gps":"0x350dc28","gpe":"0x1b7d0","cls":"0x350dc18","cle":"0x27450","ers":"0x350dc20","ere":"0xf740"},
  "12.02":{"hc":["0x3a888","0x3aad0","0x3bb18"],"gd":"0x1d66a","nt":"0x48b0","gps":"0x350dc28","gpe":"0x1b7d0","cls":"0x350dc18","cle":"0x27450","ers":"0x350dc20","ere":"0xf740"},
  "12.20":{"hc":["0x3a888","0x3aad0","0x3bb18"],"gd":"0x1d66a","nt":"0x48b0","gps":"0x350dc28","gpe":"0x1b7d0","cls":"0x350dc18","cle":"0x27450","ers":"0x350dc20","ere":"0xf740"},
  "12.40":{"hc":["0x3a888","0x3aad0","0x3bb18"],"gd":"0x1d68a","nt":"0x48b0","gps":"0x350dc28","gpe":"0x1b7f0","cls":"0x350dc18","cle":"0x27470","ers":"0x350dc20","ere":"0xf740"},
  "12.60":{"hc":["0x3a888","0x3aad0","0x3bb18"],"gd":"0x1d68a","nt":"0x48b0","gps":"0x350dc28","gpe":"0x1b7f0","cls":"0x350dc18","cle":"0x27470","ers":"0x350dc20","ere":"0xf740"},
  "12.70":{"hc":["0x3a888","0x3aad0","0x3bb18"],"gd":"0x1d68a","nt":"0x48b0","gps":"0x350dc28","gpe":"0x1b7f0","cls":"0x350dc18","cle":"0x27470","ers":"0x350dc20","ere":"0xf740"},
  // [X1NON verificado] hc/gpe/cle/ere y familias GOT confirmados por
  // X1NON-PSJB offsets/13.XX (gpe=getpid stub 0x1b860; cle=0x274e0, ere=0xf7d0
  // documentados en 13.60). gd/nt siguen siendo del POC mansoor0x.
  "13.00":{"hc":["0x56a58","0x56ca0","0x57ce8"],"gd":"0x1d6fa","nt":"0x48b0","gps":"0x3352238","gpe":"0x1b860","cls":"0x3352228","cle":"0x274e0","ers":"0x3352230","ere":"0xf7d0"},
  "13.20":{"hc":["0x56a58","0x56ca0","0x57ce8"],"gd":"0x1d6fa","nt":"0x48b0","gps":"0x3352238","gpe":"0x1b860","cls":"0x3352228","cle":"0x274e0","ers":"0x3352230","ere":"0xf7d0"},
  "13.40":{"hc":["0x56a58","0x56ca0","0x57ce8"],"gd":"0x1d6fa","nt":"0x48b0","gps":"0x334e238","gpe":"0x1b860","cls":"0x334e228","cle":"0x274e0","ers":"0x334e230","ere":"0xf7d0"},
  "13.60":{"hc":["0x56a58","0x56ca0","0x57ce8"],"gd":"0x1d6fa","nt":"0x48b0","gps":"0x334e238","gpe":"0x1b860","cls":"0x334e228","cle":"0x274e0","ers":"0x334e230","ere":"0xf7d0"},
};

export function fwNum(s) {
  const p = s.split(".");
  return parseInt(p[0], 10) * 100 + parseInt(p[1], 10);
}

/** Detect PS5 firmware from user-agent. Returns "13.60" format or null. */
export function detectFirmware() {
  const m = /PlayStation 5\/(\d+)\.(\d+)/.exec(navigator.userAgent);
  if (!m) return null;
  return `${m[1].padStart(2,"0")}.${m[2].padStart(2,"0")}`;
}

/** Find exact or nearest same-major offsets. Returns {key, entry, exact}. */
export function resolve(fw) {
  if (!fw) return null;
  if (OFFSETS[fw]) return { key: fw, entry: OFFSETS[fw], exact: true };
  const want = fwNum(fw);
  const maj  = fw.split(".")[0];
  let best = null, bestD = 1e9;
  for (const k in OFFSETS) {
    if (k.split(".")[0] !== maj) continue;
    const d = Math.abs(fwNum(k) - want);
    if (d < bestD) { bestD = d; best = k; }
  }
  return best ? { key: best, entry: OFFSETS[best], exact: false } : null;
}

/**
 * Candidatos de offset para un firmware, ordenados por probabilidad.
 * La tabla interpolada copia entradas por familia: p.ej. 13.60 puede
 * tener en realidad los slots GOT de la familia 13.00/13.20 (0x33522xx)
 * en vez de los de 13.40/13.60 (0x334e2xx). profilesFor devuelve las
 * variantes GOT/export distintas dentro del mismo major, mas cercana
 * primero; el exploit rota un perfil por intento y la comprobacion de
 * consistencia 3-vias del libkernel base rechaza sola el equivocado.
 */
export function profilesFor(fw) {
  const base = resolve(fw);
  if (!base) return [];
  const keyOf = (e) => [e.gps, e.cls, e.ers, e.gpe, e.cle, e.ere,
    e.gd, e.nt, e.hc.join(",")].join("|");
  const seen = new Set([keyOf(base.entry)]);
  const out = [base.entry];
  const want = fwNum(fw), maj = fw.split(".")[0];
  const fam = Object.keys(OFFSETS)
    .filter((k) => k.split(".")[0] === maj && k !== base.key)
    .sort((a, b) => Math.abs(fwNum(a) - want) - Math.abs(fwNum(b) - want));
  for (const k of fam) {
    const e = OFFSETS[k];
    const key = keyOf(e);
    if (!seen.has(key)) { seen.add(key); out.push(e); }
  }
  return out;
}

export const SUPPORTED_RANGE = { min: "09.00", max: "13.60" };
export const TOTAL_FW = Object.keys(OFFSETS).length;
