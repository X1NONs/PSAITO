# y2jb (from scratch, PSAITO-side)
Y2JB kex work lives here. Nothing outside this repo is read or modified.
Session order (fresh boot every time):
1. Relaunch YT loader on PS5 (listens on port 50000).
2. Mac: `python3 y2jb/logserver.py` (keeps `y2jb/session.log`).
3. Mac: `python3 y2jb/send.py 192.168.0.155 50000 y2jb/01_sanity.js`
4. Expect `[ok]` lines + TV popups. Paste them back for next step.
Files: `send.py` sender, `logserver.py` log receiver, `01_sanity.js` first probe.
