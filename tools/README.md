# Optional third-party tools

Windows Detective runs without extra tools. If you drop the tools below into this folder, it uses them automatically.

| File | Used for | Where to get it |
|---|---|---|
| `winpmem*.exe` | Capturing physical memory (`-MemoryDump`) | https://github.com/Velocidex/WinPmem/releases |
| `yara64.exe` | Scanning process images, autoruns and suspicious files with the rules in `..\rules` | https://github.com/VirusTotal/yara/releases |

Check the hash and signature of every binary you download before you put it on evidence media.
Binaries are git-ignored and never committed.

Powered by Bashar Salmo
