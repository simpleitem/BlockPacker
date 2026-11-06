# Auto-Modpacker

*English · [Русский](README.ru.md)*

A command-line tool for Minecraft players, modpack makers, and server admins. It scans a local `mods` folder, detects client/server side, finds missing dependencies and conflicts, checks updates on **Modrinth and CurseForge**, and can search, collect, and build modpacks. Pure Python, no dependencies, works on Windows, Linux, macOS, and Termux.

## Why it exists, and what makes it different

Managing a modpack by hand means switching between two sites, guessing which mods are client-only, hunting missing dependencies, and cleaning duplicates. Auto-Modpacker does that in one place: it reads every jar, parses `mods.toml` / `fabric.mod.json`, determines side (Manual-Side-Mods list → Modrinth → CurseForge), reports missing required and optional dependencies, incompatibilities, duplicate modIds and identical files, and checks updates on both platforms. The same script also keeps the Auto-Finder workflow: unified search, bulk addon collection, recursive pack building with `.mrpack` export, and import by links.

## Most useful features

- **`run`**: main scan. Classifies mods into Client / Server / Both / Unknown, then lists missing dependencies, conflicts, duplicates and stats. Snapshots go to `script_logs/`. Most other local commands work on the last `run`.
- **`updates` / `install missing` / `update`**: check updates on Modrinth and CurseForge, download missing required dependencies, or open the update center to migrate a pack to another Minecraft version (plan → stage → apply / export / rollback).
- **`aternos`**: direct Modrinth and CurseForge links (plus search links) from the last scan, ready for Aternos.
- **`bulk` / `build`**: Auto-Finder side — take a category or a core mod, find addons (including addons of addons), match the same mod on both sites by file hash, download jars and export `.mrpack`.

## How to use

1. Install Python 3. Download `Auto-Modpacker.py` and run it: `python Auto-Modpacker.py`.
2. Choose a language (`ru` / `en`).
3. For CurseForge, get a free API key at console.curseforge.com and save it with `key <your key>`. Without a key only Modrinth is used for side detection and updates. The key is stored locally in `CurseForgeApiKey_DO_NOT_SHARE.txt`.
4. Type commands at the `>` prompt. Example: `run` scans the pack, `stats` shows a short summary, `updates` lists available updates, `report` writes `modpack_report.html`.

A *slug* is the end of a mod's link, for example `sodium` in `https://modrinth.com/mod/sodium`.

## Other features

- `explain <modid|name>`: full card of one mod (side, deps, update status, jar internals).
- `version <mc> <loader>`: set the target Minecraft and loader for updates and installs.
- `scan`: heuristic risk scan (network libraries, native code, embedded executables, PowerShell).
- `disable` / `enable` / `rename` / `remove` / `export` / `clean`: manage jar files safely.
- `logs`, `timeline`, `compare`, `buildcompare`: history and comparison of scans and folders.
- Auto-Finder commands: `search`, `show`, `save`, `saveall`, `addons`, `newaddons`, `importlink`, `modupdate`. Any of them can also be called as `finder <command>`.
- `help` shows all commands, `exit` quits.

## Rules of use

The code is public to read, learn from, and use, but this is **not open source**. By using, copying, or modifying it you accept [LICENSE.md](LICENSE.md). In short:

- **Non-commercial use only.** No selling, paid access, microtransactions, paid ranks, ads, or training paid AI products. Personal, study, and non-profit use is fine, and so are videos and reviews.
- **Credit is required** in your README, in your product, and in its documentation: *Based on Auto-Modpacker by A Simple Block (https://github.com/simpleblockdev/Auto-Modpacker)*.
- **Excluded parties** listed in [EXCLUDED.md](EXCLUDED.md) get no license. Parties in [LICENSED.md](LICENSED.md) have permission in advance.
- **Donation links are allowed** if voluntary and with no perks. Demanding a donation ends your license.
- Modified copies must stay under this license and be marked as changed.
- Commercial licenses: simpleblockdev1@gmail.com, https://discord.com/invite/9KmaCbz9HQ.

Read the full text in LICENSE.md. It prevails over this summary.

## Enjoy!

Found a bug or have an idea? Open an issue. Happy modding!
