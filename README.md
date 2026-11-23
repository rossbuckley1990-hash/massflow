# Massflow (`v2.0`)

**The Memory, MCP & Storage Twin to `wattflow`: Cross-IDE `N → 1 → 0` MCP Multiplexing, Socket-Shielded MMU Cryo-Stasis & Parallel APFS Zero-Mass Compaction in a single zero-dependency Swift + ARM64 C/NEON binary (no `sudo`, `0.0%` idle CPU, `~12 MB` RSS, `0` files deleted).**

---

## Why This Exists

`wattflow` solved the **CPU Cluster, Power & WindowServer GPU** leak of modern multi-agent macOS (`22.68 W` → `3.11 – 8.00 W`).  
Yet running **Claude Desktop + 5× Claude Code terminals + Antigravity + ChatGPT/Codex + Qoder + Cursor + Chrome** simultaneously on a `16 GiB RAM / 460 GiB SSD` Apple M5 MacBook Air still hits **three severe everyday walls** in stock macOS:

1. **The `N × M` `stdio` MCP Daemon Explosion (`> 1.0 GiB` Duplicate Idle RAM)**
   Because MCP tools launch over private `stdio` pipes, `8+` concurrent IDE/CLI sessions spawn **duplicate Node, Bun, `uv`, and Python runtimes for the exact same tools** — on this Mac, `11× screenpipe-mcp` (`403 MiB`), `8× rightclick-x` (`321 MiB`), and `5× blender-mcp` (`264 MiB` + `92 MiB` `uvx`) = **`29` duplicate processes burning `1,080 MiB` of Unified Memory** just waiting on `stdin`, plus `3–6s` cold startup lag per new session.
2. **V8 / Electron Timer MMU Reference-Bit Pollution (`7.0 GiB` Swap Allocation & `2.0M` Swapouts)**
   Even on Efficiency Cores (`PRIO_DARWIN_BG`), buried Electron/Chromium apps and forgotten windows (`TV.app` idle `11h` at `624 MiB`, buried `ChatGPT` at `2.6 GiB`, `Mail`, `Notes`) still wake every few seconds on V8 GC and `setInterval` ticks — resetting ARM64 hardware MMU Access Flags (`AF`) on gigabytes of dead heap so XNU's LRU pageout scanner swaps active foreground work to SSD instead.
3. **Silent Physical SSD Exhaustion (`88.7%` Full — Only `51.77 GiB` Free)**
   Stopped hypervisor disk images (`Claude/vm_bundles/claudevm.bundle/rootfs.img`, `Docker.raw`) keep **gigabytes of all-zero `4 KB` blocks** physically allocated on APFS (`5.89 GiB` of zero blocks), while multi-repo dependency/build trees (`node_modules`, `.build`, `target`, `.venv`, `uv`, `scratch-workspaces`) duplicate tens of thousands of identical extents and uncompressed build artifacts.

**`massflow v2.0` eliminates all three bottlenecks permanently alongside `wattflow` — without `sudo` and without deleting a single file.**

---

## Key Architecture (`v2.0`)

* **Turnkey Cross-IDE `N → 1 → 0` MCP Multiplexer (`massflow mcp-adopt` + `massflow mux`)**
  * Automatically backs up and upgrades `claude_desktop_config.json`, `~/.claude.json`, `~/.cursor/mcp.json`, and `~/.codex/config.toml` (intelligently preserving stateful per-session tools like `node_repl`, bundle-relative helpers like `computer-use`, and remote SSE URLs).
  * Collapses `N` concurrent IDE/CLI `stdio` sessions across all workspaces onto **`1` global Unix-socket (`AF_UNIX`) singleton** per MCP tool with collision-free JSON-RPC 2.0 `(client_id, req_id)` virtualization and **`0.098 ms` cached `initialize` handshakes**.
  * **Scale-to-Zero Cold Hibernation (`1 → 0`)**: After `180s` with zero `tools/call` traffic, `massflow` caches `initialize` and `tools/list` schemas in `< 8 KB` and **terminates the idle Node/Python runtime (`0.0 MiB` RAM)** while keeping all `N` client pipes open — seamlessly waking & re-handshaking on the next `tools/call` (`0` dropped calls).
* **Socket- & Focus-Shielded MMU Cryo-Stasis Daemon (`local.massflow.governor`)**
  * Freezes deeply buried (`isHidden`), idle (`>= 180s` dwell) background app subtrees via `SIGSTOP` (`0.000%` CPU, `0` V8 timer MMU `AF`-bit resets), allowing XNU to compress and reclaim gigabytes of cold swap.
  * Guarded by **4 kernel shields**: Active/Visible UI, **Kernel TCP Listen Shield** (`PROC_PIDFDSOCKETINFO` `TSI_S_LISTEN` in `~12 µs` — protects `:3000`, `:8001`, LSPs, active Claude sessions), **Active `RUSAGE_INFO_V6` Compute Shield**, and **Hardware Media/Call Shield** (`IOPMCopyAssertionsByProcess`).
  * Subscribes to `NSWorkspace` focus/unhide notifications to thaw entire subtrees via live kernel child-graph traversal in **`1.0 – 1.9 µs`** (`> 4,000×` faster than a single `120 Hz` ProMotion frame), with XNU `SSTOP` recovery on startup/exit.
* **Parallel Multi-Core APFS Zero-Mass Engine (`F_PUNCHHOLE` + `clonefile` CoW + Ring-0 `UF_COMPRESSED` `LZFSE`)**
  1. **NEON Sparse Hole Punching (`fcntl(F_PUNCHHOLE)`)**: Guarded by global `PROC_PIDFDVNODEPATHINFO` open-FD shields + `flock(LOCK_EX | LOCK_NB)`, punches `4 KB` zero runs in closed VM `.img`/`.raw` files into `0-byte` APFS sparse holes.
  2. **Parallel `FEAT_SHA256` Copy-on-Write Deduplication (`clonefile(2)`)**: Hashes multi-file size buckets across all CPU cores (`DispatchQueue.concurrentPerform`), coalescing `79,000+` duplicate dependency/cache files across `uv`, `bun`, `scratch`, `src`, `spawn`, and `Documents` into `0-byte` CoW clones without touching git-tracked source files.
  3. **XNU Ring-0 Transparent `LZFSE` Folding (`CMP_Type11` / `CMP_Type12`)**: Compresses cold build/result artifacts in kernel space (up to `132×`), verifying **full `SHA-256` readback through XNU VFS before every atomic `rename()`**.

---

## Measured Results on This Mac (Apple M5 `Mac17,3`, `16 GiB` RAM, `460 GiB` SSD, macOS 27.2)

| Metric | Before `massflow` | With `massflow v2.0` |
| :--- | :--- | :--- |
| **`/System/Volumes/Data` Free Space (`df`)** | `51.77 GiB` (`88.7%` full) | **`66.78 GiB` (`+15.01 GiB` net physical SSD freed)** |
| **Total Logical Extent Reduction** | — | **`+25.67 GiB` (`5.89 GiB` VM holes + `19.78 GiB` CoW/LZFSE)** |
| **Files Deleted / `SHA-256` Mismatches** | — | **`0` deleted · `198,853` `SHA-256` checks `100%` exact** |
| **Encrypted SSD Swap Allocation** | `6,136.9 / 7,168.0 MiB` | **`5,173.2 / 6,144.0 MiB` (`-1.0 GiB` swapfile reclaimed)** |
| **Cryo-Paused Buried Idle App Footprint** | `0 MiB` (timers waking every few sec) | **`3,375.9 MiB` across `40` buried PIDs (`1.0 µs` focus thaw)** |
| **MCP `stdio` Spawns (`Claude`/`Cursor`/`Codex`)** | `29` duplicate procs (`1,080 MiB`) | **`1` shared warm broker (`0.098 ms` init) → `0.0 MiB` idle** |
| **Persistent Daemon Footprint** | — | **`0.0%` CPU · `~11.9 MiB` RSS (`15/15` tests `PASS`)** |

---

## Build & Usage

```bash
git clone https://github.com/rossbuckley1990-hash/massflow.git
cd massflow
swift build -c release

massflow status --fast       # Instant live report (RAM/swap, cryo daemon, mux brokers & TCP shields)
massflow top                 # Live 1 Hz terminal dashboard
massflow verify              # Run 15 automated kernel, N→1→0 MCP, JSON/TOML & SHA-256 tests
massflow reclaim --dry-run   # Preview lossless APFS Zero-Mass savings across all workspaces
massflow reclaim             # Execute parallel SHA-256-verified lossless APFS reclamation
massflow mcp-adopt           # Auto-wrap Claude Desktop, Claude Code, Cursor & Codex MCP configs
massflow mcp-restore         # Roll back all MCP config files to original backups
massflow thaw                # Immediately SIGCONT all cryo-paused background PIDs
massflow install             # Install ~/.local/bin/massflow & persistent local.massflow.governor
massflow uninstall           # Remove LaunchAgent & thaw all cryo-paused PIDs
```
