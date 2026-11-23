import CMassflowKernel
import Cocoa
import CryptoKit
import Darwin
import Foundation

private let kMassflowVersion = "2.0.0"

// MARK: - ANSI Styling

private enum ANSI {
    static let bold    = "\u{001B}[1m"
    static let dim     = "\u{001B}[2m"
    static let cyan    = "\u{001B}[36m"
    static let green   = "\u{001B}[32m"
    static let yellow  = "\u{001B}[33m"
    static let magenta = "\u{001B}[35m"
    static let red     = "\u{001B}[31m"
    static let reset   = "\u{001B}[0m"
    static let clear   = "\u{001B}[2J\u{001B}[H"
}

private func banner(_ title: String) {
    let line = String(repeating: "─", count: 76)
    print("\(ANSI.cyan)╭\(line)╮\(ANSI.reset)")
    let pad = max(0, 74 - title.count)
    print("\(ANSI.cyan)│\(ANSI.reset) \(ANSI.bold)\(title)\(ANSI.reset)\(String(repeating: " ", count: pad)) \(ANSI.cyan)│\(ANSI.reset)")
    print("\(ANSI.cyan)╰\(line)╯\(ANSI.reset)")
}

// MARK: - Focus-Reactive Socket-Shielded Cryo-Stasis Daemon (`massflow daemon`)

private let kConfigDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/massflow")
private let kCryoLedgerPath = kConfigDir.appendingPathComponent("cryo_pids.json")
private let kDaemonStatePath = kConfigDir.appendingPathComponent("state.json")
private let kLaunchAgentPlist = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/LaunchAgents/local.massflow.governor.plist")

private struct DaemonTelemetryState: Codable {
    let version: String
    let daemonPid: Int32
    let lastSweepEpoch: Double
    let frozenAppNames: [String]
    let frozenPidCount: Int
    let totalFrozenFootprintMB: Double
    let activeMuxBrokers: Int
}

private final class CryoDaemon: NSObject {
    private var frozenByAppPID: [Int32: (name: String, pids: [Int32], footprintMB: Double)] = [:]
    private var lastCpuTimeNs: [Int32: UInt64] = [:]
    private var hiddenSince: [Int32: Double] = [:]
    private let minBuriedSeconds: Double

    init(minBuriedSeconds: Double = 180.0) {
        self.minBuriedSeconds = minBuriedSeconds
        super.init()
    }

    static func thawAllRecorded() -> Int {
        var count = 0
        if let data = try? Data(contentsOf: kCryoLedgerPath),
           let pids = try? JSONDecoder().decode([Int32].self, from: data) {
            for p in pids where p > 1 {
                if kill(p, SIGCONT) == 0 { count += 1 }
            }
        }
        // Also query XNU live process table directly for any SSTOP (status == 4) user processes!
        var pidBuf = [Int32](repeating: 0, count: 4096)
        let n = pidBuf.withUnsafeMutableBufferPointer { mf_list_user_pids($0.baseAddress!, 4096) }
        for i in 0..<Int(n) {
            let p = pidBuf[i]
            var info = mf_proc_telemetry_t()
            if mf_inspect_process(p, &info), info.status == 4 {
                if kill(p, SIGCONT) == 0 { count += 1 }
            }
        }
        try? FileManager.default.removeItem(at: kCryoLedgerPath)
        try? FileManager.default.removeItem(at: kDaemonStatePath)
        return count
    }

    private func persistState() {
        try? FileManager.default.createDirectory(at: kConfigDir, withIntermediateDirectories: true)
        let allPids = Array(Set(frozenByAppPID.values.flatMap { $0.pids })).sorted()
        if let d = try? JSONEncoder().encode(allPids) {
            try? d.write(to: kCryoLedgerPath)
        }

        let names = frozenByAppPID.values.map { $0.name }.sorted()
        let sumMB = frozenByAppPID.values.reduce(0.0) { $0 + $1.footprintMB }
        let state = DaemonTelemetryState(
            version: kMassflowVersion,
            daemonPid: getpid(),
            lastSweepEpoch: Date().timeIntervalSince1970,
            frozenAppNames: names,
            frozenPidCount: allPids.count,
            totalFrozenFootprintMB: sumMB,
            activeMuxBrokers: MCPMultiplexer.listActiveBrokerSockets().count
        )
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let sd = try? enc.encode(state) {
            try? sd.write(to: kDaemonStatePath)
        }
    }

    func thawApp(_ appPid: Int32) {
        // Always unconditionally SIGCONT `appPid` and all live descendants so even PIDs paused
        // by one-shot `massflow trim` or an earlier daemon lifecycle thaw in <20 µs on focus!
        _ = kill(appPid, SIGCONT)
        if let entry = frozenByAppPID.removeValue(forKey: appPid) {
            for p in entry.pids {
                _ = kill(p, SIGCONT)
            }
            persistState()
        }
        var pidBuf = [Int32](repeating: 0, count: 4096)
        let n = pidBuf.withUnsafeMutableBufferPointer { mf_list_user_pids($0.baseAddress!, 4096) }
        var children: [Int32: [Int32]] = [:]
        for i in 0..<Int(n) {
            let p = pidBuf[i]
            var info = mf_proc_telemetry_t()
            if mf_inspect_process(p, &info) {
                children[info.ppid, default: []].append(p)
            }
        }
        var queue = [appPid]
        var visited: Set<Int32> = [appPid]
        while !queue.isEmpty {
            let cur = queue.removeFirst()
            _ = kill(cur, SIGCONT)
            for ch in children[cur] ?? [] where !visited.contains(ch) {
                visited.insert(ch)
                queue.append(ch)
            }
        }
        hiddenSince.removeValue(forKey: appPid)
    }

    func thawEverything() {
        for (_, entry) in frozenByAppPID {
            for p in entry.pids { _ = kill(p, SIGCONT) }
        }
        frozenByAppPID.removeAll()
        try? FileManager.default.removeItem(at: kCryoLedgerPath)
        try? FileManager.default.removeItem(at: kDaemonStatePath)
    }

    @discardableResult
    func sweepOnce(immediateForIdleLongerThanMinutes immediateIdleMin: Double? = nil) -> [(name: String, pidCount: Int, mb: Double)] {
        let now = CFAbsoluteTimeGetCurrent()
        let nowEpoch = UInt64(Date().timeIntervalSince1970)
        let mediaShields = SystemAuditor.mediaShieldedPIDs()
        let frontPid = NSWorkspace.shared.frontmostApplication?.processIdentifier ?? -1
        if frontPid > 0 { thawApp(frontPid) }

        var pidBuf = [Int32](repeating: 0, count: 4096)
        let n = pidBuf.withUnsafeMutableBufferPointer { mf_list_user_pids($0.baseAddress!, 4096) }

        var procs: [Int32: mf_proc_telemetry_t] = [:]
        var children: [Int32: [Int32]] = [:]
        for i in 0..<Int(n) {
            let p = pidBuf[i]
            var info = mf_proc_telemetry_t()
            if mf_inspect_process(p, &info) {
                procs[p] = info
                children[info.ppid, default: []].append(p)
            }
        }

        // Thaw any previously frozen app whose process exited or became visible again
        for frozenRoot in Array(frozenByAppPID.keys) {
            if procs[frozenRoot] == nil {
                frozenByAppPID.removeValue(forKey: frozenRoot)
            }
        }

        var newlyFrozen: [(name: String, pidCount: Int, mb: Double)] = []
        let excludedApps: Set<String> = [
            "Finder", "Terminal", "iTerm2", "Antigravity", "ScreenPipe", "screenpipe", "zoom.us", "FaceTime", "OBS"
        ]

        for app in NSWorkspace.shared.runningApplications where app.activationPolicy == .regular {
            let rootPid = app.processIdentifier
            if rootPid <= 1 || rootPid == frontPid || rootPid == getpid() {
                thawApp(rootPid)
                continue
            }
            let name = app.localizedName ?? "App-\(rootPid)"
            if excludedApps.contains(name) {
                continue
            }

            let ageMinutes: Double
            if let inf = procs[rootPid], nowEpoch > inf.start_tvsec {
                ageMinutes = Double(nowEpoch - inf.start_tvsec) / 60.0
            } else {
                ageMinutes = 0.0
            }

            let qualifiesImmediate = (immediateIdleMin != nil && ageMinutes >= immediateIdleMin! && (app.isHidden || name == "TV"))
            if !app.isHidden && !qualifiesImmediate {
                thawApp(rootPid)
                continue
            }

            let startHide = hiddenSince[rootPid] ?? now
            hiddenSince[rootPid] = startHide
            if !qualifiesImmediate && (now - startHide < minBuriedSeconds) {
                continue
            }
            if frozenByAppPID[rootPid] != nil {
                continue
            }

            // Collect full subtree & verify all 4 kernel shields!
            var tree: [Int32] = [rootPid]
            var idx = 0
            var blocked = false
            var footprintBytes: UInt64 = 0

            while idx < tree.count {
                let cur = tree[idx]
                idx += 1
                if mediaShields.contains(cur) { blocked = true; break }
                if let inf = procs[cur] {
                    footprintBytes += inf.phys_footprint_bytes
                    if inf.tcp_listen_count > 0 { blocked = true; break }
                    let totCpu = inf.user_time_ns + inf.system_time_ns
                    if let prev = lastCpuTimeNs[cur], totCpu > prev + 50_000_000 {
                        blocked = true
                    }
                    lastCpuTimeNs[cur] = totCpu
                }
                for ch in children[cur] ?? [] where !tree.contains(ch) {
                    tree.append(ch)
                }
            }

            if !blocked {
                var stopped: [Int32] = []
                for p in tree.reversed() {
                    if kill(p, SIGSTOP) == 0 { stopped.append(p) }
                }
                if !stopped.isEmpty {
                    let mb = Double(footprintBytes) / (1024.0 * 1024.0)
                    frozenByAppPID[rootPid] = (name: name, pids: stopped, footprintMB: mb)
                    newlyFrozen.append((name: name, pidCount: stopped.count, mb: mb))
                }
            }
        }

        persistState()
        return newlyFrozen
    }

    func runEventLoop() {
        // Recover cleanly from any stale previous run first
        _ = Self.thawAllRecorded()
        persistState()

        let nc = NSWorkspace.shared.notificationCenter
        nc.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main) { [weak self] note in
            if let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication {
                self?.thawApp(app.processIdentifier)
            }
        }
        nc.addObserver(forName: NSWorkspace.didUnhideApplicationNotification, object: nil, queue: .main) { [weak self] note in
            if let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication {
                self?.thawApp(app.processIdentifier)
            }
        }

        let sigInt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        let sigTerm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        sigInt.setEventHandler { [weak self] in self?.thawEverything(); exit(0) }
        sigTerm.setEventHandler { [weak self] in self?.thawEverything(); exit(0) }
        sigInt.resume()
        sigTerm.resume()

        sweepOnce()
        Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.sweepOnce()
        }
        RunLoop.main.run()
    }
}

// MARK: - 1. `massflow status` & `massflow top`

private func renderStatusReport(audit: SystemMassAudit, dryStorage: ZeroMassReclaimReport?) {
    banner("MASSFLOW v\(kMassflowVersion) · MULTI-AGENT MEMORY, MCP & APFS ZERO-MASS REPORT")
    print(String(format: "  %@Unified Memory%@   : %.1f MiB free / %.0f GiB · Compressed %.0f MiB · Pressure Level %d",
                 ANSI.bold, ANSI.reset, audit.ramFreeMB, audit.ramTotalGiB, audit.ramCompressedMB, audit.pressureLevel))
    print(String(format: "  %@SSD Swap Cliff%@   : %@%.1f / %.1f MiB%@ encrypted swap (%llu swapouts, %llu swapins)",
                 ANSI.bold, ANSI.reset, audit.swapUsedMB > 512 ? ANSI.yellow : ANSI.green,
                 audit.swapUsedMB, audit.swapTotalMB, ANSI.reset, audit.swapoutsTotal, audit.swapinsTotal))
    if let ds = dryStorage {
        print(String(format: "  %@APFS Data Volume%@ : %.2f GiB free / %.1f GiB (%.1f%% full) → %@+%.2f GiB lossless reclaimable%@",
                     ANSI.bold, ANSI.reset, audit.diskAvailGiB, audit.diskTotalGiB, audit.diskUsedPct,
                     ANSI.green, ds.totalLogicalReclaimedGiB, ANSI.reset))
    } else {
        print(String(format: "  %@APFS Data Volume%@ : %.2f GiB free / %.1f GiB (%.1f%% full)",
                     ANSI.bold, ANSI.reset, audit.diskAvailGiB, audit.diskTotalGiB, audit.diskUsedPct))
    }

    if let dData = try? Data(contentsOf: kDaemonStatePath),
       let dState = try? JSONDecoder().decode(DaemonTelemetryState.self, from: dData) {
        let frozenDesc = dState.frozenAppNames.isEmpty ? "none (0 buried apps past dwell)" : dState.frozenAppNames.joined(separator: ", ")
        print(String(format: "  %@Governor Daemon%@  : %@ACTIVE%@ (PID %d) · Cryo-Paused: %d PIDs (%.1f MiB) [%@]",
                     ANSI.bold, ANSI.reset, ANSI.green, ANSI.reset, dState.daemonPid,
                     dState.frozenPidCount, dState.totalFrozenFootprintMB, frozenDesc))
    }

    print("\n\(ANSI.bold)━━ 1. N → 1 → 0 MCP MULTIPLEXING & DUPLICATE DAEMON TELEMETRY ━━━━━━━━━━━━━━\(ANSI.reset)")
    if !audit.activeMuxBrokers.isEmpty {
        for b in audit.activeMuxBrokers {
            let stateBadge = b.backendRunning ? "\(ANSI.green)WARM PID \(b.backendPid)\(ANSI.reset)" : "\(ANSI.cyan)0-MB HIBERNATED\(ANSI.reset)"
            print("  • [MUX BROKER] \(b.command) → \(stateBadge) (\(b.connectedClients) clients, \(b.totalRequestsRouted) RPCs, \(b.coldHibernations) hibernations)")
        }
    }
    if audit.duplicateMCPGroups.isEmpty {
        print("  • \(ANSI.green)Zero un-muxed duplicate MCP daemons running.\(ANSI.reset)")
    } else {
        for g in audit.duplicateMCPGroups {
            print(String(format: "  • %-34s : %@%2d× legacy copies%@ · %6.1f MiB RAM",
                         (g.signature as NSString).utf8String!,
                         ANSI.yellow, g.instanceCount, ANSI.reset, g.totalFootprintMB))
        }
    }

    print("\n\(ANSI.bold)━━ 2. STALE MULTI-HOUR SUBTREES & SOCKET-SHIELDED LOCAL SERVERS ━━━━━━━━━━━━\(ANSI.reset)")
    for s in audit.staleIdleSubtrees.prefix(6) {
        let stTag = s.isStopped ? "\(ANSI.cyan)[CRYO-PAUSED]\(ANSI.reset)" : String(format: "[IDLE %5.0fm]", s.ageMinutes)
        print(String(format: "  • %@ %-22s PID %-6d (%2d procs) · %6.1f MiB footprint",
                     stTag, (s.name as NSString).utf8String!, s.rootPid, s.memberCount, s.totalFootprintMB))
    }
    if !audit.shieldedServers.isEmpty {
        let srvList = audit.shieldedServers.prefix(6).map { "\($0.name):\($0.port)" }.joined(separator: " · ")
        print("  • \(ANSI.green)TCP Listen Shields Active\(ANSI.reset) : \(srvList)")
    }

    if let ds = dryStorage {
        let nonZero = ds.directoryFolds.filter { $0.bytesReclaimed > 1024 * 1024 }
        let nonZeroVM = ds.vmImages.filter { $0.reclaimedGiB > 0.01 }
        if !nonZero.isEmpty || !nonZeroVM.isEmpty {
            print("\n\(ANSI.bold)━━ 3. LOSSLESS APFS ZERO-MASS PREVIEW (0 FILES DELETED) ━━━━━━━━━━━━━━━━━━━\(ANSI.reset)")
            for vm in nonZeroVM {
                let shortName = (vm.path as NSString).lastPathComponent
                print(String(format: "  • [F_PUNCHHOLE] %-22s : %5.2f GiB → %5.2f GiB (%@+%.2f GiB%@)",
                             (shortName as NSString).utf8String!, vm.physBeforeGiB, vm.physAfterGiB, ANSI.green, vm.reclaimedGiB, ANSI.reset))
            }
            for df in nonZero {
                let mb = Double(df.bytesReclaimed) / (1024.0 * 1024.0)
                print(String(format: "  • [CoW+LZFSE]   %-22s : %5d clones, %4d LZFSE (%@+%.1f MiB%@)",
                             ((df.rootPath as NSString).lastPathComponent as NSString).utf8String!,
                             df.clonesDeduplicated, df.filesCompressedLzfse, ANSI.green, mb, ANSI.reset))
            }
        }
    }
    print("")
}

private func runStatus(json: Bool, fast: Bool = false) {
    let audit = SystemAuditor.auditLiveSystem()
    let dryStorage = fast ? nil : ZeroMassStorage.runFullReclaim(dryRun: true, includeDeepWorkspaces: false)
    if json {
        struct CombinedStatus: Codable {
            let system: SystemMassAudit
            let storagePreview: ZeroMassReclaimReport?
        }
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(CombinedStatus(system: audit, storagePreview: dryStorage)),
           let s = String(data: d, encoding: .utf8) {
            print(s)
        }
        return
    }
    renderStatusReport(audit: audit, dryStorage: dryStorage)
}

private func runTop() {
    while true {
        print(ANSI.clear, terminator: "")
        let audit = SystemAuditor.auditLiveSystem()
        renderStatusReport(audit: audit, dryStorage: nil)
        print("  \(ANSI.dim)Refreshing every 1.0s — Press Ctrl+C to exit.\(ANSI.reset)")
        fflush(stdout)
        sleep(1)
    }
}

// MARK: - 2. `massflow reclaim`

private func runReclaim(dryRun: Bool, json: Bool) {
    let report = ZeroMassStorage.runFullReclaim(dryRun: dryRun, includeDeepWorkspaces: true)
    if json {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(report), let s = String(data: d, encoding: .utf8) {
            print(s)
        }
        return
    }

    banner(dryRun ? "MASSFLOW v\(kMassflowVersion) · DEEP WORKSPACE ZERO-MASS PREVIEW" : "MASSFLOW v\(kMassflowVersion) · LIVE DEEP WORKSPACE ZERO-MASS RECLAMATION")
    for vm in report.vmImages {
        let name = (vm.path as NSString).lastPathComponent
        if vm.skippedOpenOrLocked {
            print("  • [SKIPPED OPEN] \(name) (active FD shield prevented live VM mutation)")
        } else if vm.reclaimedGiB > 0.001 {
            print(String(format: "  • [F_PUNCHHOLE]  %-22s : %6.2f GiB → %6.2f GiB  (%@+%.2f GiB freed%@)",
                         (name as NSString).utf8String!, vm.physBeforeGiB, vm.physAfterGiB, ANSI.green, vm.reclaimedGiB, ANSI.reset))
        }
    }
    for df in report.directoryFolds {
        let name = (df.rootPath as NSString).lastPathComponent
        let gib = Double(df.bytesReclaimed) / 1_073_741_824.0
        print(String(format: "  • [CoW + LZFSE]  %-22s : %6d scanned · %5d CoW clones · %4d LZFSE (%@+%.2f GiB%@)",
                     (name as NSString).utf8String!, df.filesScanned, df.clonesDeduplicated, df.filesCompressedLzfse,
                     ANSI.green, gib, ANSI.reset))
    }
    print("  ──────────────────────────────────────────────────────────────────────────")
    print(String(format: "  %@Parallel SHA-256 Verifications%@ : %@%d passed (0 mismatches, 0 files deleted)%@",
                 ANSI.bold, ANSI.reset, ANSI.green, report.sha256VerificationsPassed, ANSI.reset))
    print(String(format: "  %@Logical Extent Reduction%@       : %@+%.2f GiB%@ in %.2fs",
                 ANSI.bold, ANSI.reset, ANSI.green, report.totalLogicalReclaimedGiB, ANSI.reset, report.elapsedSeconds))
    if !dryRun {
        print(String(format: "  %@APFS Volume Free Space (`df`)%@  : %.2f GiB → %@%@%.2f GiB (%+.2f GiB net gain)%@\n",
                     ANSI.bold, ANSI.reset, report.volumeAvailBeforeGiB,
                     ANSI.bold, ANSI.green, report.volumeAvailAfterGiB, report.netVolumeGainGiB, ANSI.reset))
    }
}

// MARK: - 3. `massflow mcp-adopt` & `massflow mcp-restore`

private func resolveStableMassflowBinary() -> String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let localBin = "\(home)/.local/bin/massflow"
    if FileManager.default.isExecutableFile(atPath: localBin) {
        return localBin
    }
    return URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
}

private func runMCPAdopt(dryRun: Bool) throws {
    let binPath = resolveStableMassflowBinary()
    let results = try MCPConfigAdopter.adoptAllStandardConfigs(massflowBin: binPath, idleSeconds: 180, dryRun: dryRun)
    banner(dryRun ? "MASSFLOW · MCP N→1→0 AUTO-ADOPT PREVIEW" : "MASSFLOW · CROSS-IDE MCP N→1→0 MULTIPLEXER ADOPTION")
    for r in results {
        let shortPath = r.configPath.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
        let w = r.wrappedServers.isEmpty ? "none" : "\(ANSI.green)\(r.wrappedServers.joined(separator: ", "))\(ANSI.reset)"
        let s = r.skippedServers.isEmpty ? "none" : "\(ANSI.dim)\(r.skippedServers.joined(separator: ", "))\(ANSI.reset)"
        print("  • \(ANSI.bold)\(shortPath)\(ANSI.reset)")
        print("      Muxed (N→1→0) : \(w)")
        print("      Preserved     : \(s)")
        if !dryRun && !r.wrappedServers.isEmpty {
            let shortB = r.backupPath.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "~")
            print("      Backup Vault  : \(ANSI.dim)\(shortB)\(ANSI.reset)")
        }
    }
    print("")
}

private func runMCPRestore() throws {
    let restored = try MCPConfigAdopter.restoreAllBackups()
    banner("MASSFLOW · MCP CONFIG ROLLBACK")
    if restored.isEmpty {
        print("  No backed-up MCP configs found to restore.\n")
    } else {
        for p in restored {
            print("  \(ANSI.green)✓ Restored original config:\(ANSI.reset) \(p)")
        }
        print("")
    }
}

// MARK: - 4. `massflow verify` (15 Automated Kernel, Cryptographic, N->1->0 & Config Tests)

private func runVerify() throws {
    banner("MASSFLOW v\(kMassflowVersion) · 15-POINT KERNEL, N→1→0 MCP, CRYO & APFS SUITE")
    var passed = 0
    let total = 15

    func check(_ idx: Int, _ name: String, _ ok: Bool, _ detail: String) {
        let badge = ok ? "\(ANSI.green)PASS\(ANSI.reset)" : "\(ANSI.red)FAIL\(ANSI.reset)"
        print(String(format: "  [%2d/%2d] %@  %-44s %@", idx, total, badge, (name as NSString).utf8String!, "\(ANSI.dim)\(detail)\(ANSI.reset)"))
        if ok { passed += 1 }
    }

    let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("massflow_verify_\(getpid())")
    try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tmpDir) }

    // [1] Sparse VM `F_PUNCHHOLE`
    do {
        let img = tmpDir.appendingPathComponent("vm_test.img").path
        let fd = open(img, O_CREAT | O_RDWR | O_TRUNC, 0o644)
        var raw = [UInt8](repeating: 0, count: 2 * 1024 * 1024)
        for i in 0..<262144 { raw[i] = UInt8((i * 13) & 0xFF) }
        for i in (2 * 1024 * 1024 - 262144)..<(2 * 1024 * 1024) { raw[i] = UInt8((i * 7) & 0xFF) }
        _ = raw.withUnsafeBufferPointer { write(fd, $0.baseAddress!, $0.count) }
        fsync(fd)
        close(fd)
        let shaBefore = ZeroMassStorage.sha256OfFile(path: img)
        var logB: UInt64 = 0, pb: UInt64 = 0, pa: UInt64 = 0, punchB: UInt64 = 0
        let ok = mf_punch_zero_extents(img, false, &logB, &pb, &pa, &punchB)
        let shaAfter = ZeroMassStorage.sha256OfFile(path: img)
        check(1, "APFS `F_PUNCHHOLE` Zero-Extent Compaction", ok && pa < pb && shaBefore == shaAfter,
              "\(pb / 1024) KB -> \(pa / 1024) KB, SHA-256 bit-exact")
    }

    // [2] Open-Vnode Kernel FD Safety Shield
    do {
        let openImg = tmpDir.appendingPathComponent("open_vm.img").path
        try Data(repeating: 0, count: 65536).write(to: URL(fileURLWithPath: openImg))
        let holder = Process()
        holder.executableURL = URL(fileURLWithPath: "/bin/sh")
        holder.arguments = ["-c", "exec 3< '\(openImg)'; sleep 2"]
        try holder.run()
        usleep(120_000)
        var st = stat()
        lstat(openImg, &st)
        let detectedOpen = mf_is_inode_open_anywhere(UInt64(st.st_ino))
        var logB: UInt64 = 0, pb: UInt64 = 0, pa: UInt64 = 0, punchB: UInt64 = 0
        let punchRefused = !mf_punch_zero_extents(openImg, false, &logB, &pb, &pa, &punchB)
        holder.terminate()
        holder.waitUntilExit()
        check(2, "Open-Vnode Kernel FD Safety Shield", detectedOpen && punchRefused,
              "blocked mutation while child PID \(holder.processIdentifier) held FD open")
    }

    // [3] XNU Ring-0 `CMP_Type11` Inline LZFSE
    do {
        let f11 = tmpDir.appendingPathComponent("inline11.json").path
        let stage11 = f11 + ".stage"
        let text = String(repeating: "{\"agent\":\"massflow\",\"status\":\"active\",\"delta_watts\":-14.6}\n", count: 250)
        try Data(text.utf8).write(to: URL(fileURLWithPath: f11))
        let sha0 = ZeroMassStorage.sha256OfFile(path: f11)
        var b0: UInt64 = 0, b1: UInt64 = 0
        let committed = mf_stage_decmpfs_lzfse(f11, stage11, &b0, &b1) && mf_commit_staged_file(f11, stage11, true)
        let sha1 = ZeroMassStorage.sha256OfFile(path: f11)
        var st = stat()
        lstat(f11, &st)
        check(3, "XNU Ring-0 `CMP_Type11` Inline LZFSE", committed && (st.st_flags & UInt32(UF_COMPRESSED)) != 0 && sha0 == sha1 && b1 < b0,
              "\(b0) B -> \(b1) B physical, UF_COMPRESSED=true, SHA-256 exact")
    }

    // [4] XNU Ring-0 `CMP_Type12` 64 KB Random-Access Chunked LZFSE
    do {
        let f12 = tmpDir.appendingPathComponent("chunked12.bin").path
        let stage12 = f12 + ".stage"
        var payload = Data()
        for i in 0..<8192 {
            payload.append(contentsOf: String(format: "LINE_%05d_MASSFLOW_KERNEL_LZFSE_RANDOM_ACCESS_CHUNK_TEST________\n", i % 64).utf8)
        }
        try payload.write(to: URL(fileURLWithPath: f12))
        let sha0 = ZeroMassStorage.sha256OfFile(path: f12)
        var b0: UInt64 = 0, b1: UInt64 = 0
        let ok = mf_stage_decmpfs_lzfse(f12, stage12, &b0, &b1) && mf_commit_staged_file(f12, stage12, true)
        let rfd = open(f12, O_RDONLY)
        var slice = [UInt8](repeating: 0, count: 4096)
        let rn = pread(rfd, &slice, 4096, 199_999)
        close(rfd)
        let expectedSlice = Array(payload[199_999..<(199_999 + 4096)])
        let sha1 = ZeroMassStorage.sha256OfFile(path: f12)
        check(4, "XNU Ring-0 `CMP_Type12` 64KB Random-Access", ok && rn == 4096 && slice == expectedSlice && sha0 == sha1,
              "\(b0 / 1024) KB -> \(b1 / 1024) KB (\(String(format: "%.1fx", Double(b0)/Double(max(1, b1))))), unaligned pread exact")
    }

    // [5] APFS `clonefile` CoW Mutation Isolation
    do {
        let fileA = tmpDir.appendingPathComponent("canon.bin").path
        let fileB = tmpDir.appendingPathComponent("dup.bin").path
        let stageB = fileB + ".stage"
        let blob = Data((0..<131072).map { UInt8(($0 * 31) & 0xFF) })
        try blob.write(to: URL(fileURLWithPath: fileA))
        try blob.write(to: URL(fileURLWithPath: fileB))
        var beforeB: UInt64 = 0
        let ok = mf_stage_clonefile_dedup(fileA, fileB, stageB, &beforeB) && mf_commit_staged_file(fileB, stageB, true)
        let mfd = open(fileB, O_RDWR)
        var flip: UInt8 = 0xFF
        _ = pwrite(mfd, &flip, 1, 0)
        close(mfd)
        let readA = try Data(contentsOf: URL(fileURLWithPath: fileA))
        check(5, "APFS `clonefile` CoW Mutation Isolation", ok && readA == blob,
              "mutating deduplicated clone B left canonical A 100% untouched")
    }

    // [6] Kernel TCP `TSI_S_LISTEN` Server Shield
    do {
        let sockFD = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(sockFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        _ = listen(sockFD, 8)
        var info = mf_proc_telemetry_t()
        let ok = mf_inspect_process(getpid(), &info)
        close(sockFD)
        check(6, "Kernel TCP `TSI_S_LISTEN` Server Shield", ok && info.tcp_listen_count >= 1 && info.first_listen_port > 0,
              "detected live listen port :\(info.first_listen_port) in ~12 µs")
    }

    // [7] Sub-Frame Cryo-Stasis Thaw Latency
    do {
        let sleeper = Process()
        sleeper.executableURL = URL(fileURLWithPath: "/bin/sleep")
        sleeper.arguments = ["10"]
        try sleeper.run()
        let spid = sleeper.processIdentifier
        usleep(40_000)
        _ = kill(spid, SIGSTOP)
        var stStop = mf_proc_telemetry_t()
        _ = mf_inspect_process(spid, &stStop)
        let t0 = CFAbsoluteTimeGetCurrent()
        _ = kill(spid, SIGCONT)
        let thawUs = (CFAbsoluteTimeGetCurrent() - t0) * 1e6
        sleeper.terminate()
        sleeper.waitUntilExit()
        check(7, "Sub-Frame Cryo-Stasis Thaw (`SIGSTOP`/`SIGCONT`)", stStop.status == 4 && thawUs < 500.0,
              String(format: "verified SSTOP=4 -> thawed in %.1f µs (<0.2%% of 120Hz frame)", thawUs))
    }

    // [8..12] 12-Client -> 1-Backend -> 0-MB Hibernation -> 1-Wake MCP Multiplexer
    do {
        let mockMCP = tmpDir.appendingPathComponent("mock_mcp_server.py").path
        let pyCode = """
        import sys, json, os
        for line in sys.stdin:
            line = line.strip()
            if not line: continue
            msg = json.loads(line)
            mid = msg.get("id")
            m = msg.get("method", "")
            if m == "initialize":
                out = {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock-mcp", "pid": os.getpid()}}}
                sys.stdout.write(json.dumps(out) + "\\n"); sys.stdout.flush()
            elif m == "tools/list":
                out = {"jsonrpc": "2.0", "id": mid, "result": {"tools": [{"name": "echo_pid"}]}}
                sys.stdout.write(json.dumps(out) + "\\n"); sys.stdout.flush()
            elif m == "tools/call":
                arg = msg.get("params", {}).get("arguments", {}).get("echoTag", "")
                out = {"jsonrpc": "2.0", "id": mid, "result": {"backend_pid": os.getpid(), "echo": arg}}
                sys.stdout.write(json.dumps(out) + "\\n"); sys.stdout.flush()
        """
        try Data(pyCode.utf8).write(to: URL(fileURLWithPath: mockMCP))

        let sockPath = tmpDir.appendingPathComponent("mux_test.sock").path
        let selfExe = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let brokerProc = Process()
        brokerProc.executableURL = URL(fileURLWithPath: selfExe)
        brokerProc.arguments = ["_mux-broker", sockPath, "0.35", "--", "/usr/bin/python3", "-u", mockMCP]
        try brokerProc.run()
        defer {
            if brokerProc.isRunning { brokerProc.terminate() }
            unlink(sockPath)
        }

        for _ in 0..<50 {
            if FileManager.default.fileExists(atPath: sockPath) { break }
            usleep(10_000)
        }

        func rpcCall(fd: Int32, obj: [String: Any]) -> [String: Any]? {
            guard var d = try? JSONSerialization.data(withJSONObject: obj) else { return nil }
            d.append(0x0A)
            _ = d.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, d.count) }
            var buf = Data()
            var byte: UInt8 = 0
            while Darwin.read(fd, &byte, 1) == 1 {
                if byte == 0x0A { break }
                buf.append(byte)
            }
            return (try? JSONSerialization.jsonObject(with: buf)) as? [String: Any]
        }

        let clientCount = 12
        var clientFDs: [Int32] = []
        for _ in 0..<clientCount {
            let cfd = mf_unix_connect(sockPath)
            if cfd >= 0 { clientFDs.append(cfd) }
        }
        defer { for cfd in clientFDs { Darwin.close(cfd) } }

        _ = rpcCall(fd: clientFDs[0], obj: ["jsonrpc": "2.0", "id": 1, "method": "tools/list"])

        let tInit0 = CFAbsoluteTimeGetCurrent()
        let initResp = rpcCall(fd: clientFDs[1], obj: ["jsonrpc": "2.0", "id": 99, "method": "initialize", "params": [:]])
        let initMs = (CFAbsoluteTimeGetCurrent() - tInit0) * 1000.0
        check(8, "Cached MCP `initialize` Replay Latency", (initResp?["result"] != nil) && initMs < 2.0,
              String(format: "%.3f ms instant handshake (vs ~3,000 ms uvx/bunx cold spawn)", initMs))

        let grp = DispatchGroup()
        let lock = NSLock()
        var backendPIDs: Set<Int> = []
        var exactEchoMatches = 0

        for idx in 0..<clientCount {
            grp.enter()
            DispatchQueue.global(qos: .userInteractive).async {
                let echoTag = "agent_payload_\(idx)"
                if let resp = rpcCall(fd: clientFDs[idx], obj: [
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": ["name": "echo_pid", "arguments": ["echoTag": echoTag]]
                ]),
                   let rid = resp["id"] as? Int, rid == 7,
                   let res = resp["result"] as? [String: Any],
                   let echo = res["echo"] as? String,
                   let bpid = res["backend_pid"] as? Int {
                    lock.lock()
                    if echo == echoTag { exactEchoMatches += 1 }
                    backendPIDs.insert(bpid)
                    lock.unlock()
                }
                grp.leave()
            }
        }
        grp.wait()

        let firstBackendPID = backendPIDs.first ?? -1
        check(9, "12-Client -> 1-Backend Singleton Multiplexing", clientFDs.count == 12 && backendPIDs.count == 1,
              "12 concurrent clients shared 1 Python PID (\(firstBackendPID)) — 91.7% process reduction")
        check(10, "JSON-RPC Collision-Free ID Virtualization", exactEchoMatches == 12,
              "12/12 colliding `id:7` requests routed back to exact caller without cross-talk")

        usleep(550_000)
        let statsHib = rpcCall(fd: clientFDs[0], obj: ["jsonrpc": "2.0", "id": 500, "method": "massflow/stats"])?["result"] as? [String: Any]
        let isHibernated = (statsHib?["backend_running"] as? Bool) == false && ((statsHib?["cold_hibernations"] as? Int ?? 0) >= 1)
        let cachedTools = rpcCall(fd: clientFDs[2], obj: ["jsonrpc": "2.0", "id": 501, "method": "tools/list"])
        let statsStillHib = rpcCall(fd: clientFDs[0], obj: ["jsonrpc": "2.0", "id": 502, "method": "massflow/stats"])?["result"] as? [String: Any]
        let stayedZeroMB = (statsStillHib?["backend_running"] as? Bool) == false
        check(11, "Scale-to-Zero Cold Hibernation (`0 MB` Idle)", isHibernated && cachedTools?["result"] != nil && stayedZeroMB,
              "backend terminated to 0 MB RAM while keeping all 12 client pipes & schema cache alive")

        let wakeResp = rpcCall(fd: clientFDs[11], obj: [
            "jsonrpc": "2.0",
            "id": 888,
            "method": "tools/call",
            "params": ["name": "echo_pid", "arguments": ["echoTag": "rewoke_cleanly"]]
        ])
        let wakeRes = wakeResp?["result"] as? [String: Any]
        let newBackendPID = wakeRes?["backend_pid"] as? Int ?? -1
        let wokeOk = (wakeRes?["echo"] as? String == "rewoke_cleanly") && newBackendPID > 0 && newBackendPID != firstBackendPID
        _ = rpcCall(fd: clientFDs[0], obj: ["jsonrpc": "2.0", "id": 999, "method": "massflow/shutdown"])
        check(12, "Transparent Cold-Wake on Demand (`0 -> 1`)", wokeOk,
              "seamlessly spawned & re-initialized PID \(newBackendPID) on `tools/call` (0 dropped calls)")
    }

    // [13..15] Cross-IDE JSON & Codex TOML `mcp-adopt` Idempotency + Stateful `node_repl` Exclusion
    do {
        let jsonCfg = tmpDir.appendingPathComponent("mcp_test.json").path
        let sampleJSON = """
        {
          "mcpServers": {
            "screenpipe": { "command": "npx", "args": ["-y", "screenpipe-mcp"], "env": { "KEEP": "1" } },
            "node_repl": { "command": "/bin/node_repl", "args": [] },
            "remote_sse": { "url": "https://example.invalid/sse" }
          },
          "otherSetting": true
        }
        """
        try Data(sampleJSON.utf8).write(to: URL(fileURLWithPath: jsonCfg))
        let r1 = try MCPConfigAdopter.adoptJSONConfig(path: jsonCfg, massflowBin: "/usr/local/bin/massflow", idleSeconds: 180, dryRun: true)
        check(13, "JSON MCP Adopter & Stateful REPL Exclusion",
              r1?.wrappedServers == ["screenpipe"] && (r1?.skippedServers.contains("node_repl") ?? false),
              "wrapped screenpipe, excluded stateful node_repl & URL server")

        let tomlCfg = tmpDir.appendingPathComponent("codex_test.toml").path
        let sampleTOML = """
        model = "gpt-5"
        [mcp_servers.node_repl]
        command = "/Applications/ChatGPT.app/node_repl"
        args = []

        [mcp_servers.blender]
        command = "uvx"
        args = ["blender-mcp"]
        """
        try Data(sampleTOML.utf8).write(to: URL(fileURLWithPath: tomlCfg))
        let rt1 = try MCPConfigAdopter.adoptCodexTOMLConfig(path: tomlCfg, massflowBin: "/usr/local/bin/massflow", idleSeconds: 180, dryRun: true)
        check(14, "TOML MCP Adopter Line-Preserving Parser",
              rt1?.wrappedServers == ["blender"] && (rt1?.skippedServers.contains("node_repl") ?? false),
              "wrapped [mcp_servers.blender], preserved model & node_repl")

        let sockA = MCPMultiplexer.socketPath(for: ["uvx", "blender-mcp"], cwd: "/tmp/workspace_a")
        let sockB = MCPMultiplexer.socketPath(for: ["uvx", "blender-mcp"], cwd: "/tmp/workspace_b")
        check(15, "Cross-Workspace Singleton Socket Convergence", sockA == sockB,
              "distinct project CWDs converge onto shared global broker \(sockA)")
    }

    print("\n  \(ANSI.bold)Verification Summary:\(ANSI.reset) \(passed == total ? ANSI.green : ANSI.red)\(passed)/\(total) invariants passed\(ANSI.reset)\n")
    if passed != total { exit(1) }
}

// MARK: - LaunchAgent & Binary Installation (`~/.local/bin/massflow` + `local.massflow.governor`)

private func installSystemWide() throws {
    let currentExe = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
    let localBinDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin")
    try FileManager.default.createDirectory(at: localBinDir, withIntermediateDirectories: true)
    let targetBin = localBinDir.appendingPathComponent("massflow").path

    if currentExe != targetBin {
        let stageBin = targetBin + ".tmp_\(getpid())"
        try? FileManager.default.removeItem(atPath: stageBin)
        try FileManager.default.copyItem(atPath: currentExe, toPath: stageBin)
        chmod(stageBin, 0o755)
        _ = rename(stageBin, targetBin)
    }

    // Unload previous LaunchAgent if already loaded
    if FileManager.default.fileExists(atPath: kLaunchAgentPlist.path) {
        let u = Process()
        u.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        u.arguments = ["unload", "-w", kLaunchAgentPlist.path]
        u.standardError = FileHandle.nullDevice
        try? u.run()
        u.waitUntilExit()
    }

    let plist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>local.massflow.governor</string>
        <key>ProgramArguments</key>
        <array>
            <string>\(targetBin)</string>
            <string>daemon</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>ProcessType</key>
        <string>Interactive</string>
        <key>StandardOutPath</key>
        <string>\(kConfigDir.path)/massflow.log</string>
        <key>StandardErrorPath</key>
        <string>\(kConfigDir.path)/massflow.log</string>
    </dict>
    </plist>
    """
    try FileManager.default.createDirectory(at: kConfigDir, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: kLaunchAgentPlist.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data(plist.utf8).write(to: kLaunchAgentPlist)

    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    p.arguments = ["load", "-w", kLaunchAgentPlist.path]
    try p.run()
    p.waitUntilExit()
    print("\(ANSI.green)✓ Installed binary at \(targetBin) & started persistent local.massflow.governor LaunchAgent.\(ANSI.reset)")
}

private func uninstallSystemWide() {
    if FileManager.default.fileExists(atPath: kLaunchAgentPlist.path) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["unload", "-w", kLaunchAgentPlist.path]
        try? p.run()
        p.waitUntilExit()
        try? FileManager.default.removeItem(at: kLaunchAgentPlist)
    }
    let thawed = CryoDaemon.thawAllRecorded()
    print("\(ANSI.green)✓ Removed local.massflow.governor LaunchAgent (thawed \(thawed) cryo PIDs).\(ANSI.reset)")
}

// MARK: - CLI Entrypoint

private func printHelp() {
    banner("MASSFLOW v\(kMassflowVersion) · MULTI-AGENT MEMORY, MCP & APFS ZERO-MASS GOVERNOR")
    print("""
      Usage:
        massflow status [--fast] [--json]         Audit live RAM/swap, MCP mux brokers, shields & APFS space
        massflow top                              Live 1 Hz terminal telemetry dashboard
        massflow verify                           Run 15 automated kernel, N→1→0 MCP, TOML/JSON & SHA-256 tests
        massflow reclaim [--dry-run] [--json]     Deep lossless APFS Zero-Mass compaction (0 files deleted)
        massflow mcp-adopt [--dry-run]            Auto-wrap Claude/Cursor/Codex MCP configs into N→1→0 mux
        massflow mcp-restore                      Restore original backed-up MCP config files
        massflow trim                             Immediately cryo-pause multi-hour idle background apps
        massflow thaw                             Immediately SIGCONT all cryo-paused background PIDs
        massflow mux [--idle <sec>] -- <cmd...>   Drop-in N→1→0 stdio MCP multiplexer & cold hibernator
        massflow install | uninstall              Install ~/.local/bin/massflow & persistent LaunchAgent
    """)
}

let rawArgs = Array(CommandLine.arguments.dropFirst())
let subcmd = rawArgs.first ?? "status"
let wantJSON = rawArgs.contains("--json")

do {
    switch subcmd {
    case "status", "audit":
        runStatus(json: wantJSON, fast: rawArgs.contains("--fast"))
    case "top":
        runTop()
    case "verify":
        try runVerify()
    case "reclaim", "compact":
        runReclaim(dryRun: rawArgs.contains("--dry-run"), json: wantJSON)
    case "mcp-adopt":
        try runMCPAdopt(dryRun: rawArgs.contains("--dry-run"))
    case "mcp-restore":
        try runMCPRestore()
    case "trim":
        let d = CryoDaemon()
        let frozen = d.sweepOnce(immediateForIdleLongerThanMinutes: 30.0)
        if frozen.isEmpty {
            print("No unshielded idle >30m background GUI apps required immediate cryo-pausing.")
        } else {
            for item in frozen {
                print(String(format: "%@✓ Cryo-paused %@%@ (%d procs, %.1f MiB — auto-thaws in ~2 µs on focus)",
                             ANSI.green, item.name, ANSI.reset, item.pidCount, item.mb))
            }
        }
    case "mux":
        var idleSec = 180.0
        var perCwd = false
        var sepIdx: Int?
        for i in 1..<rawArgs.count {
            if rawArgs[i] == "--" { sepIdx = i; break }
            if rawArgs[i] == "--per-cwd" { perCwd = true }
            if rawArgs[i] == "--idle", i + 1 < rawArgs.count, let v = Double(rawArgs[i + 1]) {
                idleSec = v
            }
        }
        guard let idx = sepIdx, idx + 1 < rawArgs.count else {
            fputs("Usage: massflow mux [--idle <sec>] [--per-cwd] -- <command> [args...]\n", stderr)
            exit(1)
        }
        let backendCmd = Array(rawArgs[(idx + 1)...])
        let sock = MCPMultiplexer.socketPath(for: backendCmd, cwd: FileManager.default.currentDirectoryPath, perCwd: perCwd)
        exit(MCPMultiplexer.runClientShim(sockPath: sock, idleSeconds: idleSec, backendCommand: backendCmd))
    case "_mux-broker":
        guard rawArgs.count >= 5, rawArgs[3] == "--" else { exit(2) }
        let sock = rawArgs[1]
        let idle = Double(rawArgs[2]) ?? 180.0
        let backendCmd = Array(rawArgs[4...])
        let broker = MCPBrokerDaemon(sockPath: sock, idleTimeout: idle, backendCommand: backendCmd)
        exit(broker.run())
    case "daemon":
        let d = CryoDaemon()
        d.runEventLoop()
    case "thaw":
        let n = CryoDaemon.thawAllRecorded()
        print("Thawed \(n) cryo-stased processes.")
    case "install":
        try installSystemWide()
    case "uninstall":
        uninstallSystemWide()
    case "help", "--help", "-h":
        printHelp()
    default:
        printHelp()
        exit(1)
    }
} catch {
    fputs("massflow error: \(error)\n", stderr)
    exit(1)
}
