import CMassflowKernel
import Cocoa
import CoreGraphics
import CryptoKit
import Darwin
import Foundation
import IOKit.pwr_mgt

// MARK: - Live Multi-Agent, MCP Duplication & Cryo-Stasis Process Auditor (v2.0)

public struct DuplicateMCPGroup: Codable {
    public let signature: String
    public let instanceCount: Int
    public let pids: [Int32]
    public let totalFootprintMB: Double
    public let reclaimableIfMuxedMB: Double
}

public struct ShieldedServerInfo: Codable {
    public let pid: Int32
    public let port: UInt16
    public let name: String
    public let footprintMB: Double
}

public struct StaleSubtreeInfo: Codable {
    public let rootPid: Int32
    public let name: String
    public let ageMinutes: Double
    public let memberCount: Int
    public let totalFootprintMB: Double
    public let isStopped: Bool
}

public struct ActiveBrokerStatus: Codable {
    public let socketPath: String
    public let command: String
    public let backendRunning: Bool
    public let backendPid: Int
    public let connectedClients: Int
    public let totalRequestsRouted: Int
    public let coldHibernations: Int
}

public struct SystemMassAudit: Codable {
    public let diskTotalGiB: Double
    public let diskAvailGiB: Double
    public let diskUsedPct: Double
    public let ramTotalGiB: Double
    public let ramFreeMB: Double
    public let ramCompressedMB: Double
    public let swapUsedMB: Double
    public let swapTotalMB: Double
    public let swapoutsTotal: UInt64
    public let swapinsTotal: UInt64
    public let pressureLevel: Int32
    public let duplicateMCPGroups: [DuplicateMCPGroup]
    public let totalDuplicateMCPWasteMB: Double
    public let activeMuxBrokers: [ActiveBrokerStatus]
    public let shieldedServers: [ShieldedServerInfo]
    public let staleIdleSubtrees: [StaleSubtreeInfo]
    public let currentlyCryoPausedCount: Int
}

public final class SystemAuditor {
    public static func captureProcessCommandLine(pid: Int32) -> String {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return "" }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return "" }

        var argc: Int32 = 0
        memcpy(&argc, &buf, 4)
        var pos = 4
        while pos < size && buf[pos] != 0 { pos += 1 }
        while pos < size && buf[pos] == 0 { pos += 1 }

        var parts: [String] = []
        var curStart = pos
        while pos < size && parts.count < Int(max(1, min(argc, 16))) {
            if buf[pos] == 0 {
                if pos > curStart, let s = String(bytes: buf[curStart..<pos], encoding: .utf8) {
                    parts.append(s)
                }
                pos += 1
                curStart = pos
            } else {
                pos += 1
            }
        }
        return parts.joined(separator: " ")
    }

    public static func mediaShieldedPIDs() -> Set<Int32> {
        var out: Set<Int32> = []
        var unmanagedDict: Unmanaged<CFDictionary>?
        if IOPMCopyAssertionsByProcess(&unmanagedDict) == kIOReturnSuccess,
           let dict = unmanagedDict?.takeRetainedValue() as? [NSNumber: [[String: Any]]] {
            for (pidNum, assertions) in dict {
                for a in assertions {
                    let t = a["AssertionTrueType"] as? String ?? (a["AssertionType"] as? String ?? "")
                    if t.contains("DisplaySleep") || t.contains("Audio") {
                        out.insert(pidNum.int32Value)
                    }
                }
            }
        }
        return out
    }

    public static func auditLiveSystem() -> SystemMassAudit {
        var sys = mf_sys_metrics_t()
        _ = mf_capture_sys_metrics("/System/Volumes/Data", &sys)

        var pidBuf = [Int32](repeating: 0, count: 4096)
        let n = pidBuf.withUnsafeMutableBufferPointer { mf_list_user_pids($0.baseAddress!, 4096) }

        var procs: [Int32: mf_proc_telemetry_t] = [:]
        var children: [Int32: [Int32]] = [:]
        var cmdLines: [Int32: String] = [:]
        var stoppedCount = 0

        for i in 0..<Int(n) {
            let pid = pidBuf[i]
            var info = mf_proc_telemetry_t()
            if mf_inspect_process(pid, &info) {
                procs[pid] = info
                children[info.ppid, default: []].append(pid)
                cmdLines[pid] = captureProcessCommandLine(pid: pid)
                if info.status == 4 { stoppedCount += 1 }
            }
        }

        // 1. Listening TCP Servers
        var servers: [ShieldedServerInfo] = []
        for (pid, info) in procs where info.tcp_listen_count > 0 {
            let path = withUnsafePointer(to: info.exec_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
            }
            servers.append(ShieldedServerInfo(
                pid: pid,
                port: info.first_listen_port,
                name: (path as NSString).lastPathComponent,
                footprintMB: Double(info.phys_footprint_bytes) / (1024.0 * 1024.0)
            ))
        }
        servers.sort { $0.footprintMB > $1.footprintMB }

        // 2. Duplicate Un-Muxed MCP Server Processes
        var mcpBuckets: [String: [Int32]] = [:]
        for (pid, cmd) in cmdLines {
            let lower = cmd.lowercased()
            guard !lower.contains("massflow") else { continue }
            var sig: String?
            if lower.contains("screenpipe-mcp") {
                sig = "screenpipe-mcp (Node/Bun stdio)"
            } else if lower.contains("blender-mcp") {
                if lower.contains("/uv ") || lower.hasPrefix("uv ") || lower.contains("/bin/uv") {
                    sig = "uvx launcher: blender-mcp"
                } else {
                    sig = "blender-mcp (Python runtime)"
                }
            } else if lower.contains("rcx.ts mcp") || lower.hasSuffix("rightclick mcp") {
                sig = "rightclick-x (MCP stdio)"
            } else if lower.contains("-mcp") && (lower.contains("node ") || lower.contains("python") || lower.contains("uvx")) {
                sig = (cmd as NSString).lastPathComponent
            }
            if let s = sig {
                mcpBuckets[s, default: []].append(pid)
            }
        }

        var dupGroups: [DuplicateMCPGroup] = []
        var totalWasteMB = 0.0
        for (sig, pids) in mcpBuckets where pids.count > 1 {
            let sortedPids = pids.sorted()
            var sumBytes: UInt64 = 0
            for p in sortedPids {
                sumBytes += procs[p]?.phys_footprint_bytes ?? 0
            }
            let totMB = Double(sumBytes) / (1024.0 * 1024.0)
            totalWasteMB += totMB
            dupGroups.append(DuplicateMCPGroup(
                signature: sig,
                instanceCount: sortedPids.count,
                pids: sortedPids,
                totalFootprintMB: totMB,
                reclaimableIfMuxedMB: totMB
            ))
        }
        dupGroups.sort { $0.totalFootprintMB > $1.totalFootprintMB }

        // 3. Active Massflow Mux Brokers
        var activeBrokers: [ActiveBrokerStatus] = []
        for sock in MCPMultiplexer.listActiveBrokerSockets() {
            if let st = MCPMultiplexer.queryBrokerStats(sockPath: sock) {
                activeBrokers.append(ActiveBrokerStatus(
                    socketPath: sock,
                    command: st["command"] as? String ?? "mcp",
                    backendRunning: st["backend_running"] as? Bool ?? false,
                    backendPid: st["backend_pid"] as? Int ?? 0,
                    connectedClients: st["connected_clients"] as? Int ?? 0,
                    totalRequestsRouted: st["total_requests_routed"] as? Int ?? 0,
                    coldHibernations: st["cold_hibernations"] as? Int ?? 0
                ))
            }
        }

        // 4. Stale Multi-Hour Subtrees & Idle Apps
        let nowSec = UInt64(Date().timeIntervalSince1970)
        let frontPid = NSWorkspace.shared.frontmostApplication?.processIdentifier ?? -1
        var staleTrees: [StaleSubtreeInfo] = []

        func subtreeStats(root: Int32) -> (count: Int, bytes: UInt64, hasListener: Bool) {
            var visited: Set<Int32> = [root]
            var queue: [Int32] = [root]
            var bytes: UInt64 = 0
            var listener = false
            while !queue.isEmpty {
                let cur = queue.removeFirst()
                if let inf = procs[cur] {
                    bytes += inf.phys_footprint_bytes
                    if inf.tcp_listen_count > 0 { listener = true }
                }
                for ch in children[cur] ?? [] where !visited.contains(ch) {
                    visited.insert(ch)
                    queue.append(ch)
                }
            }
            return (visited.count, bytes, listener)
        }

        for (pid, info) in procs {
            if pid == frontPid || pid == getpid() { continue }
            let path = withUnsafePointer(to: info.exec_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
            }
            let ageMin = nowSec > info.start_tvsec ? Double(nowSec - info.start_tvsec) / 60.0 : 0.0
            let isClaudeCLI = path.contains("claude-code") && path.hasSuffix("/claude")
            let isTVApp = path.contains("/TV.app/Contents/MacOS/TV")
            if (isClaudeCLI && ageMin >= 30.0) || (isTVApp && ageMin >= 30.0) {
                let st = subtreeStats(root: pid)
                if !st.hasListener && st.bytes > 20 * 1024 * 1024 {
                    staleTrees.append(StaleSubtreeInfo(
                        rootPid: pid,
                        name: isClaudeCLI ? "claude-code session" : "Apple TV.app (idle)",
                        ageMinutes: ageMin,
                        memberCount: st.count,
                        totalFootprintMB: Double(st.bytes) / (1024.0 * 1024.0),
                        isStopped: info.status == 4
                    ))
                }
            }
        }
        staleTrees.sort { $0.totalFootprintMB > $1.totalFootprintMB }

        let totalGiB = Double(sys.disk_total_bytes) / 1_073_741_824.0
        let availGiB = Double(sys.disk_avail_bytes) / 1_073_741_824.0
        let usedPct = totalGiB > 0 ? ((totalGiB - availGiB) / totalGiB) * 100.0 : 0.0

        return SystemMassAudit(
            diskTotalGiB: totalGiB,
            diskAvailGiB: availGiB,
            diskUsedPct: usedPct,
            ramTotalGiB: Double(sys.ram_total_bytes) / 1_073_741_824.0,
            ramFreeMB: Double(sys.ram_free_bytes) / (1024.0 * 1024.0),
            ramCompressedMB: Double(sys.ram_compressed_bytes) / (1024.0 * 1024.0),
            swapUsedMB: Double(sys.swap_used_bytes) / (1024.0 * 1024.0),
            swapTotalMB: Double(sys.swap_total_bytes) / (1024.0 * 1024.0),
            swapoutsTotal: sys.swapouts_total,
            swapinsTotal: sys.swapins_total,
            pressureLevel: sys.pressure_level,
            duplicateMCPGroups: dupGroups,
            totalDuplicateMCPWasteMB: totalWasteMB,
            activeMuxBrokers: activeBrokers,
            shieldedServers: Array(servers.prefix(12)),
            staleIdleSubtrees: staleTrees,
            currentlyCryoPausedCount: stoppedCount
        )
    }
}

// MARK: - Parallel Multi-Core APFS Zero-Mass Engine (v2.0)

public struct VMImageCompactionResult: Codable {
    public let path: String
    public let logicalGiB: Double
    public let physBeforeGiB: Double
    public let physAfterGiB: Double
    public let reclaimedGiB: Double
    public let skippedOpenOrLocked: Bool
}

public struct DirectoryFoldResult: Codable {
    public let rootPath: String
    public let filesScanned: Int
    public let clonesDeduplicated: Int
    public let filesCompressedLzfse: Int
    public let bytesReclaimed: UInt64
}

public struct ZeroMassReclaimReport: Codable {
    public let dryRun: Bool
    public let volumeAvailBeforeGiB: Double
    public let volumeAvailAfterGiB: Double
    public let netVolumeGainGiB: Double
    public let vmImages: [VMImageCompactionResult]
    public let directoryFolds: [DirectoryFoldResult]
    public let totalLogicalReclaimedGiB: Double
    public let sha256VerificationsPassed: Int
    public let elapsedSeconds: Double
}

public enum ZeroMassStorage {
    public static func sha256OfFile(path: String) -> SHA256Digest? {
        let fd = open(path, O_RDONLY)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var hasher = SHA256()
        var buf = [UInt8](repeating: 0, count: 262_144)
        while true {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { break }
            buf.withUnsafeBytes { raw in
                hasher.update(bufferPointer: UnsafeRawBufferPointer(start: raw.baseAddress, count: n))
            }
        }
        return hasher.finalize()
    }

    public static func snapshotOpenInodes() -> Set<UInt64> {
        var buf = [UInt64](repeating: 0, count: 65536)
        let n = buf.withUnsafeMutableBufferPointer { mf_collect_all_open_inodes($0.baseAddress!, 65536) }
        return Set(buf.prefix(Int(max(0, n))))
    }

    public static func discoverCandidateVMImages() -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let candidates = [
            "\(home)/Library/Application Support/Claude/vm_bundles/claudevm.bundle/rootfs.img",
            "\(home)/Library/Application Support/Claude/vm_bundles/claudevm.bundle/sessiondata.img",
            "\(home)/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"
        ]
        return candidates.filter { FileManager.default.fileExists(atPath: $0) }
    }

    /// For source workspaces (`~/src`, `~/Documents`, `~/spawn`), strictly restricts deduplication & LZFSE
    /// folding to untracked dependency/build/cache/result subtrees so `.git/index` stat caches on source code
    /// are never even dirtied!
    private static func isArtifactOrCacheSubpath(_ path: String) -> Bool {
        return path.contains("/node_modules/")
            || path.contains("/.build/")
            || path.contains("/target/")
            || path.contains("/.venv/")
            || path.contains("/venv/")
            || path.contains("/.next/")
            || path.contains("/dist/")
            || path.contains("/__pycache__/")
            || path.contains("/.pytest_cache/")
            || path.contains("/proof/results/")
            || path.contains("/benchmarks/results/")
    }

    public static func foldDirectoryTree(
        rootPath: String,
        artifactSubtreesOnly: Bool,
        enableLzfseCompression: Bool,
        dryRun: Bool,
        openInodes: Set<UInt64>,
        seenBySizeAndHash: inout [String: (path: String, ino: UInt64)],
        shaVerifiedCount: inout Int
    ) -> DirectoryFoldResult {
        let fm = FileManager.default
        guard fm.fileExists(atPath: rootPath) else {
            return DirectoryFoldResult(rootPath: rootPath, filesScanned: 0, clonesDeduplicated: 0, filesCompressedLzfse: 0, bytesReclaimed: 0)
        }

        struct CandidateFile {
            let path: String
            let size: UInt64
            let ino: UInt64
            let physBytes: UInt64
        }

        var sizeBuckets: [UInt64: [CandidateFile]] = [:]
        var coldCompressCandidates: [CandidateFile] = []
        var scanned = 0
        let now = Date().timeIntervalSince1970

        if let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: rootPath),
            includingPropertiesForKeys: nil,
            options: [.skipsPackageDescendants]
        ) {
            for case let url as URL in enumerator {
                let path = url.path
                if path.contains("/.git/") || path.contains("/massflow/") || path.contains("/wattflow/") || path.hasSuffix(".app") {
                    continue
                }
                if artifactSubtreesOnly && !isArtifactOrCacheSubpath(path) {
                    continue
                }

                var st = stat()
                guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { continue }
                if st.st_nlink > 1 || st.st_size < 8192 { continue }
                let ino = UInt64(st.st_ino)
                if openInodes.contains(ino) { continue }
                scanned += 1

                let sz = UInt64(st.st_size)
                let phys = UInt64(st.st_blocks) * 512
                if phys == 0 { continue }

                let cand = CandidateFile(path: path, size: sz, ino: ino, physBytes: phys)
                if sz >= 16384 && sz <= 128 * 1024 * 1024 {
                    sizeBuckets[sz, default: []].append(cand)
                }

                let ageSec = now - Double(st.st_mtimespec.tv_sec)
                if enableLzfseCompression && ageSec > 600 && (st.st_flags & UInt32(UF_COMPRESSED)) == 0 && phys >= 16384 {
                    let isColdArtifact = path.contains("/.build/")
                        || path.contains("/target/debug/")
                        || path.contains("/target/release/deps/")
                        || path.contains("/proof/results/")
                        || path.contains("/benchmarks/results/")
                        || path.contains("/scratch-workspaces/")
                    if isColdArtifact && (path.hasSuffix(".o") || path.hasSuffix(".rlib") || path.hasSuffix(".rmeta") || path.hasSuffix(".swiftmodule") || path.hasSuffix(".swiftdoc") || path.hasSuffix(".swiftsourceinfo") || path.hasSuffix(".d") || path.hasSuffix(".dia") || path.hasSuffix(".json") || path.hasSuffix(".jsonl") || path.hasSuffix(".log") || path.hasSuffix(".txt") || path.hasSuffix(".md") || path.hasSuffix(".js") || path.hasSuffix(".map") || path.hasSuffix(".a")) {
                        coldCompressCandidates.append(cand)
                    }
                }
            }
        }

        // Flatten only multi-file size buckets (or sizes already in global seen map) for parallel SHA-256!
        var existingSizes = Set<UInt64>()
        for k in seenBySizeAndHash.keys {
            if let colon = k.firstIndex(of: ":"), let sz = UInt64(k[..<colon]) {
                existingSizes.insert(sz)
            }
        }

        var toHash: [CandidateFile] = []
        for (sz, list) in sizeBuckets where list.count >= 2 || existingSizes.contains(sz) {
            toHash.append(contentsOf: list)
        }

        // Multi-Core Parallel Hardware FEAT_SHA256 Hashing!
        var computedKeys = [String?](repeating: nil, count: toHash.count)
        if !toHash.isEmpty {
            computedKeys.withUnsafeMutableBufferPointer { outBuf in
                DispatchQueue.concurrentPerform(iterations: toHash.count) { idx in
                    let item = toHash[idx]
                    if let d = sha256OfFile(path: item.path) {
                        let hex = d.map { String(format: "%02x", $0) }.joined()
                        outBuf[idx] = "\(item.size):\(hex)"
                    }
                }
            }
        }

        var clones = 0
        var compressed = 0
        var reclaimed: UInt64 = 0
        var deduplicatedPaths: Set<String> = []

        for idx in 0..<toHash.count {
            guard let key = computedKeys[idx] else { continue }
            shaVerifiedCount += 1
            let cand = toHash[idx]

            if let canon = seenBySizeAndHash[key], canon.ino != cand.ino, fm.fileExists(atPath: canon.path) {
                var stCan = stat(), stDup = stat()
                if lstat(canon.path, &stCan) == 0, lstat(cand.path, &stDup) == 0, stCan.st_dev == stDup.st_dev {
                    if dryRun {
                        clones += 1
                        reclaimed += cand.physBytes
                        deduplicatedPaths.insert(cand.path)
                    } else {
                        let stage = cand.path + ".mf_clone_\(getpid())"
                        var beforeB: UInt64 = 0
                        if mf_stage_clonefile_dedup(canon.path, cand.path, stage, &beforeB) {
                            if mf_commit_staged_file(cand.path, stage, false) {
                                clones += 1
                                reclaimed += beforeB
                                deduplicatedPaths.insert(cand.path)
                            }
                        }
                    }
                }
            } else {
                seenBySizeAndHash[key] = (cand.path, cand.ino)
            }
        }

        // Pass 2: XNU Ring-0 Transparent `decmpfs` LZFSE Compression on Cold Artifacts
        for cand in coldCompressCandidates where !deduplicatedPaths.contains(cand.path) {
            if dryRun {
                compressed += 1
                reclaimed += UInt64(Double(cand.physBytes) * 0.65)
            } else {
                guard let origDigest = sha256OfFile(path: cand.path) else { continue }
                let stage = cand.path + ".mf_lzfse_\(getpid())"
                var b0: UInt64 = 0, b1: UInt64 = 0
                if mf_stage_decmpfs_lzfse(cand.path, stage, &b0, &b1) {
                    if let stageDigest = sha256OfFile(path: stage), stageDigest == origDigest, b0 > b1 {
                        shaVerifiedCount += 1
                        if mf_commit_staged_file(cand.path, stage, false) {
                            compressed += 1
                            reclaimed += (b0 - b1)
                        }
                    } else {
                        unlink(stage)
                    }
                }
            }
        }

        return DirectoryFoldResult(
            rootPath: rootPath,
            filesScanned: scanned,
            clonesDeduplicated: clones,
            filesCompressedLzfse: compressed,
            bytesReclaimed: reclaimed
        )
    }

    public static func runFullReclaim(dryRun: Bool, includeDeepWorkspaces: Bool = true) -> ZeroMassReclaimReport {
        let t0 = CFAbsoluteTimeGetCurrent()
        var sysBefore = mf_sys_metrics_t()
        _ = mf_capture_sys_metrics("/System/Volumes/Data", &sysBefore)

        var vmResults: [VMImageCompactionResult] = []
        var totalLogicalBytes: UInt64 = 0
        var shaChecks = 0

        for imgPath in discoverCandidateVMImages() {
            var logB: UInt64 = 0, pb: UInt64 = 0, pa: UInt64 = 0, punchB: UInt64 = 0
            let ok = mf_punch_zero_extents(imgPath, dryRun, &logB, &pb, &pa, &punchB)
            if ok {
                let saved = pb > pa ? (pb - pa) : 0
                totalLogicalBytes += saved
                vmResults.append(VMImageCompactionResult(
                    path: imgPath,
                    logicalGiB: Double(logB) / 1_073_741_824.0,
                    physBeforeGiB: Double(pb) / 1_073_741_824.0,
                    physAfterGiB: Double(pa) / 1_073_741_824.0,
                    reclaimedGiB: Double(saved) / 1_073_741_824.0,
                    skippedOpenOrLocked: false
                ))
            } else {
                vmResults.append(VMImageCompactionResult(
                    path: imgPath,
                    logicalGiB: 0, physBeforeGiB: 0, physAfterGiB: 0, reclaimedGiB: 0,
                    skippedOpenOrLocked: true
                ))
            }
        }

        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var foldTargets: [(path: String, artifactsOnly: Bool, compressLzfse: Bool)] = [
            ("\(home)/.gemini/antigravity/scratch", false, true),
            ("\(home)/Library/Application Support/Claude/scratch-workspaces", false, true),
            ("\(home)/.cache/uv", false, false),
            ("\(home)/.bun/install/cache", false, false),
            ("\(home)/.npm/_cacache", false, false)
        ]
        if includeDeepWorkspaces {
            foldTargets.append((path: "\(home)/src", artifactsOnly: true, compressLzfse: true))
            foldTargets.append((path: "\(home)/spawn", artifactsOnly: true, compressLzfse: true))
            foldTargets.append((path: "\(home)/Documents", artifactsOnly: true, compressLzfse: true))
        }

        var seenHashes: [String: (path: String, ino: UInt64)] = [:]
        var dirResults: [DirectoryFoldResult] = []
        let openInos = snapshotOpenInodes()

        for target in foldTargets where FileManager.default.fileExists(atPath: target.path) {
            let res = foldDirectoryTree(
                rootPath: target.path,
                artifactSubtreesOnly: target.artifactsOnly,
                enableLzfseCompression: target.compressLzfse,
                dryRun: dryRun,
                openInodes: openInos,
                seenBySizeAndHash: &seenHashes,
                shaVerifiedCount: &shaChecks
            )
            totalLogicalBytes += res.bytesReclaimed
            dirResults.append(res)
        }

        if !dryRun {
            sync()
            usleep(200_000)
        }

        var sysAfter = mf_sys_metrics_t()
        _ = mf_capture_sys_metrics("/System/Volumes/Data", &sysAfter)

        let availBefore = Double(sysBefore.disk_avail_bytes) / 1_073_741_824.0
        let availAfter = Double(sysAfter.disk_avail_bytes) / 1_073_741_824.0

        return ZeroMassReclaimReport(
            dryRun: dryRun,
            volumeAvailBeforeGiB: availBefore,
            volumeAvailAfterGiB: availAfter,
            netVolumeGainGiB: availAfter - availBefore,
            vmImages: vmResults,
            directoryFolds: dirResults,
            totalLogicalReclaimedGiB: Double(totalLogicalBytes) / 1_073_741_824.0,
            sha256VerificationsPassed: shaChecks,
            elapsedSeconds: CFAbsoluteTimeGetCurrent() - t0
        )
    }
}
