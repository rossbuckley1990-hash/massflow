import CMassflowKernel
import CryptoKit
import Darwin
import Foundation

// MARK: - N -> 1 -> 0 Transparent `stdio` MCP Multiplexer & Scale-to-Zero Hibernator (v2.0)

public enum MCPMultiplexer {
    /// Computes deterministic singleton socket path across all IDEs/terminals on the Mac.
    /// By default keys globally by normalized command + args (so Claude Desktop, Cursor, Codex, and all
    /// Claude Code project folders share ONE singleton server), unless `perCwd == true`.
    public static func socketPath(for command: [String], cwd: String, perCwd: Bool = false) -> String {
        let scope = perCwd ? cwd : "global"
        let key = command.joined(separator: "\u{1F}") + "@" + scope
        let digest = SHA256.hash(data: Data(key.utf8))
        let hex = digest.prefix(8).map { String(format: "%02x", $0) }.joined()
        return "/tmp/massflow_mcp_\(hex).sock"
    }

    public static func listActiveBrokerSockets() -> [String] {
        guard let items = try? FileManager.default.contentsOfDirectory(atPath: "/tmp") else { return [] }
        return items
            .filter { $0.hasPrefix("massflow_mcp_") && $0.hasSuffix(".sock") }
            .map { "/tmp/\($0)" }
            .sorted()
    }

    public static func queryBrokerStats(sockPath: String) -> [String: Any]? {
        let fd = mf_unix_connect(sockPath)
        guard fd >= 0 else { return nil }
        defer { Darwin.close(fd) }

        let req: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": "massflow/stats"]
        guard var data = try? JSONSerialization.data(withJSONObject: req) else { return nil }
        data.append(0x0A)
        _ = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, data.count) }

        var buf = Data()
        var b: UInt8 = 0
        while Darwin.read(fd, &b, 1) == 1 {
            if b == 0x0A { break }
            buf.append(b)
            if buf.count > 65536 { break }
        }
        guard let resp = (try? JSONSerialization.jsonObject(with: buf)) as? [String: Any] else { return nil }
        return resp["result"] as? [String: Any]
    }

    public static func runClientShim(sockPath: String, idleSeconds: Double, backendCommand: [String]) -> Int32 {
        var fd = mf_unix_connect(sockPath)
        if fd < 0 {
            spawnBrokerDaemon(sockPath: sockPath, idleSeconds: idleSeconds, backendCommand: backendCommand)
            for _ in 0..<120 {
                usleep(10_000)
                fd = mf_unix_connect(sockPath)
                if fd >= 0 { break }
            }
        }
        guard fd >= 0 else {
            fputs("massflow mux: failed to connect to broker at \(sockPath)\n", stderr)
            return 1
        }

        let doneSem = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInteractive).async {
            var buf = [UInt8](repeating: 0, count: 65536)
            while true {
                let n = Darwin.read(fd, &buf, buf.count)
                if n <= 0 { break }
                var written = 0
                while written < n {
                    let w = buf.withUnsafeBufferPointer { ptr in
                        Darwin.write(STDOUT_FILENO, ptr.baseAddress!.advanced(by: written), n - written)
                    }
                    if w <= 0 { break }
                    written += w
                }
            }
            doneSem.signal()
        }

        var inBuf = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = Darwin.read(STDIN_FILENO, &inBuf, inBuf.count)
            if n <= 0 {
                Darwin.shutdown(fd, SHUT_WR)
                break
            }
            var written = 0
            while written < n {
                let w = inBuf.withUnsafeBufferPointer { ptr in
                    Darwin.write(fd, ptr.baseAddress!.advanced(by: written), n - written)
                }
                if w <= 0 { break }
                written += w
            }
        }

        _ = doneSem.wait(timeout: .now() + 2.0)
        Darwin.close(fd)
        return 0
    }

    private static func spawnBrokerDaemon(sockPath: String, idleSeconds: Double, backendCommand: [String]) {
        let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: exe)
        var args = ["_mux-broker", sockPath, String(format: "%.3f", idleSeconds), "--"]
        args.append(contentsOf: backendCommand)
        proc.arguments = args
        proc.environment = enrichedEnvironment()
        proc.standardInput = FileHandle.nullDevice
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
    }

    public static func enrichedEnvironment() -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let requiredPaths = [
            "\(home)/.local/bin",
            "\(home)/.bun/bin",
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin"
        ]
        let existing = (env["PATH"] ?? "").split(separator: ":").map(String.init)
        var merged: [String] = []
        for p in requiredPaths + existing where !p.isEmpty && !merged.contains(p) {
            merged.append(p)
        }
        env["PATH"] = merged.joined(separator: ":")
        return env
    }
}

// MARK: - Singleton Broker Daemon (`N` Clients -> `1` Active Backend -> `0` Cold Hibernation)

public final class MCPBrokerDaemon {
    private let sockPath: String
    private let idleTimeout: Double
    private let backendCommand: [String]

    private let stateQueue = DispatchQueue(label: "local.massflow.mcp.broker", qos: .userInteractive)
    private var clients: [Int: Int32] = [:]
    private var nextClientID: Int = 1
    private var nextMuxSeq: UInt64 = 1
    private var pendingRoutes: [String: (clientID: Int, originalID: Any)] = [:]

    private var backendProcess: Process?
    private var backendStdinPipe: Pipe?
    private var cachedInitializeResult: [String: Any]?
    private var cachedToolsListResult: [String: Any]?
    private var savedInitializeParams: [String: Any]?
    private var backendInitialized = false
    private var pendingBackendWaiters: [() -> Void] = []
    private var lastActivityTime: Double = CFAbsoluteTimeGetCurrent()

    private var totalRequestsRouted: Int = 0
    private var backendSpawns: Int = 0
    private var coldHibernations: Int = 0

    public init(sockPath: String, idleTimeout: Double, backendCommand: [String]) {
        self.sockPath = sockPath
        self.idleTimeout = idleTimeout
        self.backendCommand = backendCommand
    }

    public func run() -> Int32 {
        signal(SIGPIPE, SIG_IGN)
        let listenFD = mf_unix_listen(sockPath)
        guard listenFD >= 0 else { return 1 }

        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        let checkInterval = max(0.05, min(1.0, idleTimeout / 4.0))
        timer.schedule(deadline: .now() + checkInterval, repeating: checkInterval)
        timer.setEventHandler { [weak self] in
            self?.checkIdleHibernation()
        }
        timer.resume()

        while true {
            let clientFD = Darwin.accept(listenFD, nil, nil)
            if clientFD < 0 {
                if errno == EINTR { continue }
                break
            }
            var cid = 0
            stateQueue.sync {
                cid = self.nextClientID
                self.nextClientID += 1
                self.clients[cid] = clientFD
            }
            DispatchQueue.global(qos: .userInteractive).async {
                self.handleClientLoop(clientID: cid, fd: clientFD)
            }
        }

        Darwin.close(listenFD)
        unlink(sockPath)
        return 0
    }

    private func handleClientLoop(clientID: Int, fd: Int32) {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 16384)

        while true {
            let n = Darwin.read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            buffer.append(chunk, count: n)

            while let nl = buffer.firstIndex(of: 0x0A) {
                let lineData = Data(buffer[..<nl])
                buffer.removeSubrange(...nl)
                if lineData.isEmpty { continue }
                stateQueue.async {
                    self.processClientJSONLine(clientID: clientID, lineData: lineData)
                }
            }
        }

        stateQueue.async {
            self.clients.removeValue(forKey: clientID)
            Darwin.close(fd)
        }
    }

    private func sendJSON(toClient clientID: Int, obj: [String: Any]) {
        guard let fd = clients[clientID],
              var data = try? JSONSerialization.data(withJSONObject: obj, options: []) else { return }
        data.append(0x0A)
        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            var sent = 0
            while sent < data.count {
                let w = Darwin.write(fd, base.advanced(by: sent), data.count - sent)
                if w <= 0 { break }
                sent += w
            }
        }
    }

    private func writeToBackendStdin(_ obj: [String: Any]) {
        guard let fh = backendStdinPipe?.fileHandleForWriting,
              var data = try? JSONSerialization.data(withJSONObject: obj, options: []) else { return }
        data.append(0x0A)
        try? fh.write(contentsOf: data)
    }

    private func processClientJSONLine(clientID: Int, lineData: Data) {
        guard var msg = (try? JSONSerialization.jsonObject(with: lineData)) as? [String: Any] else { return }
        let method = msg["method"] as? String ?? ""
        let origID = msg["id"]

        if method == "massflow/stats", let reqID = origID {
            let pid = backendProcess?.isRunning == true ? Int(backendProcess!.processIdentifier) : 0
            let stats: [String: Any] = [
                "command": backendCommand.joined(separator: " "),
                "backend_running": (pid > 0),
                "backend_pid": pid,
                "connected_clients": max(0, clients.count - 1),
                "total_requests_routed": totalRequestsRouted,
                "backend_spawns": backendSpawns,
                "cold_hibernations": coldHibernations,
                "has_cached_schema": (cachedInitializeResult != nil)
            ]
            sendJSON(toClient: clientID, obj: ["jsonrpc": "2.0", "id": reqID, "result": stats])
            return
        }

        if method == "massflow/shutdown", let reqID = origID {
            terminateBackendIfRunning(countAsHibernation: false)
            sendJSON(toClient: clientID, obj: ["jsonrpc": "2.0", "id": reqID, "result": ["ok": true]])
            unlink(sockPath)
            exit(0)
        }

        if method == "initialize", let reqID = origID {
            if let params = msg["params"] as? [String: Any], savedInitializeParams == nil {
                savedInitializeParams = params
            }
            if let cached = cachedInitializeResult {
                sendJSON(toClient: clientID, obj: ["jsonrpc": "2.0", "id": reqID, "result": cached])
                return
            }
        }

        if method == "notifications/initialized" {
            return
        }

        if method == "tools/list", let reqID = origID, backendProcess == nil, let cachedTools = cachedToolsListResult {
            sendJSON(toClient: clientID, obj: ["jsonrpc": "2.0", "id": reqID, "result": cachedTools])
            return
        }

        lastActivityTime = CFAbsoluteTimeGetCurrent()
        ensureBackendReady { [weak self] in
            guard let self = self else { return }
            self.lastActivityTime = CFAbsoluteTimeGetCurrent()
            if let reqID = origID {
                let seq = self.nextMuxSeq
                self.nextMuxSeq += 1
                let muxID = "mf_\(clientID)_\(seq)_\(method)"
                self.pendingRoutes[muxID] = (clientID, reqID)
                msg["id"] = muxID
                self.totalRequestsRouted += 1
            }
            self.writeToBackendStdin(msg)
        }
    }

    private func ensureBackendReady(_ onReady: @escaping () -> Void) {
        if let proc = backendProcess, proc.isRunning, backendInitialized {
            onReady()
            return
        }
        pendingBackendWaiters.append(onReady)
        if let proc = backendProcess, proc.isRunning {
            return
        }

        guard let first = backendCommand.first else { return }
        let proc = Process()
        proc.environment = MCPMultiplexer.enrichedEnvironment()
        if first.contains("/") {
            proc.executableURL = URL(fileURLWithPath: first)
            proc.arguments = Array(backendCommand.dropFirst())
        } else {
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            proc.arguments = backendCommand
        }

        let inPipe = Pipe()
        let outPipe = Pipe()
        proc.standardInput = inPipe
        proc.standardOutput = outPipe
        proc.standardError = FileHandle.nullDevice

        backendProcess = proc
        backendStdinPipe = inPipe
        backendInitialized = false
        backendSpawns += 1

        let outFD = outPipe.fileHandleForReading.fileDescriptor
        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            self?.readBackendStdoutLoop(fd: outFD, expectedProcess: proc)
        }

        do {
            try proc.run()
            let initParams: [String: Any] = savedInitializeParams ?? [
                "protocolVersion": "2024-11-05",
                "capabilities": [:],
                "clientInfo": ["name": "massflow-mux", "version": "2.0.0"]
            ]
            writeToBackendStdin([
                "jsonrpc": "2.0",
                "id": "__mf_internal_init__",
                "method": "initialize",
                "params": initParams
            ])
        } catch {
            backendProcess = nil
            backendStdinPipe = nil
        }
    }

    private func readBackendStdoutLoop(fd: Int32, expectedProcess: Process) {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 32768)

        while true {
            let n = Darwin.read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            buffer.append(chunk, count: n)

            while let nl = buffer.firstIndex(of: 0x0A) {
                let lineData = Data(buffer[..<nl])
                buffer.removeSubrange(...nl)
                if lineData.isEmpty { continue }
                stateQueue.async {
                    self.handleBackendJSONLine(lineData: lineData)
                }
            }
        }

        stateQueue.async {
            if self.backendProcess === expectedProcess {
                self.backendProcess = nil
                self.backendStdinPipe = nil
                self.backendInitialized = false
            }
        }
    }

    private func handleBackendJSONLine(lineData: Data) {
        guard var msg = (try? JSONSerialization.jsonObject(with: lineData)) as? [String: Any] else { return }

        if let idStr = msg["id"] as? String {
            if idStr == "__mf_internal_init__" {
                if let res = msg["result"] as? [String: Any] {
                    cachedInitializeResult = res
                }
                writeToBackendStdin(["jsonrpc": "2.0", "method": "notifications/initialized"])
                backendInitialized = true
                let waiters = pendingBackendWaiters
                pendingBackendWaiters.removeAll()
                for w in waiters { w() }
                return
            }

            if let route = pendingRoutes.removeValue(forKey: idStr) {
                if idStr.hasSuffix("_tools/list"), let res = msg["result"] as? [String: Any] {
                    cachedToolsListResult = res
                }
                if idStr.hasSuffix("_initialize"), let res = msg["result"] as? [String: Any] {
                    cachedInitializeResult = res
                }
                msg["id"] = route.originalID
                sendJSON(toClient: route.clientID, obj: msg)
                lastActivityTime = CFAbsoluteTimeGetCurrent()
                return
            }
        }

        if msg["id"] == nil {
            for cid in clients.keys {
                sendJSON(toClient: cid, obj: msg)
            }
        }
    }

    private func checkIdleHibernation() {
        guard idleTimeout > 0,
              let proc = backendProcess,
              proc.isRunning,
              backendInitialized,
              pendingRoutes.isEmpty,
              pendingBackendWaiters.isEmpty else { return }

        let idleElapsed = CFAbsoluteTimeGetCurrent() - lastActivityTime
        if idleElapsed >= idleTimeout {
            terminateBackendIfRunning(countAsHibernation: true)
        }
    }

    private func terminateBackendIfRunning(countAsHibernation: Bool) {
        guard let proc = backendProcess else { return }
        if proc.isRunning {
            try? backendStdinPipe?.fileHandleForWriting.close()
            proc.terminate()
            if countAsHibernation {
                coldHibernations += 1
            }
        }
        backendProcess = nil
        backendStdinPipe = nil
        backendInitialized = false
    }
}

// MARK: - Backup-Safe Cross-IDE MCP Auto-Adopter (`Claude Desktop`, `Claude Code`, `Cursor`, `Codex`)

public struct MCPAdoptFileResult: Codable {
    public let configPath: String
    public let backupPath: String
    public let wrappedServers: [String]
    public let skippedServers: [String]
}

public enum MCPConfigAdopter {
    public static var backupRoot: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/massflow/mcp_backups")
    }

    /// Stateful or bundle-relative MCP tools that must remain per-session rather than multiplexed globally.
    public static func shouldSkipServer(name: String, command: String) -> Bool {
        let lowerName = name.lowercased()
        let lowerCmd = command.lowercased()
        if command.isEmpty || command.hasPrefix("./") || command.hasPrefix("../") { return true }
        if lowerName.contains("repl") || lowerCmd.contains("node_repl") { return true }
        if lowerName.contains("computer-use") || lowerCmd.contains("computeruse") { return true }
        return false
    }

    private static func backupKey(for path: String) -> String {
        let digest = SHA256.hash(data: Data(path.utf8))
        let hex = digest.prefix(6).map { String(format: "%02x", $0) }.joined()
        let base = (path as NSString).lastPathComponent
        return "\(hex)_\(base)"
    }

    private static func ensureOriginalBackup(for path: String) throws -> String {
        try FileManager.default.createDirectory(at: backupRoot, withIntermediateDirectories: true)
        let bPath = backupRoot.appendingPathComponent(backupKey(for: path)).path
        // Only write backup if no original backup exists yet, so repeated `mcp-adopt` never overwrites the pre-Massflow original!
        if !FileManager.default.fileExists(atPath: bPath) {
            try FileManager.default.copyItem(atPath: path, toPath: bPath)
        }
        // Record path mapping for `mcp-restore`
        let mapURL = backupRoot.appendingPathComponent("manifest.json")
        var manifest: [String: String] = [:]
        if let d = try? Data(contentsOf: mapURL),
           let m = try? JSONDecoder().decode([String: String].self, from: d) {
            manifest = m
        }
        manifest[path] = bPath
        if let d = try? JSONEncoder().encode(manifest) {
            try? d.write(to: mapURL)
        }
        return bPath
    }

    public static func adoptJSONConfig(path: String, massflowBin: String, idleSeconds: Int = 180, dryRun: Bool = false) throws -> MCPAdoptFileResult? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let rawData = try Data(contentsOf: URL(fileURLWithPath: path))
        guard var root = (try JSONSerialization.jsonObject(with: rawData)) as? [String: Any] else { return nil }
        guard var mcpServers = root["mcpServers"] as? [String: Any] else { return nil }

        var wrapped: [String] = []
        var skipped: [String] = []

        for (srvName, val) in mcpServers {
            guard var entry = val as? [String: Any],
                  let cmd = entry["command"] as? String else {
                skipped.append(srvName)
                continue
            }
            let args = (entry["args"] as? [Any])?.compactMap { "\($0)" } ?? []

            // Already wrapped by massflow?
            if cmd.hasSuffix("/massflow") || cmd == "massflow" {
                skipped.append("\(srvName) (already muxed)")
                continue
            }
            if shouldSkipServer(name: srvName, command: cmd) {
                skipped.append(srvName)
                continue
            }

            var newArgs = ["mux", "--idle", "\(idleSeconds)", "--", cmd]
            newArgs.append(contentsOf: args)
            entry["command"] = massflowBin
            entry["args"] = newArgs
            mcpServers[srvName] = entry
            wrapped.append(srvName)
        }

        var bPath = backupRoot.appendingPathComponent(backupKey(for: path)).path
        if !dryRun && !wrapped.isEmpty {
            bPath = try ensureOriginalBackup(for: path)
            root["mcpServers"] = mcpServers
            let outData = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
            let stage = path + ".mf_tmp_\(getpid())"
            try outData.write(to: URL(fileURLWithPath: stage))
            _ = rename(stage, path)
        }

        return MCPAdoptFileResult(configPath: path, backupPath: bPath, wrappedServers: wrapped.sorted(), skippedServers: skipped.sorted())
    }

    /// Surgical line-preserving TOML updater for `~/.codex/config.toml` `[mcp_servers.<name>]` blocks.
    public static func adoptCodexTOMLConfig(path: String, massflowBin: String, idleSeconds: Int = 180, dryRun: Bool = false) throws -> MCPAdoptFileResult? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.components(separatedBy: "\n")

        // Parse sections `[mcp_servers.<name>]` line ranges
        struct Section {
            let name: String
            let startLine: Int
            let endLine: Int
        }
        var sections: [Section] = []
        var curName: String?
        var curStart = 0

        for (i, rawLine) in lines.enumerated() {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                if let prev = curName {
                    sections.append(Section(name: prev, startLine: curStart, endLine: i))
                    curName = nil
                }
                let inner = String(trimmed.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                if inner.hasPrefix("mcp_servers.") {
                    let rest = String(inner.dropFirst("mcp_servers.".count))
                    if !rest.contains(".") { // skip subtables like `[mcp_servers.foo.env]`
                        curName = rest.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                        curStart = i
                    }
                }
            }
        }
        if let prev = curName {
            sections.append(Section(name: prev, startLine: curStart, endLine: lines.count))
        }

        var updatedLines = lines
        var wrapped: [String] = []
        var skipped: [String] = []

        func parseTOMLString(_ s: String) -> String? {
            let t = s.trimmingCharacters(in: .whitespaces)
            guard t.count >= 2, (t.first == "\"" && t.last == "\"") || (t.first == "'" && t.last == "'") else { return nil }
            return String(t.dropFirst().dropLast())
        }

        func parseTOMLStringArray(_ s: String) -> [String]? {
            let t = s.trimmingCharacters(in: .whitespaces)
            guard t.hasPrefix("[") && t.hasSuffix("]") else { return nil }
            let body = t.dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
            if body.isEmpty { return [] }
            var items: [String] = []
            var inQuotes: Character?
            var cur = ""
            for ch in body {
                if let q = inQuotes {
                    if ch == q {
                        inQuotes = nil
                        items.append(cur)
                        cur = ""
                    } else {
                        cur.append(ch)
                    }
                } else if ch == "\"" || ch == "'" {
                    inQuotes = ch
                }
            }
            return items
        }

        for sec in sections {
            var cmdLineIdx: Int?
            var argsLineIdx: Int?
            var cmdVal: String?
            var argsVal: [String] = []

            for i in (sec.startLine + 1)..<sec.endLine {
                let t = updatedLines[i].trimmingCharacters(in: .whitespaces)
                if t.hasPrefix("#") || !t.contains("=") { continue }
                let parts = t.split(separator: "=", maxSplits: 1).map(String.init)
                let key = parts[0].trimmingCharacters(in: .whitespaces)
                let rhs = parts[1].trimmingCharacters(in: .whitespaces)
                if key == "command" {
                    cmdLineIdx = i
                    cmdVal = parseTOMLString(rhs)
                } else if key == "args" {
                    argsLineIdx = i
                    argsVal = parseTOMLStringArray(rhs) ?? []
                }
            }

            guard let cIdx = cmdLineIdx, let cmd = cmdVal else {
                skipped.append(sec.name)
                continue
            }
            if cmd.hasSuffix("/massflow") || cmd == "massflow" {
                skipped.append("\(sec.name) (already muxed)")
                continue
            }
            if shouldSkipServer(name: sec.name, command: cmd) {
                skipped.append(sec.name)
                continue
            }

            var newArgs = ["mux", "--idle", "\(idleSeconds)", "--", cmd]
            newArgs.append(contentsOf: argsVal)
            let formattedArgs = "[" + newArgs.map { "\"\($0.replacingOccurrences(of: "\"", with: "\\\""))\"" }.joined(separator: ", ") + "]"

            updatedLines[cIdx] = "command = \"\(massflowBin)\""
            if let aIdx = argsLineIdx {
                updatedLines[aIdx] = "args = \(formattedArgs)"
            } else {
                updatedLines[cIdx] += "\nargs = \(formattedArgs)"
            }
            wrapped.append(sec.name)
        }

        var bPath = backupRoot.appendingPathComponent(backupKey(for: path)).path
        if !dryRun && !wrapped.isEmpty {
            bPath = try ensureOriginalBackup(for: path)
            let outText = updatedLines.joined(separator: "\n")
            let stage = path + ".mf_tmp_\(getpid())"
            try Data(outText.utf8).write(to: URL(fileURLWithPath: stage))
            _ = rename(stage, path)
        }

        return MCPAdoptFileResult(configPath: path, backupPath: bPath, wrappedServers: wrapped.sorted(), skippedServers: skipped.sorted())
    }

    public static func adoptAllStandardConfigs(massflowBin: String, idleSeconds: Int = 180, dryRun: Bool = false) throws -> [MCPAdoptFileResult] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var results: [MCPAdoptFileResult] = []
        let jsonPaths = [
            "\(home)/Library/Application Support/Claude/claude_desktop_config.json",
            "\(home)/.cursor/mcp.json",
            "\(home)/.claude.json"
        ]
        for p in jsonPaths {
            if let r = try adoptJSONConfig(path: p, massflowBin: massflowBin, idleSeconds: idleSeconds, dryRun: dryRun) {
                results.append(r)
            }
        }
        let codexPath = "\(home)/.codex/config.toml"
        if let r = try adoptCodexTOMLConfig(path: codexPath, massflowBin: massflowBin, idleSeconds: idleSeconds, dryRun: dryRun) {
            results.append(r)
        }
        return results
    }

    public static func restoreAllBackups() throws -> [String] {
        let mapURL = backupRoot.appendingPathComponent("manifest.json")
        guard let d = try? Data(contentsOf: mapURL),
              let manifest = try? JSONDecoder().decode([String: String].self, from: d) else {
            return []
        }
        var restored: [String] = []
        for (origPath, bPath) in manifest {
            if FileManager.default.fileExists(atPath: bPath) {
                let stage = origPath + ".mf_restore_\(getpid())"
                try? FileManager.default.removeItem(atPath: stage)
                try FileManager.default.copyItem(atPath: bPath, toPath: stage)
                if rename(stage, origPath) == 0 {
                    restored.append(origPath)
                }
            }
        }
        return restored.sorted()
    }
}
