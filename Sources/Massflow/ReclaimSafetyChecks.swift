import CMassflowKernel
import Darwin
import Foundation

// MARK: - `massflow verify` [16..22]: adversarial reclaim-safety checks
//
// Each check attacks one way an in-place rewrite could lose data or metadata, and asserts the
// kernel commit path fails closed (file untouched) or rolls back (no bytes lost).

private var gBeforeSwapAction: ((String) -> Void)?

private func installBeforeSwapHook(_ action: ((String) -> Void)?) {
    gBeforeSwapAction = action
    if action == nil {
        mf_set_test_hook_before_swap(nil)
    } else {
        mf_set_test_hook_before_swap { cPath in
            guard let cPath else { return }
            gBeforeSwapAction?(String(cString: cPath))
        }
    }
}

private func xattrs(_ path: String) -> [String: Data] {
    var out: [String: Data] = [:]
    let n = listxattr(path, nil, 0, XATTR_NOFOLLOW)
    guard n > 0 else { return out }
    var names = [CChar](repeating: 0, count: n)
    guard listxattr(path, &names, n, XATTR_NOFOLLOW) == n else { return out }
    var start = 0
    for i in 0..<n where names[i] == 0 {
        let name = names[start..<i].withUnsafeBufferPointer { String(cString: Array($0) + [0]) }
        start = i + 1
        let len = getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW)
        guard len >= 0 else { continue }
        var buf = [UInt8](repeating: 0, count: max(len, 1))
        let got = getxattr(path, name, &buf, len, 0, XATTR_NOFOLLOW)
        out[name] = Data(buf.prefix(max(0, got)))
    }
    return out
}

private func setX(_ path: String, _ name: String, _ value: String) {
    let d = Array(value.utf8)
    _ = setxattr(path, name, d, d.count, 0, XATTR_NOFOLLOW)
}

private func lstatOf(_ path: String) -> stat {
    var st = stat()
    _ = lstat(path, &st)
    return st
}

private func aclText(_ path: String) -> String {
    guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else { return "" }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var len: Int = 0
    guard let t = acl_to_text(acl, &len) else { return "" }
    defer { acl_free(UnsafeMutableRawPointer(t)) }
    return String(cString: t)
}

private func run(_ exe: String, _ args: [String]) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: exe)
    p.arguments = args
    p.standardError = FileHandle.nullDevice
    try? p.run()
    p.waitUntilExit()
}

private func setMtime(_ path: String, secondsSince1970: Int) {
    var ts = [timespec(tv_sec: secondsSince1970, tv_nsec: 123_456_789),
              timespec(tv_sec: secondsSince1970, tv_nsec: 123_456_789)]
    _ = utimensat(AT_FDCWD, path, &ts, AT_SYMLINK_NOFOLLOW)
}

private func stageLeftovers(_ dir: URL) -> [String] {
    let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
    return names.filter { $0.hasPrefix(".mfstage-") }
}

private func fingerprint(_ path: String) -> mf_file_fingerprint_t {
    var fp = mf_file_fingerprint_t()
    _ = mf_capture_fingerprint(path, &fp)
    return fp
}

func runReclaimSafetyChecks(tmpDir root: URL, check: (Int, String, Bool, String) -> Void) throws {
    let fm = FileManager.default
    let dir = root.appendingPathComponent("reclaim_safety")
    try fm.createDirectory(at: dir, withIntermediateDirectories: true)
    let blob = Data((0..<200_000).map { UInt8(($0 * 131 + 7) & 0xFF) })

    // [16] Edit after scan (the old TOCTOU): fingerprint, then the user edits, then commit.
    do {
        let a = dir.appendingPathComponent("t16_canon.bin").path
        let b = dir.appendingPathComponent("t16_dup.bin").path
        try blob.write(to: URL(fileURLWithPath: a))
        try blob.write(to: URL(fileURLWithPath: b))
        var fp = fingerprint(b)
        usleep(5_000)
        var edited = blob
        edited[100] ^= 0xFF
        try edited.write(to: URL(fileURLWithPath: b))   // same size, same inode, new bytes
        var before: UInt64 = 0
        let rc = mf_dedup_replace_with_clone(a, b, &fp, &before, nil, 0)
        let after = try Data(contentsOf: URL(fileURLWithPath: b))
        check(16, "Edit-After-Scan TOCTOU Refused", rc == MF_COMMIT_SKIP_CHANGED && after == edited,
              "rc=\(rc): user's post-scan edit kept, dedup aborted")
    }

    // [17] Dedup metadata fidelity: the duplicate keeps ITS xattrs (incl. quarantine), ACL,
    //      mode, group, UF_HIDDEN, mtime and birthtime — not the canonical file's.
    do {
        let a = dir.appendingPathComponent("t17_canon.bin").path
        let b = dir.appendingPathComponent("t17_dup.bin").path
        try blob.write(to: URL(fileURLWithPath: a))
        try blob.write(to: URL(fileURLWithPath: b))
        setX(a, "com.example.canon-only", "canon")
        setX(b, "com.apple.quarantine", "0081;6740b9f0;Safari;8C6F4E2A-0000-0000-0000-000000000000")
        setX(b, "com.example.dup-only", "dup")
        setX(b, "com.apple.metadata:_kMDItemUserTags", "bplist00-tag")
        chmod(b, 0o640)
        run("/bin/chmod", ["+a", "group:everyone allow read", b])
        _ = chflags(b, UInt32(UF_HIDDEN))
        setMtime(b, secondsSince1970: 1_600_000_000)
        let x0 = xattrs(b), st0 = lstatOf(b), acl0 = aclText(b)
        var fp = fingerprint(b)
        var before: UInt64 = 0
        let rc = mf_dedup_replace_with_clone(a, b, &fp, &before, nil, 0)
        let x1 = xattrs(b), st1 = lstatOf(b), acl1 = aclText(b)
        let content = try Data(contentsOf: URL(fileURLWithPath: b))
        let ok = rc == MF_COMMIT_OK
            && st1.st_ino != st0.st_ino               // really replaced by the clone
            && content == blob
            && x1 == x0                               // exactly the dup's own xattrs
            && x1["com.example.canon-only"] == nil
            && !acl0.isEmpty && acl1 == acl0
            && (st1.st_mode & 0o7777) == 0o640
            && st1.st_gid == st0.st_gid
            && (st1.st_flags & UInt32(UF_HIDDEN)) != 0
            && st1.st_mtimespec.tv_sec == st0.st_mtimespec.tv_sec && st1.st_mtimespec.tv_nsec == st0.st_mtimespec.tv_nsec
            && st1.st_birthtimespec.tv_sec == st0.st_birthtimespec.tv_sec && st1.st_birthtimespec.tv_nsec == st0.st_birthtimespec.tv_nsec
            && stageLeftovers(dir).isEmpty
        check(17, "Dedup Keeps xattrs/Quarantine/ACL/Flags", ok,
              "rc=\(rc), \(x1.count) xattrs, ACL \(acl1.isEmpty ? "missing" : "kept"), mode \(String(st1.st_mode & 0o7777, radix: 8))")
    }

    // [18] LZFSE metadata fidelity on a read-only (0444) file with xattrs.
    do {
        let f = dir.appendingPathComponent("t18_cold.json").path
        let text = String(repeating: "{\"cold\":true,\"artifact\":\"build-log\",\"n\":12345}\n", count: 2000)
        try Data(text.utf8).write(to: URL(fileURLWithPath: f))
        setX(f, "com.apple.quarantine", "0083;6740b9f0;curl;")
        setX(f, "com.example.provenance", "ci-run-42")
        setMtime(f, secondsSince1970: 1_650_000_000)
        chmod(f, 0o444)
        let x0 = xattrs(f), st0 = lstatOf(f)
        var fp = fingerprint(f)
        var b0: UInt64 = 0, b1: UInt64 = 0
        let rc = mf_lzfse_compress_in_place(f, &fp, &b0, &b1, nil, 0)
        let x1 = xattrs(f), st1 = lstatOf(f)
        let content = try Data(contentsOf: URL(fileURLWithPath: f))
        let ok = rc == MF_COMMIT_OK
            && (st1.st_flags & UInt32(UF_COMPRESSED)) != 0
            && content == Data(text.utf8)
            && x1 == x0
            && (st1.st_mode & 0o7777) == 0o444
            && st1.st_mtimespec.tv_sec == st0.st_mtimespec.tv_sec && st1.st_mtimespec.tv_nsec == st0.st_mtimespec.tv_nsec
            && stageLeftovers(dir).isEmpty
        check(18, "LZFSE Keeps xattrs/Mode/Times (0444 file)", ok,
              "rc=\(rc), \(b0 / 1024) KB -> \(b1 / 1024) KB, \(x1.count) xattrs kept")
    }

    // [19] Another process holds the duplicate open for writing → refuse.
    do {
        let a = dir.appendingPathComponent("t19_canon.bin").path
        let b = dir.appendingPathComponent("t19_dup.bin").path
        try blob.write(to: URL(fileURLWithPath: a))
        try blob.write(to: URL(fileURLWithPath: b))
        let ino0 = lstatOf(b).st_ino
        let holder = Process()
        holder.executableURL = URL(fileURLWithPath: "/bin/sh")
        holder.arguments = ["-c", "exec 3>>'\(b)'; sleep 3"]
        try holder.run()
        usleep(150_000)
        var fp = fingerprint(b)
        var before: UInt64 = 0
        let rc = mf_dedup_replace_with_clone(a, b, &fp, &before, nil, 0)
        holder.terminate()
        holder.waitUntilExit()
        check(19, "Open-Writer Shield (live FD in other PID)", rc == MF_COMMIT_SKIP_OPEN && lstatOf(b).st_ino == ino0,
              "rc=\(rc): inode untouched while PID \(holder.processIdentifier) held it open")
    }

    // [20] A write lands in the window right before RENAME_SWAP → swap back, no bytes lost.
    do {
        let a = dir.appendingPathComponent("t20_canon.bin").path
        let b = dir.appendingPathComponent("t20_dup.bin").path
        try blob.write(to: URL(fileURLWithPath: a))
        try blob.write(to: URL(fileURLWithPath: b))
        let ino0 = lstatOf(b).st_ino
        var fp = fingerprint(b)
        installBeforeSwapHook { path in
            guard path == b, let h = FileHandle(forUpdatingAtPath: path) else { return }
            h.seek(toFileOffset: 10)
            h.write(Data([0xDE, 0xAD, 0xBE, 0xEF]))
            try? h.close()
        }
        var before: UInt64 = 0
        let rc = mf_dedup_replace_with_clone(a, b, &fp, &before, nil, 0)
        installBeforeSwapHook(nil)
        let after = try Data(contentsOf: URL(fileURLWithPath: b))
        var expected = blob
        expected.replaceSubrange(10..<14, with: [0xDE, 0xAD, 0xBE, 0xEF])
        check(20, "Write-During-Swap Rolled Back Losslessly", rc == MF_COMMIT_RACE_ROLLED_BACK && after == expected
              && lstatOf(b).st_ino == ino0 && stageLeftovers(dir).isEmpty,
              "rc=\(rc): racing write preserved, original inode restored")
    }

    // [21] Same size + forged "hash match" but different bytes → refuse.
    do {
        let a = dir.appendingPathComponent("t21_canon.bin").path
        let b = dir.appendingPathComponent("t21_dup.bin").path
        var other = blob
        other[blob.count - 1] ^= 0x01
        try other.write(to: URL(fileURLWithPath: a))
        try blob.write(to: URL(fileURLWithPath: b))
        var fp = fingerprint(b)
        var before: UInt64 = 0
        let rc = mf_dedup_replace_with_clone(a, b, &fp, &before, nil, 0)
        let after = try Data(contentsOf: URL(fileURLWithPath: b))
        check(21, "Byte-Exact Compare Beats Hash Trust", rc == MF_COMMIT_SKIP_MISMATCH && after == blob && stageLeftovers(dir).isEmpty,
              "rc=\(rc): 1-byte difference caught before swap")
    }

    // [22] End-to-end accounting: 3 identical files, one is raced → counts are honest.
    do {
        let e2e = dir.appendingPathComponent("t22")
        try fm.createDirectory(at: e2e, withIntermediateDirectories: true)
        let paths = ["one.bin", "two.bin", "three.bin"].map { e2e.appendingPathComponent($0).path }
        for p in paths { try blob.write(to: URL(fileURLWithPath: p)) }
        var swaps = 0
        var racedPath = ""
        installBeforeSwapHook { path in
            swaps += 1
            if swaps == 2, let h = FileHandle(forUpdatingAtPath: path) {
                racedPath = path
                h.seekToEndOfFile()
                h.write(Data("appended-by-racing-writer".utf8))
                try? h.close()
            }
        }
        var seen: [String: (path: String, ino: UInt64)] = [:]
        var tally = ReclaimSafetyTally()
        let res = ZeroMassStorage.foldDirectoryTree(
            rootPath: e2e.path, artifactSubtreesOnly: false, enableLzfseCompression: false,
            dryRun: false, openInodes: [], seenBySizeAndHash: &seen, tally: &tally)
        installBeforeSwapHook(nil)
        let racedData = racedPath.isEmpty ? Data() : ((try? Data(contentsOf: URL(fileURLWithPath: racedPath))) ?? Data())
        let ok = tally.filesHashed == 3
            && tally.verifiedCommits == 1 && res.clonesDeduplicated == 1
            && tally.racesRolledBack == 1
            && racedData.count == blob.count + 25
            && stageLeftovers(e2e).isEmpty
        check(22, "Honest Commit Accounting (hashed ≠ verified)", ok,
              "hashed \(tally.filesHashed) · verified \(tally.verifiedCommits) · rolled back \(tally.racesRolledBack)")
    }
}
