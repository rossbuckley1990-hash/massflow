#ifndef MASSFLOW_KERNEL_H
#define MASSFLOW_KERNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t  pid;
    int32_t  ppid;
    int32_t  pgid;
    uint32_t status;          // SIDL=1, SRUN=2, SSLEEP=3, SSTOP=4, SZOMB=5
    uint32_t flags;
    uint64_t start_tvsec;
    uint64_t phys_footprint_bytes;
    uint64_t user_time_ns;
    uint64_t system_time_ns;
    uint64_t disk_bytes_written;
    uint32_t tcp_listen_count;
    uint16_t first_listen_port;
    uint32_t tcp_established_count;
    char     exec_path[1024];
} mf_proc_telemetry_t;

typedef struct {
    uint64_t disk_total_bytes;
    uint64_t disk_avail_bytes;
    uint64_t ram_total_bytes;
    uint64_t ram_free_bytes;
    uint64_t ram_compressed_bytes;
    uint64_t swap_used_bytes;
    uint64_t swap_total_bytes;
    uint64_t swapouts_total;
    uint64_t swapins_total;
    int32_t  pressure_level;
} mf_sys_metrics_t;

// Identity + change-detection snapshot of a file, captured with lstat() BEFORE hashing so any
// edit between scan and commit is detected (ctime cannot be forged from userspace).
typedef struct {
    uint64_t dev;
    uint64_t ino;
    uint64_t size;
    uint64_t blocks;
    int64_t  atime_sec;
    int64_t  atime_nsec;
    int64_t  mtime_sec;
    int64_t  mtime_nsec;
    int64_t  ctime_sec;
    int64_t  ctime_nsec;
    uint32_t nlink;
    uint32_t flags;
    uint32_t uid;
    uint32_t mode;
} mf_file_fingerprint_t;

// Outcomes of an in-place rewrite. Only MF_COMMIT_OK changed anything on disk.
#define MF_COMMIT_OK                   0  // replaced, metadata mirrored, read back byte-identical
#define MF_COMMIT_SKIP_CHANGED         1  // file changed (or vanished) since it was scanned
#define MF_COMMIT_SKIP_OPEN            2  // another process holds the file open
#define MF_COMMIT_SKIP_UNSAFE          3  // hardlinked, foreign-owned, special flags, resource fork...
#define MF_COMMIT_SKIP_MISMATCH        4  // staged bytes differ from the file (hash collision / edit)
#define MF_COMMIT_SKIP_INCOMPRESSIBLE  5  // LZFSE would not save space
#define MF_COMMIT_RACE_ROLLED_BACK     6  // written/opened during the swap; original swapped back
#define MF_COMMIT_ERR_IO               7  // I/O error before the swap; nothing changed
#define MF_COMMIT_ERR_METADATA         8  // could not mirror xattrs/ACL/mode/flags/times; nothing changed
#define MF_COMMIT_ERR_VERIFY           9  // post-swap read-back failed; original swapped back
#define MF_COMMIT_ERR_ROLLBACK        10  // could not swap back; original kept at *out_backup_path

// Process & Socket Inspection (~12 us per PID, zero subprocesses)
int  mf_list_user_pids(int32_t* out_pids, int max_pids);
bool mf_inspect_process(int32_t pid, mf_proc_telemetry_t* out_info);
bool mf_is_file_open_anywhere(uint64_t target_dev, uint64_t target_ino); // dev 0 = any volume
bool mf_is_inode_open_anywhere(uint64_t target_ino);
int  mf_collect_all_open_inodes(uint64_t* out_inos, int max_inos);
bool mf_capture_fingerprint(const char* path, mf_file_fingerprint_t* out);

// System VM & APFS Volume Telemetry
bool mf_capture_sys_metrics(const char* mount_path, mf_sys_metrics_t* out_sys);

// Pillar 3A: Sparse Zero-Extent Punching (`fcntl(F_PUNCHHOLE)` at 4 KB APFS block granularity)
bool mf_punch_zero_extents(
    const char* path,
    bool dry_run,
    uint64_t* out_logical_bytes,
    uint64_t* out_phys_before,
    uint64_t* out_phys_after,
    uint64_t* out_punchable_bytes
);

// Pillar 3B: Transparent `decmpfs` LZFSE folding of one file, in place.
// Re-verifies `expected`, stages a compressed copy, byte-compares it through the VFS, mirrors
// xattrs/ACL/mode/group/flags/times, then RENAME_SWAPs and verifies again (see the .c file).
int32_t mf_lzfse_compress_in_place(
    const char* path,
    const mf_file_fingerprint_t* expected,
    uint64_t* out_phys_before,
    uint64_t* out_phys_after,
    char* out_backup_path,   // set only for MF_COMMIT_ERR_ROLLBACK (may be NULL)
    size_t backup_cap
);

// Pillar 3C: Replace `dup_path` with an APFS clone of `canonical_path`, under the same checks.
int32_t mf_dedup_replace_with_clone(
    const char* canonical_path,
    const char* dup_path,
    const mf_file_fingerprint_t* expected_dup,
    uint64_t* out_phys_before,
    char* out_backup_path,
    size_t backup_cap
);

// Test-only: called after the final pre-swap checks, immediately before RENAME_SWAP.
void mf_set_test_hook_before_swap(void (*hook)(const char* path));

// Fast Unix Domain Socket Helpers for N->1->0 MCP Multiplexer
int  mf_unix_listen(const char* sock_path);
int  mf_unix_connect(const char* sock_path);

#ifdef __cplusplus
}
#endif

#endif
