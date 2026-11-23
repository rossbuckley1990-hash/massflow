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

// Process & Socket Inspection (~12 us per PID, zero subprocesses)
int  mf_list_user_pids(int32_t* out_pids, int max_pids);
bool mf_inspect_process(int32_t pid, mf_proc_telemetry_t* out_info);
bool mf_is_inode_open_anywhere(uint64_t target_ino);
int  mf_collect_all_open_inodes(uint64_t* out_inos, int max_inos);

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

// Pillar 3B: XNU Ring-0 Transparent `decmpfs` LZFSE Staging (`CMP_Type11` 0-block inline + `CMP_Type12` 64KB chunked)
bool mf_stage_decmpfs_lzfse(
    const char* src_path,
    const char* stage_path,
    uint64_t* out_phys_before,
    uint64_t* out_phys_after
);

// Pillar 3C: APFS Copy-on-Write `clonefile(2)` Extent Deduplication Staging
bool mf_stage_clonefile_dedup(
    const char* canonical_path,
    const char* dup_path,
    const char* stage_path,
    uint64_t* out_phys_before
);

// Preserve original mtime/atime & mode on stage before atomic rename
bool mf_commit_staged_file(const char* orig_path, const char* stage_path, bool check_open_fds);

// Fast Unix Domain Socket Helpers for N->1->0 MCP Multiplexer
int  mf_unix_listen(const char* sock_path);
int  mf_unix_connect(const char* sock_path);

#ifdef __cplusplus
}
#endif

#endif
