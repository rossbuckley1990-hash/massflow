#include "massflow_kernel.h"

#include <arpa/inet.h>
#include <arm_neon.h>
#include <compression.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <netinet/tcp_fsm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <unistd.h>

// MARK: - Process, Rusage & Kernel Socket Shield Inspection

int mf_list_user_pids(int32_t* out_pids, int max_pids) {
    if (!out_pids || max_pids <= 0) return 0;
    int bytes = proc_listpids(PROC_UID_ONLY, getuid(), out_pids, max_pids * (int)sizeof(int32_t));
    if (bytes <= 0) return 0;
    int count = bytes / (int)sizeof(int32_t);
    int valid = 0;
    for (int i = 0; i < count; i++) {
        if (out_pids[i] > 0) {
            out_pids[valid++] = out_pids[i];
        }
    }
    return valid;
}

bool mf_inspect_process(int32_t pid, mf_proc_telemetry_t* out_info) {
    if (!out_info || pid <= 0) return false;
    memset(out_info, 0, sizeof(*out_info));

    struct proc_bsdinfo bsd;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) != sizeof(bsd)) {
        return false;
    }

    out_info->pid = pid;
    out_info->ppid = (int32_t)bsd.pbi_ppid;
    out_info->pgid = (int32_t)bsd.pbi_pgid;
    out_info->status = bsd.pbi_status;
    out_info->flags = bsd.pbi_flags;
    out_info->start_tvsec = bsd.pbi_start_tvsec;

    if (proc_pidpath(pid, out_info->exec_path, sizeof(out_info->exec_path)) <= 0) {
        strncpy(out_info->exec_path, bsd.pbi_comm, sizeof(out_info->exec_path) - 1);
    }

    struct rusage_info_v6 ri;
    memset(&ri, 0, sizeof(ri));
    if (proc_pid_rusage(pid, RUSAGE_INFO_V6, (rusage_info_t*)&ri) == 0) {
        static mach_timebase_info_data_t tb = {0, 0};
        if (tb.denom == 0) mach_timebase_info(&tb);
        out_info->phys_footprint_bytes = ri.ri_phys_footprint;
        out_info->user_time_ns = ri.ri_user_time * tb.numer / tb.denom;
        out_info->system_time_ns = ri.ri_system_time * tb.numer / tb.denom;
        out_info->disk_bytes_written = ri.ri_diskio_byteswritten;
    }

    // Inspect up to 512 open FDs for TCP LISTEN & ESTABLISHED sockets (protects local dev servers!)
    struct proc_fdinfo fds[512];
    int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
    if (fd_bytes > 0) {
        int nfds = fd_bytes / (int)sizeof(struct proc_fdinfo);
        for (int i = 0; i < nfds; i++) {
            if (fds[i].proc_fdtype == PROX_FDTYPE_SOCKET) {
                struct socket_fdinfo si;
                if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si)) == sizeof(si)) {
                    if (si.psi.soi_kind == SOCKINFO_TCP) {
                        int st = si.psi.soi_proto.pri_tcp.tcpsi_state;
                        if (st == TSI_S_LISTEN) {
                            out_info->tcp_listen_count++;
                            if (out_info->first_listen_port == 0) {
                                uint16_t raw_port = (uint16_t)si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport;
                                out_info->first_listen_port = ntohs(raw_port);
                            }
                        } else if (st == TSI_S_ESTABLISHED) {
                            out_info->tcp_established_count++;
                        }
                    }
                }
            }
        }
    }

    return true;
}

// Returns a malloc'd, *complete* FD table for `pid` (the old fixed 1024-entry buffer silently
// truncated processes with many open files, so their files looked "not open").
// Returns -1 if the table could not be read at all, otherwise the FD count.
static int mf_list_fds(int32_t pid, struct proc_fdinfo** out_fds) {
    *out_fds = NULL;
    int need = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (need <= 0) return -1;
    int cap = need + 64 * (int)sizeof(struct proc_fdinfo);
    for (int attempt = 0; attempt < 6; attempt++) {
        struct proc_fdinfo* fds = (struct proc_fdinfo*)malloc((size_t)cap);
        if (!fds) return -1;
        int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, cap);
        if (got <= 0) { free(fds); return -1; }
        // A completely full buffer may mean truncation: grow and retry.
        if (got <= cap - (int)sizeof(struct proc_fdinfo)) {
            *out_fds = fds;
            return got / (int)sizeof(struct proc_fdinfo);
        }
        free(fds);
        cap *= 2;
    }
    return -1;
}

int mf_collect_all_open_inodes(uint64_t* out_inos, int max_inos) {
    if (!out_inos || max_inos <= 0) return 0;
    int32_t pids[4096];
    int npids = mf_list_user_pids(pids, 4096);
    int32_t self_pid = getpid();
    int count = 0;

    for (int p = 0; p < npids; p++) {
        int32_t pid = pids[p];
        if (pid == self_pid) continue;
        struct proc_fdinfo* fds = NULL;
        int nfds = mf_list_fds(pid, &fds);
        for (int i = 0; i < nfds; i++) {
            if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
                struct vnode_fdinfowithpath vi;
                if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi)) == sizeof(vi)) {
                    uint64_t ino = vi.pvip.vip_vi.vi_stat.vst_ino;
                    if (ino != 0 && count < max_inos) {
                        out_inos[count++] = ino;
                    }
                }
            }
        }
        free(fds);
    }
    return count;
}

bool mf_is_file_open_anywhere(uint64_t target_dev, uint64_t target_ino) {
    if (target_ino == 0) return false;
    int32_t pids[4096];
    int npids = mf_list_user_pids(pids, 4096);
    int32_t self_pid = getpid();

    for (int p = 0; p < npids; p++) {
        int32_t pid = pids[p];
        if (pid == self_pid) continue;
        struct proc_fdinfo* fds = NULL;
        int nfds = mf_list_fds(pid, &fds);
        bool hit = false;
        for (int i = 0; i < nfds && !hit; i++) {
            if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
                struct vnode_fdinfowithpath vi;
                if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi)) == sizeof(vi)) {
                    const struct vinfo_stat* vs = &vi.pvip.vip_vi.vi_stat;
                    if (vs->vst_ino == target_ino && (target_dev == 0 || (uint64_t)vs->vst_dev == target_dev)) {
                        hit = true;
                    }
                }
            }
        }
        free(fds);
        if (hit) return true;
    }
    return false;
}

bool mf_is_inode_open_anywhere(uint64_t target_ino) {
    return mf_is_file_open_anywhere(0, target_ino);
}

// MARK: - System VM & APFS Volume Telemetry

static uint64_t mf_sysctl_u64(const char* name) {
    uint64_t val = 0;
    size_t sz = sizeof(val);
    if (sysctlbyname(name, &val, &sz, NULL, 0) == 0) {
        if (sz == 4) return *(uint32_t*)&val;
        return val;
    }
    return 0;
}

bool mf_capture_sys_metrics(const char* mount_path, mf_sys_metrics_t* out_sys) {
    if (!out_sys) return false;
    memset(out_sys, 0, sizeof(*out_sys));

    struct statfs sfs;
    if (statfs(mount_path ? mount_path : "/System/Volumes/Data", &sfs) == 0) {
        out_sys->disk_total_bytes = (uint64_t)sfs.f_blocks * (uint64_t)sfs.f_bsize;
        out_sys->disk_avail_bytes = (uint64_t)sfs.f_bavail * (uint64_t)sfs.f_bsize;
    }

    out_sys->ram_total_bytes = mf_sysctl_u64("hw.memsize");
    out_sys->swapouts_total = mf_sysctl_u64("vm.compressor.swapper.swapouts_total");
    out_sys->swapins_total = mf_sysctl_u64("vm.compressor.swapper.swapins_total");

    struct xsw_usage su;
    size_t sz = sizeof(su);
    if (sysctlbyname("vm.swapusage", &su, &sz, NULL, 0) == 0) {
        out_sys->swap_used_bytes = su.xsu_used;
        out_sys->swap_total_bytes = su.xsu_total;
    }

    int32_t pl = 0;
    size_t psz = sizeof(pl);
    if (sysctlbyname("kern.memorystatus_vm_pressure_level", &pl, &psz, NULL, 0) == 0) {
        out_sys->pressure_level = pl;
    }

    vm_statistics64_data_t vms;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vms, &count) == KERN_SUCCESS) {
        uint64_t pg = (uint64_t)vm_kernel_page_size;
        out_sys->ram_free_bytes = (uint64_t)(vms.free_count + vms.speculative_count) * pg;
        out_sys->ram_compressed_bytes = (uint64_t)vms.compressor_page_count * pg;
    }
    return true;
}

// MARK: - Pillar 3A: NEON-Accelerated Sparse Zero-Extent Punching (`F_PUNCHHOLE`)

static inline bool mf_is_zero_4k(const uint8_t* p) {
    uint64x2_t acc0 = vdupq_n_u64(0);
    uint64x2_t acc1 = vdupq_n_u64(0);
    for (size_t i = 0; i < 4096; i += 64) {
        uint64x2_t v0 = vld1q_u64((const uint64_t*)(p + i));
        uint64x2_t v1 = vld1q_u64((const uint64_t*)(p + i + 16));
        uint64x2_t v2 = vld1q_u64((const uint64_t*)(p + i + 32));
        uint64x2_t v3 = vld1q_u64((const uint64_t*)(p + i + 48));
        acc0 = vorrq_u64(acc0, vorrq_u64(v0, v1));
        acc1 = vorrq_u64(acc1, vorrq_u64(v2, v3));
    }
    uint64x2_t comb = vorrq_u64(acc0, acc1);
    return (vgetq_lane_u64(comb, 0) | vgetq_lane_u64(comb, 1)) == 0;
}

// Re-checks (rate-limited) that no other process has opened the image since we started.
// macOS has no mandatory locks, so a VM that boots mid-scan could write into a block we just
// read as zero; re-checking before every punch bounds that window to ~100 ms instead of the
// whole multi-minute scan.
typedef struct {
    uint64_t dev, ino;
    uint64_t last_check_ns;
    bool aborted;
} mf_punch_guard_t;

static uint64_t mf_now_ns(void) {
    return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
}

static bool mf_punch_run(int fd, off_t start, off_t len, mf_punch_guard_t* g) {
    if (g->aborted) return false;
    uint64_t now = mf_now_ns();
    if (now - g->last_check_ns > 100ULL * 1000ULL * 1000ULL) {
        if (mf_is_file_open_anywhere(g->dev, g->ino)) {
            g->aborted = true;
            return false;
        }
        g->last_check_ns = mf_now_ns();
    }
    fpunchhole_t ph = { 0, 0, start, len };
    (void)fcntl(fd, F_PUNCHHOLE, &ph);
    return true;
}

bool mf_punch_zero_extents(
    const char* path,
    bool dry_run,
    uint64_t* out_logical_bytes,
    uint64_t* out_phys_before,
    uint64_t* out_phys_after,
    uint64_t* out_punchable_bytes
) {
    if (!path) return false;
    struct stat st0;
    if (lstat(path, &st0) != 0 || !S_ISREG(st0.st_mode)) return false;

    // Never touch an image currently open by any VM / Docker / user process!
    if (!dry_run && mf_is_file_open_anywhere((uint64_t)st0.st_dev, (uint64_t)st0.st_ino)) {
        return false;
    }

    int fd = open(path, (dry_run ? O_RDONLY : O_RDWR) | O_NOFOLLOW);
    if (fd < 0) return false;

    if (!dry_run) {
        if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
            close(fd);
            return false;
        }
    }

    struct timespec orig_times[2] = { st0.st_atimespec, st0.st_mtimespec };
    mf_punch_guard_t guard = { (uint64_t)st0.st_dev, (uint64_t)st0.st_ino, mf_now_ns(), false };

    if (out_logical_bytes) *out_logical_bytes = (uint64_t)st0.st_size;
    if (out_phys_before)   *out_phys_before   = (uint64_t)st0.st_blocks * 512ULL;

    const size_t io_buf_sz = 1024 * 1024;
    uint8_t* buf = (uint8_t*)malloc(io_buf_sz);
    if (!buf) { close(fd); return false; }
    uint64_t punchable = 0;

    off_t pos = 0;
    off_t run_start = -1;
    off_t run_len = 0;

    while (pos < st0.st_size && !guard.aborted) {
        off_t data_off = lseek(fd, pos, SEEK_DATA);
        if (data_off < 0 || data_off >= st0.st_size) break;
        off_t hole_off = lseek(fd, data_off, SEEK_HOLE);
        if (hole_off < 0 || hole_off > st0.st_size) hole_off = st0.st_size;

        // Align data_off upward to 4096-byte APFS block boundary
        off_t cur = (data_off + 4095) & ~4095LL;
        while (cur + 4096 <= hole_off && !guard.aborted) {
            size_t want = (size_t)((hole_off - cur) > (off_t)io_buf_sz ? (off_t)io_buf_sz : (hole_off - cur));
            want &= ~4095ULL;
            if (want == 0) break;

            ssize_t n = pread(fd, buf, want, cur);
            if (n < 4096) break;
            size_t blocks_read = (size_t)n & ~4095ULL;

            for (size_t off = 0; off < blocks_read && !guard.aborted; off += 4096) {
                off_t blk_off = cur + (off_t)off;
                if (mf_is_zero_4k(buf + off)) {
                    punchable += 4096;
                    if (run_start < 0) {
                        run_start = blk_off;
                        run_len = 4096;
                    } else if (run_start + run_len == blk_off) {
                        run_len += 4096;
                    } else {
                        if (!dry_run) (void)mf_punch_run(fd, run_start, run_len, &guard);
                        run_start = blk_off;
                        run_len = 4096;
                    }
                } else if (run_start >= 0) {
                    if (!dry_run) (void)mf_punch_run(fd, run_start, run_len, &guard);
                    run_start = -1;
                    run_len = 0;
                }
            }
            cur += (off_t)blocks_read;
        }

        if (run_start >= 0) {
            if (!dry_run) (void)mf_punch_run(fd, run_start, run_len, &guard);
            run_start = -1;
            run_len = 0;
        }
        pos = hole_off;
    }

    free(buf);

    struct stat st1 = st0;
    if (!dry_run) {
        (void)futimens(fd, orig_times);
        (void)flock(fd, LOCK_UN);
        fstat(fd, &st1);
    }
    close(fd);

    if (guard.aborted) return false;  // another process opened the image mid-scan: stop, report as skipped

    if (out_punchable_bytes) *out_punchable_bytes = punchable;
    if (out_phys_after) {
        if (dry_run) {
            uint64_t b0 = (uint64_t)st0.st_blocks * 512ULL;
            *out_phys_after = (b0 > punchable) ? (b0 - punchable) : 0;
        } else {
            *out_phys_after = (uint64_t)st1.st_blocks * 512ULL;
        }
    }
    return true;
}

// MARK: - Pillar 3 Safety Core: Fingerprints, Exact Compare, Metadata Mirror & Verified Swap
//
// Invariant for every in-place rewrite (LZFSE folding and clonefile dedup):
//   The original inode is unlinked ONLY after
//     (1) it still matches the fingerprint captured before hashing (no edit since scan),
//     (2) the staged replacement is byte-identical to it,
//     (3) its xattrs, ACL, mode, group, flags and times have been mirrored onto the stage
//         and read back equal,
//     (4) no other process holds it open, before or after the atomic RENAME_SWAP, and
//     (5) the file now at the original path reads back byte-identical to the original.
//   Any failure before the swap discards the stage; any failure after it swaps back, and
//   if even that is impossible the original inode is left on disk as a hidden backup.

static void (*g_mf_test_hook_before_swap)(const char* path) = NULL;

void mf_set_test_hook_before_swap(void (*hook)(const char* path)) {
    g_mf_test_hook_before_swap = hook;
}

static void mf_fill_fingerprint(const struct stat* st, mf_file_fingerprint_t* out) {
    memset(out, 0, sizeof(*out));
    out->dev = (uint64_t)st->st_dev;
    out->ino = (uint64_t)st->st_ino;
    out->size = (uint64_t)st->st_size;
    out->blocks = (uint64_t)st->st_blocks;
    out->atime_sec = (int64_t)st->st_atimespec.tv_sec;
    out->atime_nsec = (int64_t)st->st_atimespec.tv_nsec;
    out->mtime_sec = (int64_t)st->st_mtimespec.tv_sec;
    out->mtime_nsec = (int64_t)st->st_mtimespec.tv_nsec;
    out->ctime_sec = (int64_t)st->st_ctimespec.tv_sec;
    out->ctime_nsec = (int64_t)st->st_ctimespec.tv_nsec;
    out->nlink = (uint32_t)st->st_nlink;
    out->flags = (uint32_t)st->st_flags;
    out->uid = (uint32_t)st->st_uid;
    out->mode = (uint32_t)st->st_mode;
}

bool mf_capture_fingerprint(const char* path, mf_file_fingerprint_t* out) {
    if (!path || !out) return false;
    struct stat st;
    if (lstat(path, &st) != 0) return false;
    mf_fill_fingerprint(&st, out);
    return true;
}

// Identity + content-change detection. ctime cannot be forged from userspace, so an unchanged
// ctime means no write, truncate, chmod, xattr or rename-over touched the inode since the scan.
static bool mf_stat_matches(const struct stat* st, const mf_file_fingerprint_t* fp) {
    return (uint64_t)st->st_dev == fp->dev
        && (uint64_t)st->st_ino == fp->ino
        && (uint64_t)st->st_size == fp->size
        && (int64_t)st->st_mtimespec.tv_sec == fp->mtime_sec
        && (int64_t)st->st_mtimespec.tv_nsec == fp->mtime_nsec
        && (int64_t)st->st_ctimespec.tv_sec == fp->ctime_sec
        && (int64_t)st->st_ctimespec.tv_nsec == fp->ctime_nsec
        && (uint32_t)st->st_nlink == fp->nlink;
}

// Strict allowlist: anything immutable, append-only, document-tracked, dataless (iCloud
// evicted), restricted or otherwise special is left alone.
#define MF_MIRRORED_FLAGS (UF_NODUMP | UF_HIDDEN)

static int32_t mf_precheck(const char* path, const mf_file_fingerprint_t* fp, bool allow_compressed) {
    struct stat st;
    if (lstat(path, &st) != 0) return MF_COMMIT_SKIP_CHANGED;
    if (!S_ISREG(st.st_mode)) return MF_COMMIT_SKIP_UNSAFE;
    if (!mf_stat_matches(&st, fp)) return MF_COMMIT_SKIP_CHANGED;
    if (st.st_nlink != 1) return MF_COMMIT_SKIP_UNSAFE;
    if (st.st_uid != getuid()) return MF_COMMIT_SKIP_UNSAFE;
    uint32_t allowed = MF_MIRRORED_FLAGS | (allow_compressed ? UF_COMPRESSED : 0);
    if ((st.st_flags & ~allowed) != 0) return MF_COMMIT_SKIP_UNSAFE;
    if (mf_is_file_open_anywhere(fp->dev, fp->ino)) return MF_COMMIT_SKIP_OPEN;
    return MF_COMMIT_OK;
}

static bool mf_pread_full(int fd, uint8_t* buf, size_t len, off_t off) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = pread(fd, buf + got, len - got, off + (off_t)got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

// Exact byte-for-byte equality of two open files over `size` bytes, and both exactly that long.
static bool mf_fds_equal(int a, int b, uint64_t size) {
    const size_t chunk = 1024 * 1024;
    uint8_t* x = (uint8_t*)malloc(chunk);
    uint8_t* y = (uint8_t*)malloc(chunk);
    bool eq = (x && y);
    uint64_t off = 0;
    while (eq && off < size) {
        size_t want = (size - off) < chunk ? (size_t)(size - off) : chunk;
        if (!mf_pread_full(a, x, want, (off_t)off) || !mf_pread_full(b, y, want, (off_t)off) || memcmp(x, y, want) != 0) {
            eq = false;
        }
        off += want;
    }
    if (eq) {
        uint8_t t;
        if (pread(a, &t, 1, (off_t)size) != 0 || pread(b, &t, 1, (off_t)size) != 0) eq = false;
    }
    free(x);
    free(y);
    return eq;
}

// Visible xattr names (decmpfs-internal com.apple.decmpfs / compressed resource forks are hidden
// by the kernel without XATTR_SHOWCOMPRESSION, which is exactly what we want).
static char* mf_list_xattr_names(int fd, ssize_t* out_len) {
    *out_len = 0;
    ssize_t n = flistxattr(fd, NULL, 0, 0);
    if (n < 0) return NULL;
    char* names = (char*)malloc((size_t)n + 1);
    if (!names) return NULL;
    if (n > 0) {
        ssize_t m = flistxattr(fd, names, (size_t)n, 0);
        if (m != n) { free(names); return NULL; }
    }
    names[n] = 0;
    *out_len = n;
    return names;
}

static bool mf_read_xattr(int fd, const char* name, uint8_t** out, ssize_t* out_len) {
    *out = NULL;
    *out_len = 0;
    ssize_t len = fgetxattr(fd, name, NULL, 0, 0, 0);
    if (len < 0) return false;
    uint8_t* buf = (uint8_t*)malloc((size_t)len + 1);
    if (!buf) return false;
    if (len > 0 && fgetxattr(fd, name, buf, (size_t)len, 0, 0) != len) { free(buf); return false; }
    *out = buf;
    *out_len = len;
    return true;
}

static bool mf_strip_xattrs(int fd) {
    ssize_t n = 0;
    char* names = mf_list_xattr_names(fd, &n);
    if (!names) return false;
    bool ok = true;
    for (char* nm = names; nm < names + n; nm += strlen(nm) + 1) {
        if (fremovexattr(fd, nm, 0) != 0 && errno != ENOATTR) { ok = false; break; }
    }
    free(names);
    return ok;
}

static bool mf_copy_xattrs(int src, int dst, bool dst_compressed) {
    ssize_t n = 0;
    char* names = mf_list_xattr_names(src, &n);
    if (!names) return false;
    bool ok = true;
    for (char* nm = names; ok && nm < names + n; nm += strlen(nm) + 1) {
        if (strcmp(nm, "com.apple.decmpfs") == 0) { ok = false; break; }
        // A real resource fork cannot coexist with a decmpfs-compressed destination.
        if (dst_compressed && strcmp(nm, XATTR_RESOURCEFORK_NAME) == 0) { ok = false; break; }
        uint8_t* val = NULL;
        ssize_t vlen = 0;
        if (!mf_read_xattr(src, nm, &val, &vlen)) { ok = false; break; }
        if (fsetxattr(dst, nm, val, (size_t)vlen, 0, 0) != 0) ok = false;
        free(val);
    }
    free(names);
    return ok;
}

// Returns a malloc'd canonical text form of the extended ACL ("" if none), or NULL on error.
static char* mf_acl_text(int fd) {
    acl_t a = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!a) {
        if (errno == ENOENT) return strdup("");
        return NULL;
    }
    ssize_t len = 0;
    char* t = acl_to_text(a, &len);
    acl_free(a);
    if (!t) return NULL;
    char* copy = strdup(t);
    acl_free(t);
    return copy;
}

static bool mf_xattrs_equal(int a, int b) {
    ssize_t na = 0, nb = 0;
    char* la = mf_list_xattr_names(a, &na);
    char* lb = mf_list_xattr_names(b, &nb);
    bool eq = (la && lb);
    int count_a = 0, count_b = 0;
    if (eq) {
        for (char* nm = lb; nm < lb + nb; nm += strlen(nm) + 1) count_b++;
        for (char* nm = la; eq && nm < la + na; nm += strlen(nm) + 1) {
            count_a++;
            uint8_t *va = NULL, *vb = NULL;
            ssize_t lva = 0, lvb = 0;
            if (!mf_read_xattr(a, nm, &va, &lva) || !mf_read_xattr(b, nm, &vb, &lvb) ||
                lva != lvb || (lva > 0 && memcmp(va, vb, (size_t)lva) != 0)) {
                eq = false;
            }
            free(va);
            free(vb);
        }
        if (count_a != count_b) eq = false;
    }
    free(la);
    free(lb);
    return eq;
}

// Mirrors every piece of user-visible metadata from `src_fd` (the original inode) onto
// `dst_fd` (the staged replacement), then reads it back and verifies it.
static bool mf_mirror_metadata(int src_fd, int dst_fd, const mf_file_fingerprint_t* fp) {
    struct stat ss, ds;
    if (fstat(src_fd, &ss) != 0 || fstat(dst_fd, &ds) != 0) return false;
    bool dst_compressed = (ds.st_flags & UF_COMPRESSED) != 0;

    // 0. Make the stage writable for us while we transplant attributes.
    if (fchmod(dst_fd, 0600) != 0) return false;

    // 1. Drop whatever ACL the stage inherited (clonefile copies the canonical file's ACL).
    acl_t empty = acl_init(0);
    if (!empty) return false;
    int r = acl_set_fd_np(dst_fd, empty, ACL_TYPE_EXTENDED);
    acl_free(empty);
    if (r != 0) return false;

    // 2. Replace the stage's xattrs with exactly the original's (quarantine, Finder tags,
    //    provenance, code-signing EAs, custom app metadata...).
    if (!mf_strip_xattrs(dst_fd)) return false;
    if (!mf_copy_xattrs(src_fd, dst_fd, dst_compressed)) return false;

    // 3. Group (new files inherit the parent directory's group on macOS).
    if (ds.st_gid != ss.st_gid && fchown(dst_fd, (uid_t)-1, ss.st_gid) != 0) return false;

    // 4. Permission bits.
    if (fchmod(dst_fd, ss.st_mode & 07777) != 0) return false;

    // 5. BSD flags we allow (UF_HIDDEN, UF_NODUMP); keep the stage's own UF_COMPRESSED bit,
    //    because clearing it would expose an empty data fork.
    uint32_t want_flags = (ss.st_flags & MF_MIRRORED_FLAGS) | (ds.st_flags & UF_COMPRESSED);
    if (fchflags(dst_fd, want_flags) != 0) return false;

    // 6. atime/mtime from the pre-scan fingerprint (our own reads may have bumped atime).
    struct timespec ts[2] = {
        { (time_t)fp->atime_sec, (long)fp->atime_nsec },
        { (time_t)fp->mtime_sec, (long)fp->mtime_nsec }
    };
    if (futimens(dst_fd, ts) != 0) return false;

    // 7. Birth time (after mtime, since APFS pulls crtime back when mtime < crtime).
    struct attrlist al;
    memset(&al, 0, sizeof(al));
    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    al.commonattr = ATTR_CMN_CRTIME;
    struct timespec crt = ss.st_birthtimespec;
    if (fsetattrlist(dst_fd, &al, &crt, sizeof(crt), 0) != 0) return false;

    // 8. ACL last, so a restrictive ACL cannot block the steps above.
    acl_t a = acl_get_fd_np(src_fd, ACL_TYPE_EXTENDED);
    if (a) {
        r = acl_set_fd_np(dst_fd, a, ACL_TYPE_EXTENDED);
        acl_free(a);
        if (r != 0) return false;
    } else if (errno != ENOENT) {
        return false;
    }

    // Read back and verify.
    struct stat vs;
    if (fstat(dst_fd, &vs) != 0) return false;
    if ((vs.st_mode & 07777) != (ss.st_mode & 07777)) return false;
    if (vs.st_uid != ss.st_uid || vs.st_gid != ss.st_gid) return false;
    if ((vs.st_flags & ~UF_COMPRESSED) != (ss.st_flags & MF_MIRRORED_FLAGS)) return false;
    if ((int64_t)vs.st_mtimespec.tv_sec != fp->mtime_sec || (int64_t)vs.st_mtimespec.tv_nsec != fp->mtime_nsec) return false;
    if (vs.st_birthtimespec.tv_sec != ss.st_birthtimespec.tv_sec || vs.st_birthtimespec.tv_nsec != ss.st_birthtimespec.tv_nsec) return false;
    if (!mf_xattrs_equal(src_fd, dst_fd)) return false;
    char* acl_s = mf_acl_text(src_fd);
    char* acl_d = mf_acl_text(dst_fd);
    bool acl_eq = acl_s && acl_d && strcmp(acl_s, acl_d) == 0;
    free(acl_s);
    free(acl_d);
    return acl_eq;
}

static uint32_t g_mf_stage_counter = 0;

static bool mf_make_stage_path(const char* orig_path, char* out, size_t cap) {
    const char* slash = strrchr(orig_path, '/');
    size_t dir_len = slash ? (size_t)(slash - orig_path) : 0;
    const char* base = slash ? slash + 1 : orig_path;
    uint32_t n = __atomic_add_fetch(&g_mf_stage_counter, 1, __ATOMIC_RELAXED);
    int w;
    if (slash) {
        w = snprintf(out, cap, "%.*s/.mfstage-%d-%u-%.100s", (int)dir_len, orig_path, (int)getpid(), n, base);
    } else {
        w = snprintf(out, cap, ".mfstage-%d-%u-%.100s", (int)getpid(), n, base);
    }
    return w > 0 && (size_t)w < cap;
}

static void mf_set_backup(char* out, size_t cap, const char* path) {
    if (out && cap > 0) snprintf(out, cap, "%s", path ? path : "");
}

// `orig_fd` is an O_RDONLY fd on the original inode; `stage_path` holds the replacement.
static int32_t mf_verify_and_swap(
    const char* orig_path,
    int orig_fd,
    const char* stage_path,
    const mf_file_fingerprint_t* fp,
    char* out_backup_path,
    size_t backup_cap
) {
    int stage_fd = open(stage_path, O_RDONLY | O_NOFOLLOW);
    if (stage_fd < 0) { unlink(stage_path); return MF_COMMIT_ERR_IO; }

    // (2) exact content equality, read through the VFS (so decmpfs decoding is exercised).
    if (!mf_fds_equal(orig_fd, stage_fd, fp->size)) {
        close(stage_fd);
        unlink(stage_path);
        return MF_COMMIT_SKIP_MISMATCH;
    }

    // (3) metadata fidelity.
    if (!mf_mirror_metadata(orig_fd, stage_fd, fp)) {
        close(stage_fd);
        unlink(stage_path);
        return MF_COMMIT_ERR_METADATA;
    }

    // (1)+(4) last look before the swap.
    struct stat st;
    if (lstat(orig_path, &st) != 0 || !mf_stat_matches(&st, fp)) {
        close(stage_fd);
        unlink(stage_path);
        return MF_COMMIT_SKIP_CHANGED;
    }
    if (mf_is_file_open_anywhere(fp->dev, fp->ino)) {
        close(stage_fd);
        unlink(stage_path);
        return MF_COMMIT_SKIP_OPEN;
    }

    if (g_mf_test_hook_before_swap) g_mf_test_hook_before_swap(orig_path);

    if (renamex_np(stage_path, orig_path, RENAME_SWAP) != 0) {
        close(stage_fd);
        unlink(stage_path);
        return MF_COMMIT_ERR_IO;
    }
    // Now: orig_path -> replacement inode, stage_path -> original inode (still held by orig_fd).

    // (4) did anyone write to, or open, the original in the window before the swap?
    struct stat post;
    bool raced = fstat(orig_fd, &post) != 0
        || (uint64_t)post.st_size != fp->size
        || (int64_t)post.st_mtimespec.tv_sec != fp->mtime_sec
        || (int64_t)post.st_mtimespec.tv_nsec != fp->mtime_nsec
        || mf_is_file_open_anywhere(fp->dev, fp->ino);

    // (5) post-commit verification of what now lives at orig_path.
    bool verified = false;
    if (!raced) {
        struct stat now_st, stage_st;
        int check_fd = open(orig_path, O_RDONLY | O_NOFOLLOW);
        if (check_fd >= 0) {
            verified = fstat(check_fd, &now_st) == 0
                && fstat(stage_fd, &stage_st) == 0
                && now_st.st_ino == stage_st.st_ino
                && now_st.st_dev == stage_st.st_dev
                && mf_fds_equal(orig_fd, check_fd, fp->size);
            close(check_fd);
        }
    }
    close(stage_fd);

    if (!raced && verified) {
        unlink(stage_path);  // drop the original inode: its bytes now live in the verified replacement
        return MF_COMMIT_OK;
    }

    // Put the original back.
    if (renamex_np(stage_path, orig_path, RENAME_SWAP) == 0) {
        unlink(stage_path);  // stage_path now holds the replacement again
        return raced ? MF_COMMIT_RACE_ROLLED_BACK : MF_COMMIT_ERR_VERIFY;
    }
    // Could not swap back: never delete anything; leave the original inode beside the file.
    mf_set_backup(out_backup_path, backup_cap, stage_path);
    return MF_COMMIT_ERR_ROLLBACK;
}

// MARK: - Pillar 3B: XNU Ring-0 Transparent `decmpfs` LZFSE Folding

#pragma pack(push, 1)
typedef struct {
    uint32_t magic; // 0x636d7066 ('fpmc')
    uint32_t type;  // 11 = LZFSE inline (0 data blocks!), 12 = LZFSE 64KB chunked resource fork
    uint64_t size;
} mf_decmpfs_disk_hdr_t;
#pragma pack(pop)

// Builds a decmpfs-compressed copy of the bytes read from `sfd` at `stage_path` (created
// O_EXCL, never clobbering an existing file). Metadata is mirrored later by the commit path.
static bool mf_build_lzfse_stage(
    int sfd,
    const struct stat* st,
    const char* stage_path,
    uint64_t* out_phys_before,
    uint64_t* out_phys_after
) {
    if (st->st_size <= 128 || st->st_size > 64 * 1024 * 1024) return false;

    size_t raw_len = (size_t)st->st_size;
    uint8_t* raw = (uint8_t*)malloc(raw_len);
    if (!raw) return false;
    if (!mf_pread_full(sfd, raw, raw_len, 0)) { free(raw); return false; }

    int dfd = open(stage_path, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600);
    if (dfd < 0) { free(raw); return false; }

    bool encoded_ok = false;

    // Fast path 1: CMP_Type11 Inline LZFSE inside com.apple.decmpfs xattr (0 physical data blocks!)
    if (raw_len <= 65536) {
        uint8_t inline_buf[sizeof(mf_decmpfs_disk_hdr_t) + 3802];
        mf_decmpfs_disk_hdr_t* hdr = (mf_decmpfs_disk_hdr_t*)inline_buf;
        hdr->magic = 0x636d7066;
        hdr->type = 11;
        hdr->size = (uint64_t)raw_len;
        size_t clen = compression_encode_buffer(
            inline_buf + sizeof(mf_decmpfs_disk_hdr_t),
            3800,
            raw,
            raw_len,
            NULL,
            COMPRESSION_LZFSE
        );
        if (clen > 0 && clen <= 3800) {
            if (fsetxattr(dfd, "com.apple.decmpfs", inline_buf, sizeof(mf_decmpfs_disk_hdr_t) + clen, 0, 0) == 0 &&
                fchflags(dfd, UF_COMPRESSED) == 0) {
                encoded_ok = true;
            }
        }
    }

    // Path 2: CMP_Type12 64 KB Random-Access Chunked LZFSE in Resource Fork
    if (!encoded_ok) {
        const size_t chunk_sz = 65536;
        size_t nchunks = (raw_len + chunk_sz - 1) / chunk_sz;
        uint32_t table_bytes = (uint32_t)((nchunks + 1) * sizeof(uint32_t));
        size_t rsrc_cap = table_bytes + raw_len + nchunks * 256;
        uint8_t* rsrc = (uint8_t*)malloc(rsrc_cap);
        if (rsrc) {
            uint32_t* table = (uint32_t*)rsrc;
            uint32_t cur_off = table_bytes;
            table[0] = cur_off;

            bool chunks_ok = true;
            for (size_t c = 0; c < nchunks; c++) {
                size_t len = (c + 1) * chunk_sz <= raw_len ? chunk_sz : (raw_len - c * chunk_sz);
                size_t enc = compression_encode_buffer(
                    rsrc + cur_off,
                    len, // require each chunk to strictly fit <= uncompressed chunk size
                    raw + c * chunk_sz,
                    len,
                    NULL,
                    COMPRESSION_LZFSE
                );
                if (enc == 0 || enc >= len) {
                    chunks_ok = false;
                    break;
                }
                cur_off += (uint32_t)enc;
                table[c + 1] = cur_off;
            }

            if (chunks_ok && (double)cur_off < (double)raw_len * 0.85) {
                mf_decmpfs_disk_hdr_t hdr = { 0x636d7066, 12, (uint64_t)raw_len };
                if (fsetxattr(dfd, XATTR_RESOURCEFORK_NAME, rsrc, cur_off, 0, 0) == 0 &&
                    fsetxattr(dfd, "com.apple.decmpfs", &hdr, sizeof(hdr), 0, 0) == 0 &&
                    fchflags(dfd, UF_COMPRESSED) == 0) {
                    encoded_ok = true;
                }
            }
            free(rsrc);
        }
    }

    free(raw);
    close(dfd);

    if (!encoded_ok) {
        unlink(stage_path);
        return false;
    }

    struct stat st_stage;
    if (lstat(stage_path, &st_stage) != 0 || st_stage.st_blocks >= st->st_blocks) {
        unlink(stage_path);
        return false;
    }

    if (out_phys_before) *out_phys_before = (uint64_t)st->st_blocks * 512ULL;
    if (out_phys_after)  *out_phys_after  = (uint64_t)st_stage.st_blocks * 512ULL;
    return true;
}

int32_t mf_lzfse_compress_in_place(
    const char* path,
    const mf_file_fingerprint_t* expected,
    uint64_t* out_phys_before,
    uint64_t* out_phys_after,
    char* out_backup_path,
    size_t backup_cap
) {
    mf_set_backup(out_backup_path, backup_cap, "");
    if (!path || !expected) return MF_COMMIT_ERR_IO;
    int32_t pre = mf_precheck(path, expected, false);
    if (pre != MF_COMMIT_OK) return pre;

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return MF_COMMIT_ERR_IO;
    struct stat st;
    if (fstat(fd, &st) != 0 || !mf_stat_matches(&st, expected)) { close(fd); return MF_COMMIT_SKIP_CHANGED; }
    // Files with a real resource fork can't be decmpfs-compressed without clobbering it.
    if (fgetxattr(fd, XATTR_RESOURCEFORK_NAME, NULL, 0, 0, 0) >= 0) { close(fd); return MF_COMMIT_SKIP_UNSAFE; }

    char stage[PATH_MAX];
    if (!mf_make_stage_path(path, stage, sizeof(stage))) { close(fd); return MF_COMMIT_SKIP_UNSAFE; }

    uint64_t b0 = 0, b1 = 0;
    if (!mf_build_lzfse_stage(fd, &st, stage, &b0, &b1)) { close(fd); return MF_COMMIT_SKIP_INCOMPRESSIBLE; }

    int32_t rc = mf_verify_and_swap(path, fd, stage, expected, out_backup_path, backup_cap);
    close(fd);
    if (rc == MF_COMMIT_OK) {
        if (out_phys_before) *out_phys_before = b0;
        if (out_phys_after) *out_phys_after = b1;
    }
    return rc;
}

// MARK: - Pillar 3C: APFS Copy-on-Write `clonefile` Deduplication

int32_t mf_dedup_replace_with_clone(
    const char* canonical_path,
    const char* dup_path,
    const mf_file_fingerprint_t* expected_dup,
    uint64_t* out_phys_before,
    char* out_backup_path,
    size_t backup_cap
) {
    mf_set_backup(out_backup_path, backup_cap, "");
    if (!canonical_path || !dup_path || !expected_dup) return MF_COMMIT_ERR_IO;
    int32_t pre = mf_precheck(dup_path, expected_dup, true);
    if (pre != MF_COMMIT_OK) return pre;

    struct stat cst;
    if (lstat(canonical_path, &cst) != 0 || !S_ISREG(cst.st_mode)) return MF_COMMIT_SKIP_CHANGED;
    if ((uint64_t)cst.st_dev != expected_dup->dev || (uint64_t)cst.st_ino == expected_dup->ino) return MF_COMMIT_SKIP_UNSAFE;
    if ((uint64_t)cst.st_size != expected_dup->size) return MF_COMMIT_SKIP_MISMATCH;

    int fd = open(dup_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return MF_COMMIT_ERR_IO;
    struct stat st;
    if (fstat(fd, &st) != 0 || !mf_stat_matches(&st, expected_dup)) { close(fd); return MF_COMMIT_SKIP_CHANGED; }
    if ((cst.st_flags & UF_COMPRESSED) && fgetxattr(fd, XATTR_RESOURCEFORK_NAME, NULL, 0, 0, 0) >= 0) {
        close(fd);
        return MF_COMMIT_SKIP_UNSAFE;
    }

    char stage[PATH_MAX];
    if (!mf_make_stage_path(dup_path, stage, sizeof(stage))) { close(fd); return MF_COMMIT_SKIP_UNSAFE; }
    // clonefile fails with EEXIST rather than overwriting anything at `stage`.
    if (clonefile(canonical_path, stage, CLONE_NOFOLLOW) != 0) { close(fd); return MF_COMMIT_ERR_IO; }

    int32_t rc = mf_verify_and_swap(dup_path, fd, stage, expected_dup, out_backup_path, backup_cap);
    close(fd);
    if (rc == MF_COMMIT_OK && out_phys_before) *out_phys_before = (uint64_t)st.st_blocks * 512ULL;
    return rc;
}

// MARK: - Unix Domain Socket Helpers for N -> 1 -> 0 MCP Multiplexer

int mf_unix_listen(const char* sock_path) {
    if (!sock_path) return -1;
    unlink(sock_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    (void)chmod(sock_path, 0600);
    if (listen(fd, 128) != 0) {
        close(fd);
        unlink(sock_path);
        return -1;
    }
    return fd;
}

int mf_unix_connect(const char* sock_path) {
    if (!sock_path) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}
