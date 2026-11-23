#include "massflow_kernel.h"

#include <arpa/inet.h>
#include <arm_neon.h>
#include <compression.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <netinet/tcp_fsm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int mf_collect_all_open_inodes(uint64_t* out_inos, int max_inos) {
    if (!out_inos || max_inos <= 0) return 0;
    int32_t pids[4096];
    int npids = mf_list_user_pids(pids, 4096);
    int32_t self_pid = getpid();
    int count = 0;

    struct proc_fdinfo fds[1024];
    for (int p = 0; p < npids; p++) {
        int32_t pid = pids[p];
        if (pid == self_pid) continue;
        int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
        if (fd_bytes <= 0) continue;
        int nfds = fd_bytes / (int)sizeof(struct proc_fdinfo);
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
    }
    return count;
}

bool mf_is_inode_open_anywhere(uint64_t target_ino) {
    if (target_ino == 0) return false;
    int32_t pids[4096];
    int npids = mf_list_user_pids(pids, 4096);
    int32_t self_pid = getpid();

    struct proc_fdinfo fds[1024];
    for (int p = 0; p < npids; p++) {
        int32_t pid = pids[p];
        if (pid == self_pid) continue;
        int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
        if (fd_bytes <= 0) continue;
        int nfds = fd_bytes / (int)sizeof(struct proc_fdinfo);
        for (int i = 0; i < nfds; i++) {
            if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
                struct vnode_fdinfowithpath vi;
                if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi)) == sizeof(vi)) {
                    if (vi.pvip.vip_vi.vi_stat.vst_ino == target_ino) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
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
    if (!dry_run && mf_is_inode_open_anywhere(st0.st_ino)) {
        return false;
    }

    int fd = open(path, dry_run ? O_RDONLY : O_RDWR);
    if (fd < 0) return false;

    if (!dry_run) {
        if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
            close(fd);
            return false;
        }
    }

    struct timespec orig_times[2] = { st0.st_atimespec, st0.st_mtimespec };

    if (out_logical_bytes) *out_logical_bytes = (uint64_t)st0.st_size;
    if (out_phys_before)   *out_phys_before   = (uint64_t)st0.st_blocks * 512ULL;

    const size_t io_buf_sz = 1024 * 1024;
    uint8_t* buf = (uint8_t*)malloc(io_buf_sz);
    uint64_t punchable = 0;

    off_t pos = 0;
    off_t run_start = -1;
    off_t run_len = 0;

    while (pos < st0.st_size) {
        off_t data_off = lseek(fd, pos, SEEK_DATA);
        if (data_off < 0 || data_off >= st0.st_size) break;
        off_t hole_off = lseek(fd, data_off, SEEK_HOLE);
        if (hole_off < 0 || hole_off > st0.st_size) hole_off = st0.st_size;

        // Align data_off upward to 4096-byte APFS block boundary
        off_t cur = (data_off + 4095) & ~4095LL;
        while (cur + 4096 <= hole_off) {
            size_t want = (size_t)((hole_off - cur) > (off_t)io_buf_sz ? (off_t)io_buf_sz : (hole_off - cur));
            want &= ~4095ULL;
            if (want == 0) break;

            ssize_t n = pread(fd, buf, want, cur);
            if (n < 4096) break;
            size_t blocks_read = (size_t)n & ~4095ULL;

            for (size_t off = 0; off < blocks_read; off += 4096) {
                off_t blk_off = cur + (off_t)off;
                if (mf_is_zero_4k(buf + off)) {
                    punchable += 4096;
                    if (run_start < 0) {
                        run_start = blk_off;
                        run_len = 4096;
                    } else if (run_start + run_len == blk_off) {
                        run_len += 4096;
                    } else {
                        if (!dry_run) {
                            fpunchhole_t ph = { 0, 0, run_start, run_len };
                            (void)fcntl(fd, F_PUNCHHOLE, &ph);
                        }
                        run_start = blk_off;
                        run_len = 4096;
                    }
                } else if (run_start >= 0) {
                    if (!dry_run) {
                        fpunchhole_t ph = { 0, 0, run_start, run_len };
                        (void)fcntl(fd, F_PUNCHHOLE, &ph);
                    }
                    run_start = -1;
                    run_len = 0;
                }
            }
            cur += (off_t)blocks_read;
        }

        if (run_start >= 0) {
            if (!dry_run) {
                fpunchhole_t ph = { 0, 0, run_start, run_len };
                (void)fcntl(fd, F_PUNCHHOLE, &ph);
            }
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

// MARK: - Pillar 3B: XNU Ring-0 Transparent `decmpfs` LZFSE Staging

#pragma pack(push, 1)
typedef struct {
    uint32_t magic; // 0x636d7066 ('fpmc')
    uint32_t type;  // 11 = LZFSE inline (0 data blocks!), 12 = LZFSE 64KB chunked resource fork
    uint64_t size;
} mf_decmpfs_disk_hdr_t;
#pragma pack(pop)

bool mf_stage_decmpfs_lzfse(
    const char* src_path,
    const char* stage_path,
    uint64_t* out_phys_before,
    uint64_t* out_phys_after
) {
    if (!src_path || !stage_path) return false;
    struct stat st;
    if (lstat(src_path, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    if ((st.st_flags & UF_COMPRESSED) != 0) return false;
    if (st.st_nlink > 1 || st.st_size <= 128 || st.st_size > 64 * 1024 * 1024) return false;
    // Skip files that already carry custom resource forks so we never clobber existing xattrs
    if (getxattr(src_path, XATTR_RESOURCEFORK_NAME, NULL, 0, 0, XATTR_NOFOLLOW) > 0) return false;

    int sfd = open(src_path, O_RDONLY);
    if (sfd < 0) return false;

    size_t raw_len = (size_t)st.st_size;
    uint8_t* raw = (uint8_t*)malloc(raw_len);
    if (!raw) { close(sfd); return false; }
    ssize_t got = read(sfd, raw, raw_len);
    close(sfd);
    if (got != (ssize_t)raw_len) { free(raw); return false; }

    unlink(stage_path);
    int dfd = open(stage_path, O_CREAT | O_RDWR | O_TRUNC, st.st_mode & 07777);
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
                fchflags(dfd, st.st_flags | UF_COMPRESSED) == 0) {
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
                fchflags(dfd, st.st_flags | UF_COMPRESSED) == 0) {
                encoded_ok = true;
            }
        }
        free(rsrc);
    }

    free(raw);
    close(dfd);

    if (!encoded_ok) {
        unlink(stage_path);
        return false;
    }

    struct stat st_stage;
    if (lstat(stage_path, &st_stage) != 0 || st_stage.st_blocks >= st.st_blocks) {
        unlink(stage_path);
        return false;
    }

    if (out_phys_before) *out_phys_before = (uint64_t)st.st_blocks * 512ULL;
    if (out_phys_after)  *out_phys_after  = (uint64_t)st_stage.st_blocks * 512ULL;
    return true;
}

// MARK: - Pillar 3C: APFS Copy-on-Write `clonefile` Deduplication & Commit

bool mf_stage_clonefile_dedup(
    const char* canonical_path,
    const char* dup_path,
    const char* stage_path,
    uint64_t* out_phys_before
) {
    if (!canonical_path || !dup_path || !stage_path) return false;
    struct stat st_can, st_dup;
    if (lstat(canonical_path, &st_can) != 0 || lstat(dup_path, &st_dup) != 0) return false;
    if (!S_ISREG(st_can.st_mode) || !S_ISREG(st_dup.st_mode)) return false;
    if (st_can.st_ino == st_dup.st_ino || st_can.st_dev != st_dup.st_dev) return false;
    if (st_dup.st_nlink > 1) return false;

    unlink(stage_path);
    if (clonefile(canonical_path, stage_path, 0) != 0) {
        return false;
    }
    if (out_phys_before) *out_phys_before = (uint64_t)st_dup.st_blocks * 512ULL;
    return true;
}

bool mf_commit_staged_file(const char* orig_path, const char* stage_path, bool check_open_fds) {
    if (!orig_path || !stage_path) return false;
    struct stat st_orig;
    if (lstat(orig_path, &st_orig) != 0) {
        unlink(stage_path);
        return false;
    }
    if (check_open_fds && mf_is_inode_open_anywhere(st_orig.st_ino)) {
        unlink(stage_path);
        return false;
    }

    (void)chmod(stage_path, st_orig.st_mode & 07777);
    struct timespec ts[2] = { st_orig.st_atimespec, st_orig.st_mtimespec };
    (void)utimensat(AT_FDCWD, stage_path, ts, AT_SYMLINK_NOFOLLOW);

    if (rename(stage_path, orig_path) != 0) {
        unlink(stage_path);
        return false;
    }
    return true;
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
