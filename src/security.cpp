#include "pieces/security.hpp"

#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <fstream>
#include <map>
#include <stdexcept>
#include <system_error>

namespace pieces {

namespace {

uint32_t host_audit_arch() {
#if defined(__x86_64__)
    return AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    return AUDIT_ARCH_AARCH64;
#elif defined(__riscv) && (__riscv_xlen == 64)
    return AUDIT_ARCH_RISCV64;
#elif defined(__i386__)
    return AUDIT_ARCH_I386;
#elif defined(__arm__)
    return AUDIT_ARCH_ARM;
#else
    return 0;
#endif
}

std::string normalize_cap_token(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (s.rfind("cap_", 0) != 0 && s != "all") {
        s = "cap_" + s;
    }
    return s;
}

const std::map<std::string, int>& syscall_name_table() {
    static const std::map<std::string, int> kTable = {
#ifdef __NR_accept
        {"accept", __NR_accept},
#endif
#ifdef __NR_accept4
        {"accept4", __NR_accept4},
#endif
#ifdef __NR_access
        {"access", __NR_access},
#endif
#ifdef __NR_alarm
        {"alarm", __NR_alarm},
#endif
#ifdef __NR_arch_prctl
        {"arch_prctl", __NR_arch_prctl},
#endif
#ifdef __NR_bind
        {"bind", __NR_bind},
#endif
#ifdef __NR_brk
        {"brk", __NR_brk},
#endif
#ifdef __NR_capget
        {"capget", __NR_capget},
#endif
#ifdef __NR_capset
        {"capset", __NR_capset},
#endif
#ifdef __NR_chdir
        {"chdir", __NR_chdir},
#endif
#ifdef __NR_chmod
        {"chmod", __NR_chmod},
#endif
#ifdef __NR_chown
        {"chown", __NR_chown},
#endif
#ifdef __NR_clock_getres
        {"clock_getres", __NR_clock_getres},
#endif
#ifdef __NR_clock_gettime
        {"clock_gettime", __NR_clock_gettime},
#endif
#ifdef __NR_clock_nanosleep
        {"clock_nanosleep", __NR_clock_nanosleep},
#endif
#ifdef __NR_clone
        {"clone", __NR_clone},
#endif
#ifdef __NR_clone3
        {"clone3", __NR_clone3},
#endif
#ifdef __NR_close
        {"close", __NR_close},
#endif
#ifdef __NR_close_range
        {"close_range", __NR_close_range},
#endif
#ifdef __NR_connect
        {"connect", __NR_connect},
#endif
#ifdef __NR_copy_file_range
        {"copy_file_range", __NR_copy_file_range},
#endif
#ifdef __NR_creat
        {"creat", __NR_creat},
#endif
#ifdef __NR_dup
        {"dup", __NR_dup},
#endif
#ifdef __NR_dup2
        {"dup2", __NR_dup2},
#endif
#ifdef __NR_dup3
        {"dup3", __NR_dup3},
#endif
#ifdef __NR_epoll_create
        {"epoll_create", __NR_epoll_create},
#endif
#ifdef __NR_epoll_create1
        {"epoll_create1", __NR_epoll_create1},
#endif
#ifdef __NR_epoll_ctl
        {"epoll_ctl", __NR_epoll_ctl},
#endif
#ifdef __NR_epoll_pwait
        {"epoll_pwait", __NR_epoll_pwait},
#endif
#ifdef __NR_epoll_pwait2
        {"epoll_pwait2", __NR_epoll_pwait2},
#endif
#ifdef __NR_epoll_wait
        {"epoll_wait", __NR_epoll_wait},
#endif
#ifdef __NR_eventfd
        {"eventfd", __NR_eventfd},
#endif
#ifdef __NR_eventfd2
        {"eventfd2", __NR_eventfd2},
#endif
#ifdef __NR_execve
        {"execve", __NR_execve},
#endif
#ifdef __NR_execveat
        {"execveat", __NR_execveat},
#endif
#ifdef __NR_exit
        {"exit", __NR_exit},
#endif
#ifdef __NR_exit_group
        {"exit_group", __NR_exit_group},
#endif
#ifdef __NR_faccessat
        {"faccessat", __NR_faccessat},
#endif
#ifdef __NR_faccessat2
        {"faccessat2", __NR_faccessat2},
#endif
#ifdef __NR_fadvise64
        {"fadvise64", __NR_fadvise64},
#endif
#ifdef __NR_fallocate
        {"fallocate", __NR_fallocate},
#endif
#ifdef __NR_fchdir
        {"fchdir", __NR_fchdir},
#endif
#ifdef __NR_fchmod
        {"fchmod", __NR_fchmod},
#endif
#ifdef __NR_fchmodat
        {"fchmodat", __NR_fchmodat},
#endif
#ifdef __NR_fchown
        {"fchown", __NR_fchown},
#endif
#ifdef __NR_fchownat
        {"fchownat", __NR_fchownat},
#endif
#ifdef __NR_fcntl
        {"fcntl", __NR_fcntl},
#endif
#ifdef __NR_fdatasync
        {"fdatasync", __NR_fdatasync},
#endif
#ifdef __NR_fgetxattr
        {"fgetxattr", __NR_fgetxattr},
#endif
#ifdef __NR_flistxattr
        {"flistxattr", __NR_flistxattr},
#endif
#ifdef __NR_flock
        {"flock", __NR_flock},
#endif
#ifdef __NR_fork
        {"fork", __NR_fork},
#endif
#ifdef __NR_fstat
        {"fstat", __NR_fstat},
#endif
#ifdef __NR_fstatfs
        {"fstatfs", __NR_fstatfs},
#endif
#ifdef __NR_fsync
        {"fsync", __NR_fsync},
#endif
#ifdef __NR_ftruncate
        {"ftruncate", __NR_ftruncate},
#endif
#ifdef __NR_futex
        {"futex", __NR_futex},
#endif
#ifdef __NR_getcpu
        {"getcpu", __NR_getcpu},
#endif
#ifdef __NR_getcwd
        {"getcwd", __NR_getcwd},
#endif
#ifdef __NR_getdents
        {"getdents", __NR_getdents},
#endif
#ifdef __NR_getdents64
        {"getdents64", __NR_getdents64},
#endif
#ifdef __NR_getegid
        {"getegid", __NR_getegid},
#endif
#ifdef __NR_geteuid
        {"geteuid", __NR_geteuid},
#endif
#ifdef __NR_getgid
        {"getgid", __NR_getgid},
#endif
#ifdef __NR_getgroups
        {"getgroups", __NR_getgroups},
#endif
#ifdef __NR_getitimer
        {"getitimer", __NR_getitimer},
#endif
#ifdef __NR_getpeername
        {"getpeername", __NR_getpeername},
#endif
#ifdef __NR_getpgid
        {"getpgid", __NR_getpgid},
#endif
#ifdef __NR_getpgrp
        {"getpgrp", __NR_getpgrp},
#endif
#ifdef __NR_getpid
        {"getpid", __NR_getpid},
#endif
#ifdef __NR_getppid
        {"getppid", __NR_getppid},
#endif
#ifdef __NR_getpriority
        {"getpriority", __NR_getpriority},
#endif
#ifdef __NR_getrandom
        {"getrandom", __NR_getrandom},
#endif
#ifdef __NR_getresgid
        {"getresgid", __NR_getresgid},
#endif
#ifdef __NR_getresuid
        {"getresuid", __NR_getresuid},
#endif
#ifdef __NR_getrlimit
        {"getrlimit", __NR_getrlimit},
#endif
#ifdef __NR_getrusage
        {"getrusage", __NR_getrusage},
#endif
#ifdef __NR_getsid
        {"getsid", __NR_getsid},
#endif
#ifdef __NR_getsockname
        {"getsockname", __NR_getsockname},
#endif
#ifdef __NR_getsockopt
        {"getsockopt", __NR_getsockopt},
#endif
#ifdef __NR_gettid
        {"gettid", __NR_gettid},
#endif
#ifdef __NR_gettimeofday
        {"gettimeofday", __NR_gettimeofday},
#endif
#ifdef __NR_getuid
        {"getuid", __NR_getuid},
#endif
#ifdef __NR_getxattr
        {"getxattr", __NR_getxattr},
#endif
#ifdef __NR_ioctl
        {"ioctl", __NR_ioctl},
#endif
#ifdef __NR_kill
        {"kill", __NR_kill},
#endif
#ifdef __NR_lchown
        {"lchown", __NR_lchown},
#endif
#ifdef __NR_lgetxattr
        {"lgetxattr", __NR_lgetxattr},
#endif
#ifdef __NR_link
        {"link", __NR_link},
#endif
#ifdef __NR_linkat
        {"linkat", __NR_linkat},
#endif
#ifdef __NR_listen
        {"listen", __NR_listen},
#endif
#ifdef __NR_listxattr
        {"listxattr", __NR_listxattr},
#endif
#ifdef __NR_llistxattr
        {"llistxattr", __NR_llistxattr},
#endif
#ifdef __NR_lseek
        {"lseek", __NR_lseek},
#endif
#ifdef __NR_lstat
        {"lstat", __NR_lstat},
#endif
#ifdef __NR_madvise
        {"madvise", __NR_madvise},
#endif
#ifdef __NR_membarrier
        {"membarrier", __NR_membarrier},
#endif
#ifdef __NR_memfd_create
        {"memfd_create", __NR_memfd_create},
#endif
#ifdef __NR_mkdir
        {"mkdir", __NR_mkdir},
#endif
#ifdef __NR_mkdirat
        {"mkdirat", __NR_mkdirat},
#endif
#ifdef __NR_mknod
        {"mknod", __NR_mknod},
#endif
#ifdef __NR_mknodat
        {"mknodat", __NR_mknodat},
#endif
#ifdef __NR_mlock
        {"mlock", __NR_mlock},
#endif
#ifdef __NR_mmap
        {"mmap", __NR_mmap},
#endif
#ifdef __NR_mprotect
        {"mprotect", __NR_mprotect},
#endif
#ifdef __NR_mremap
        {"mremap", __NR_mremap},
#endif
#ifdef __NR_msgctl
        {"msgctl", __NR_msgctl},
#endif
#ifdef __NR_msgget
        {"msgget", __NR_msgget},
#endif
#ifdef __NR_msgrcv
        {"msgrcv", __NR_msgrcv},
#endif
#ifdef __NR_msgsnd
        {"msgsnd", __NR_msgsnd},
#endif
#ifdef __NR_msync
        {"msync", __NR_msync},
#endif
#ifdef __NR_munlock
        {"munlock", __NR_munlock},
#endif
#ifdef __NR_munmap
        {"munmap", __NR_munmap},
#endif
#ifdef __NR_nanosleep
        {"nanosleep", __NR_nanosleep},
#endif
#ifdef __NR_newfstatat
        {"newfstatat", __NR_newfstatat},
#endif
#ifdef __NR_open
        {"open", __NR_open},
#endif
#ifdef __NR_openat
        {"openat", __NR_openat},
#endif
#ifdef __NR_openat2
        {"openat2", __NR_openat2},
#endif
#ifdef __NR_pause
        {"pause", __NR_pause},
#endif
#ifdef __NR_pipe
        {"pipe", __NR_pipe},
#endif
#ifdef __NR_pipe2
        {"pipe2", __NR_pipe2},
#endif
#ifdef __NR_poll
        {"poll", __NR_poll},
#endif
#ifdef __NR_ppoll
        {"ppoll", __NR_ppoll},
#endif
#ifdef __NR_prctl
        {"prctl", __NR_prctl},
#endif
#ifdef __NR_pread64
        {"pread64", __NR_pread64},
#endif
#ifdef __NR_preadv
        {"preadv", __NR_preadv},
#endif
#ifdef __NR_preadv2
        {"preadv2", __NR_preadv2},
#endif
#ifdef __NR_prlimit64
        {"prlimit64", __NR_prlimit64},
#endif
#ifdef __NR_pselect6
        {"pselect6", __NR_pselect6},
#endif
#ifdef __NR_pwrite64
        {"pwrite64", __NR_pwrite64},
#endif
#ifdef __NR_pwritev
        {"pwritev", __NR_pwritev},
#endif
#ifdef __NR_pwritev2
        {"pwritev2", __NR_pwritev2},
#endif
#ifdef __NR_read
        {"read", __NR_read},
#endif
#ifdef __NR_readlink
        {"readlink", __NR_readlink},
#endif
#ifdef __NR_readlinkat
        {"readlinkat", __NR_readlinkat},
#endif
#ifdef __NR_readv
        {"readv", __NR_readv},
#endif
#ifdef __NR_recvfrom
        {"recvfrom", __NR_recvfrom},
#endif
#ifdef __NR_recvmmsg
        {"recvmmsg", __NR_recvmmsg},
#endif
#ifdef __NR_recvmsg
        {"recvmsg", __NR_recvmsg},
#endif
#ifdef __NR_rename
        {"rename", __NR_rename},
#endif
#ifdef __NR_renameat
        {"renameat", __NR_renameat},
#endif
#ifdef __NR_renameat2
        {"renameat2", __NR_renameat2},
#endif
#ifdef __NR_restart_syscall
        {"restart_syscall", __NR_restart_syscall},
#endif
#ifdef __NR_rmdir
        {"rmdir", __NR_rmdir},
#endif
#ifdef __NR_rseq
        {"rseq", __NR_rseq},
#endif
#ifdef __NR_rt_sigaction
        {"rt_sigaction", __NR_rt_sigaction},
#endif
#ifdef __NR_rt_sigpending
        {"rt_sigpending", __NR_rt_sigpending},
#endif
#ifdef __NR_rt_sigprocmask
        {"rt_sigprocmask", __NR_rt_sigprocmask},
#endif
#ifdef __NR_rt_sigqueueinfo
        {"rt_sigqueueinfo", __NR_rt_sigqueueinfo},
#endif
#ifdef __NR_rt_sigreturn
        {"rt_sigreturn", __NR_rt_sigreturn},
#endif
#ifdef __NR_rt_sigsuspend
        {"rt_sigsuspend", __NR_rt_sigsuspend},
#endif
#ifdef __NR_rt_sigtimedwait
        {"rt_sigtimedwait", __NR_rt_sigtimedwait},
#endif
#ifdef __NR_rt_tgsigqueueinfo
        {"rt_tgsigqueueinfo", __NR_rt_tgsigqueueinfo},
#endif
#ifdef __NR_sched_getaffinity
        {"sched_getaffinity", __NR_sched_getaffinity},
#endif
#ifdef __NR_sched_getattr
        {"sched_getattr", __NR_sched_getattr},
#endif
#ifdef __NR_sched_getparam
        {"sched_getparam", __NR_sched_getparam},
#endif
#ifdef __NR_sched_getscheduler
        {"sched_getscheduler", __NR_sched_getscheduler},
#endif
#ifdef __NR_sched_setaffinity
        {"sched_setaffinity", __NR_sched_setaffinity},
#endif
#ifdef __NR_sched_yield
        {"sched_yield", __NR_sched_yield},
#endif
#ifdef __NR_seccomp
        {"seccomp", __NR_seccomp},
#endif
#ifdef __NR_select
        {"select", __NR_select},
#endif
#ifdef __NR_semctl
        {"semctl", __NR_semctl},
#endif
#ifdef __NR_semget
        {"semget", __NR_semget},
#endif
#ifdef __NR_semop
        {"semop", __NR_semop},
#endif
#ifdef __NR_semtimedop
        {"semtimedop", __NR_semtimedop},
#endif
#ifdef __NR_sendfile
        {"sendfile", __NR_sendfile},
#endif
#ifdef __NR_sendmmsg
        {"sendmmsg", __NR_sendmmsg},
#endif
#ifdef __NR_sendmsg
        {"sendmsg", __NR_sendmsg},
#endif
#ifdef __NR_sendto
        {"sendto", __NR_sendto},
#endif
#ifdef __NR_set_robust_list
        {"set_robust_list", __NR_set_robust_list},
#endif
#ifdef __NR_set_tid_address
        {"set_tid_address", __NR_set_tid_address},
#endif
#ifdef __NR_setgid
        {"setgid", __NR_setgid},
#endif
#ifdef __NR_setgroups
        {"setgroups", __NR_setgroups},
#endif
#ifdef __NR_setitimer
        {"setitimer", __NR_setitimer},
#endif
#ifdef __NR_setpgid
        {"setpgid", __NR_setpgid},
#endif
#ifdef __NR_setpriority
        {"setpriority", __NR_setpriority},
#endif
#ifdef __NR_setregid
        {"setregid", __NR_setregid},
#endif
#ifdef __NR_setresgid
        {"setresgid", __NR_setresgid},
#endif
#ifdef __NR_setresuid
        {"setresuid", __NR_setresuid},
#endif
#ifdef __NR_setreuid
        {"setreuid", __NR_setreuid},
#endif
#ifdef __NR_setrlimit
        {"setrlimit", __NR_setrlimit},
#endif
#ifdef __NR_setsid
        {"setsid", __NR_setsid},
#endif
#ifdef __NR_setsockopt
        {"setsockopt", __NR_setsockopt},
#endif
#ifdef __NR_setuid
        {"setuid", __NR_setuid},
#endif
#ifdef __NR_shmat
        {"shmat", __NR_shmat},
#endif
#ifdef __NR_shmctl
        {"shmctl", __NR_shmctl},
#endif
#ifdef __NR_shmdt
        {"shmdt", __NR_shmdt},
#endif
#ifdef __NR_shmget
        {"shmget", __NR_shmget},
#endif
#ifdef __NR_shutdown
        {"shutdown", __NR_shutdown},
#endif
#ifdef __NR_sigaltstack
        {"sigaltstack", __NR_sigaltstack},
#endif
#ifdef __NR_signalfd
        {"signalfd", __NR_signalfd},
#endif
#ifdef __NR_signalfd4
        {"signalfd4", __NR_signalfd4},
#endif
#ifdef __NR_socket
        {"socket", __NR_socket},
#endif
#ifdef __NR_socketpair
        {"socketpair", __NR_socketpair},
#endif
#ifdef __NR_splice
        {"splice", __NR_splice},
#endif
#ifdef __NR_stat
        {"stat", __NR_stat},
#endif
#ifdef __NR_statfs
        {"statfs", __NR_statfs},
#endif
#ifdef __NR_statx
        {"statx", __NR_statx},
#endif
#ifdef __NR_symlink
        {"symlink", __NR_symlink},
#endif
#ifdef __NR_symlinkat
        {"symlinkat", __NR_symlinkat},
#endif
#ifdef __NR_sync
        {"sync", __NR_sync},
#endif
#ifdef __NR_sysinfo
        {"sysinfo", __NR_sysinfo},
#endif
#ifdef __NR_tee
        {"tee", __NR_tee},
#endif
#ifdef __NR_tgkill
        {"tgkill", __NR_tgkill},
#endif
#ifdef __NR_time
        {"time", __NR_time},
#endif
#ifdef __NR_timer_create
        {"timer_create", __NR_timer_create},
#endif
#ifdef __NR_timer_delete
        {"timer_delete", __NR_timer_delete},
#endif
#ifdef __NR_timer_gettime
        {"timer_gettime", __NR_timer_gettime},
#endif
#ifdef __NR_timer_settime
        {"timer_settime", __NR_timer_settime},
#endif
#ifdef __NR_timerfd_create
        {"timerfd_create", __NR_timerfd_create},
#endif
#ifdef __NR_timerfd_gettime
        {"timerfd_gettime", __NR_timerfd_gettime},
#endif
#ifdef __NR_timerfd_settime
        {"timerfd_settime", __NR_timerfd_settime},
#endif
#ifdef __NR_times
        {"times", __NR_times},
#endif
#ifdef __NR_tkill
        {"tkill", __NR_tkill},
#endif
#ifdef __NR_truncate
        {"truncate", __NR_truncate},
#endif
#ifdef __NR_umask
        {"umask", __NR_umask},
#endif
#ifdef __NR_uname
        {"uname", __NR_uname},
#endif
#ifdef __NR_unlink
        {"unlink", __NR_unlink},
#endif
#ifdef __NR_unlinkat
        {"unlinkat", __NR_unlinkat},
#endif
#ifdef __NR_utime
        {"utime", __NR_utime},
#endif
#ifdef __NR_utimensat
        {"utimensat", __NR_utimensat},
#endif
#ifdef __NR_utimes
        {"utimes", __NR_utimes},
#endif
#ifdef __NR_vfork
        {"vfork", __NR_vfork},
#endif
#ifdef __NR_wait4
        {"wait4", __NR_wait4},
#endif
#ifdef __NR_waitid
        {"waitid", __NR_waitid},
#endif
#ifdef __NR_write
        {"write", __NR_write},
#endif
#ifdef __NR_writev
        {"writev", __NR_writev},
#endif
#ifdef __NR_get_robust_list
        {"get_robust_list", __NR_get_robust_list},
#endif
#ifdef __NR_set_thread_area
        {"set_thread_area", __NR_set_thread_area},
#endif
#ifdef __NR_get_thread_area
        {"get_thread_area", __NR_get_thread_area},
#endif
#ifdef __NR_epoll_ctl_old
        {"epoll_ctl_old", __NR_epoll_ctl_old},
#endif
#ifdef __NR_epoll_wait_old
        {"epoll_wait_old", __NR_epoll_wait_old},
#endif
    };
    return kTable;
}

uint32_t oci_action_to_bpf(const std::string& action, uint32_t errno_ret = EPERM) {
    if (action == "SCMP_ACT_ALLOW") return SECCOMP_RET_ALLOW;
    if (action == "SCMP_ACT_ERRNO") return SECCOMP_RET_ERRNO | (errno_ret & 0x0000FFFFU);
    if (action == "SCMP_ACT_KILL" || action == "SCMP_ACT_KILL_THREAD") return SECCOMP_RET_KILL;
    if (action == "SCMP_ACT_KILL_PROCESS") return SECCOMP_RET_KILL_PROCESS;
    if (action == "SCMP_ACT_TRAP") return SECCOMP_RET_TRAP;
    if (action == "SCMP_ACT_LOG") return SECCOMP_RET_LOG;
    throw std::invalid_argument("Unsupported OCI seccomp action: '" + action + "'");
}

void write_proc_attr_file(const char* path, const std::string& content) {
    int fd = ::open(path, O_WRONLY);
    if (fd < 0) {
        throw std::system_error(errno, std::generic_category(), std::string("open(") + path + ")");
    }
    ssize_t w = ::write(fd, content.data(), content.size());
    int saved_err = errno;
    ::close(fd);
    if (w != static_cast<ssize_t>(content.size())) {
        throw std::system_error(saved_err, std::generic_category(), std::string("write(") + path + ")");
    }
}

}  // namespace

cap_value_t parse_capability_name(const std::string& name) {
    std::string norm = normalize_cap_token(name);
    cap_value_t val = 0;
    if (::cap_from_name(norm.c_str(), &val) != 0) {
        throw std::invalid_argument("Unknown Linux capability: '" + name + "'");
    }
    return val;
}

std::set<cap_value_t> default_container_capabilities() {
    return {
        CAP_CHOWN,
        CAP_DAC_OVERRIDE,
        CAP_FOWNER,
        CAP_FSETID,
        CAP_KILL,
        CAP_SETGID,
        CAP_SETUID,
        CAP_SETPCAP,
        CAP_NET_BIND_SERVICE,
        CAP_NET_RAW,
        CAP_SYS_CHROOT,
        CAP_MKNOD,
        CAP_AUDIT_WRITE,
        CAP_SETFCAP,
    };
}

std::set<cap_value_t> compute_target_capabilities(
    const std::vector<std::string>& cap_add,
    const std::vector<std::string>& cap_drop) {
    std::set<cap_value_t> result = default_container_capabilities();

    for (const auto& raw : cap_drop) {
        std::string norm = normalize_cap_token(raw);
        if (norm == "all") {
            result.clear();
        } else {
            result.erase(parse_capability_name(raw));
        }
    }

    for (const auto& raw : cap_add) {
        std::string norm = normalize_cap_token(raw);
        if (norm == "all") {
            for (cap_value_t c = 0; c <= CAP_LAST_CAP; ++c) {
                if (CAP_IS_SUPPORTED(c)) result.insert(c);
            }
        } else {
            result.insert(parse_capability_name(raw));
        }
    }
    return result;
}

void drop_capabilities_to_set(const std::set<cap_value_t>& allowed_caps) {
    for (cap_value_t c = 0; c <= CAP_LAST_CAP; ++c) {
        if (!CAP_IS_SUPPORTED(c)) continue;
        if (!allowed_caps.contains(c)) {
            ::cap_drop_bound(c);
        }
    }

    cap_t caps = ::cap_init();
    if (!caps) {
        throw std::system_error(errno, std::generic_category(), "cap_init");
    }

    std::vector<cap_value_t> vec;
    vec.reserve(allowed_caps.size());
    cap_t cur = ::cap_get_proc();
    for (cap_value_t c : allowed_caps) {
        cap_flag_value_t flag = CAP_CLEAR;
        if (cur) {
            ::cap_get_flag(cur, c, CAP_PERMITTED, &flag);
        }
        if (flag == CAP_SET) {
            vec.push_back(c);
        }
    }
    if (cur) ::cap_free(cur);

    if (!vec.empty()) {
        int n = static_cast<int>(vec.size());
        if (::cap_set_flag(caps, CAP_EFFECTIVE, n, vec.data(), CAP_SET) != 0 ||
            ::cap_set_flag(caps, CAP_PERMITTED, n, vec.data(), CAP_SET) != 0 ||
            ::cap_set_flag(caps, CAP_INHERITABLE, n, vec.data(), CAP_SET) != 0) {
            int err = errno;
            ::cap_free(caps);
            throw std::system_error(err, std::generic_category(), "cap_set_flag");
        }
    }

    if (::cap_set_proc(caps) != 0) {
        int err = errno;
        ::cap_free(caps);
        throw std::system_error(err, std::generic_category(), "cap_set_proc");
    }
    ::cap_free(caps);
}

std::optional<int> resolve_syscall_number(const std::string& name) {
    const auto& tbl = syscall_name_table();
    auto it = tbl.find(name);
    if (it != tbl.end()) return it->second;
    return std::nullopt;
}

std::vector<int> default_allowed_syscalls() {
    std::vector<int> nrs;
    nrs.reserve(syscall_name_table().size());
    for (const auto& [name, nr] : syscall_name_table()) {
        (void)name;
        nrs.push_back(nr);
    }
    return nrs;
}

SeccompProgram build_allowlist_seccomp_filter(
    const std::vector<int>& allowed_syscalls,
    uint32_t default_action) {
    SeccompProgram prog;
    uint32_t arch = host_audit_arch();
    if (arch == 0) return prog;

    // 1. Strict ABI architecture check (prevents 32-bit compat syscall bypass)
    prog.instructions.push_back(
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, arch))));
    prog.instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0));
    prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // 2. Load syscall number
    prog.instructions.push_back(
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, nr))));

    // 3. Explicit allowlist
    for (int nr : allowed_syscalls) {
        prog.instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(nr), 0, 1));
        prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    // 4. Default deny
    prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, default_action));
    return prog;
}

SeccompProgram build_seccomp_from_oci_json(const JsonValue& seccomp_obj) {
    if (!seccomp_obj.is_object()) {
        throw std::invalid_argument("OCI seccomp profile must be a JSON object");
    }

    std::string def_act_str = "SCMP_ACT_ERRNO";
    if (const JsonValue* da = seccomp_obj.find("defaultAction"); da && da->is_string()) {
        def_act_str = da->as_string();
    }
    uint32_t def_errno = EPERM;
    if (const JsonValue* de = seccomp_obj.find("defaultErrnoRet"); de && de->is_int()) {
        def_errno = static_cast<uint32_t>(de->as_int());
    }
    uint32_t default_action = oci_action_to_bpf(def_act_str, def_errno);

    std::vector<SeccompRule> rules;
    if (const JsonValue* syscalls = seccomp_obj.find("syscalls"); syscalls && syscalls->is_array()) {
        for (const auto& entry : syscalls->as_array()) {
            const JsonValue* names = entry.find("names");
            const JsonValue* act = entry.find("action");
            if (!names || !names->is_array() || !act || !act->is_string()) continue;
            uint32_t errno_ret = EPERM;
            if (const JsonValue* er = entry.find("errnoRet"); er && er->is_int()) {
                errno_ret = static_cast<uint32_t>(er->as_int());
            }
            uint32_t bpf_act = oci_action_to_bpf(act->as_string(), errno_ret);
            for (const auto& name_v : names->as_array()) {
                if (!name_v.is_string()) continue;
                if (auto nr = resolve_syscall_number(name_v.as_string())) {
                    rules.push_back({*nr, bpf_act});
                }
            }
        }
    }

    SeccompProgram prog;
    uint32_t arch = host_audit_arch();
    if (arch == 0) return prog;

    prog.instructions.push_back(
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, arch))));
    prog.instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0));
    prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    prog.instructions.push_back(
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, nr))));

    for (const auto& rule : rules) {
        prog.instructions.push_back(
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(rule.syscall_nr), 0, 1));
        prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, rule.action));
    }
    prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, default_action));
    return prog;
}

SeccompProgram load_seccomp_profile_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Cannot open seccomp profile: " + path);
    }
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return build_seccomp_from_oci_json(JsonValue::parse(content));
}

void apply_seccomp_program(const SeccompProgram& prog) {
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        throw std::system_error(errno, std::generic_category(), "prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if (prog.instructions.empty()) return;
    struct sock_fprog fprog{};
    fprog.len = static_cast<unsigned short>(prog.instructions.size());
    fprog.filter = const_cast<sock_filter*>(prog.instructions.data());
    if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) != 0) {
        throw std::system_error(errno, std::generic_category(), "prctl(PR_SET_SECCOMP)");
    }
}

void apply_default_seccomp_filter() {
    apply_seccomp_program(
        build_allowlist_seccomp_filter(
            default_allowed_syscalls(),
            SECCOMP_RET_ERRNO | (EPERM & 0x0000FFFFU)));
}

UserSpec parse_user_spec(const std::string& spec) {
    if (spec.empty()) {
        throw std::invalid_argument("User specification cannot be empty");
    }
    auto colon = spec.find(':');
    std::string uid_s = (colon == std::string::npos) ? spec : spec.substr(0, colon);
    std::string gid_s = (colon == std::string::npos) ? "" : spec.substr(colon + 1);

    auto parse_id = [](const std::string& s, const char* label) -> uint32_t {
        if (s.empty() || !std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); })) {
            throw std::invalid_argument(std::string("Invalid numeric ") + label + ": '" + s + "'");
        }
        return static_cast<uint32_t>(std::stoul(s));
    };

    UserSpec us;
    us.uid = static_cast<uid_t>(parse_id(uid_s, "UID"));
    if (colon != std::string::npos) {
        us.gid = static_cast<gid_t>(parse_id(gid_s, "GID"));
        us.has_gid = true;
    } else {
        us.gid = static_cast<gid_t>(us.uid);
    }
    return us;
}

void apply_process_user(
    uid_t uid,
    gid_t gid,
    const std::vector<gid_t>& additional_gids,
    bool run_as_non_root) {
    if (run_as_non_root && uid == 0) {
        throw std::runtime_error("Security policy forbids running as UID 0 (runAsNonRoot=true)");
    }
    if (!additional_gids.empty()) {
        if (::setgroups(additional_gids.size(), additional_gids.data()) != 0 && errno != EPERM) {
            throw std::system_error(errno, std::generic_category(), "setgroups");
        }
    } else if (::geteuid() == 0) {
        ::setgroups(0, nullptr);
    }

    if (gid != ::getgid() || ::getegid() != gid) {
        if (::setgid(gid) != 0) {
            throw std::system_error(errno, std::generic_category(), "setgid");
        }
    }
    if (uid != ::getuid() || ::geteuid() != uid) {
        if (::setuid(uid) != 0) {
            throw std::system_error(errno, std::generic_category(), "setuid");
        }
    }
}

SecurityOptions parse_security_opts(const std::vector<std::string>& opts) {
    SecurityOptions out;
    for (const auto& opt : opts) {
        auto eq = opt.find('=');
        if (eq == std::string::npos) {
            throw std::invalid_argument("Invalid --security-opt '" + opt + "'; expected key=value");
        }
        std::string key = opt.substr(0, eq);
        std::string val = opt.substr(eq + 1);
        if (key == "apparmor") {
            out.apparmor_profile = val;
        } else if (key == "label") {
            out.selinux_label = val;
        } else {
            throw std::invalid_argument("Unsupported --security-opt key '" + key + "'; expected apparmor or label");
        }
    }
    return out;
}

void apply_apparmor_profile(const std::string& profile) {
    if (profile.empty() || profile == "unconfined") return;
    std::string payload = "exec " + profile;
    if (::access("/proc/self/attr/apparmor/exec", W_OK) == 0) {
        write_proc_attr_file("/proc/self/attr/apparmor/exec", payload);
    } else {
        write_proc_attr_file("/proc/self/attr/exec", payload);
    }
}

void apply_selinux_label(const std::string& label) {
    if (label.empty() || label == "disable") return;
    write_proc_attr_file("/proc/self/attr/exec", label);
}

}  // namespace pieces
