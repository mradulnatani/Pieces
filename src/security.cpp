#include "pieces/security.hpp"

#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
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
    std::set<cap_value_t> caps = {
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
    return caps;
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
                if (CAP_IS_SUPPORTED(c)) {
                    result.insert(c);
                }
            }
        } else {
            result.insert(parse_capability_name(raw));
        }
    }

    return result;
}

void drop_capabilities_to_set(const std::set<cap_value_t>& allowed_caps) {
    // Drop unneeded capabilities from bounding set first (requires CAP_SETPCAP while still held)
    for (cap_value_t c = 0; c <= CAP_LAST_CAP; ++c) {
        if (!CAP_IS_SUPPORTED(c)) {
            continue;
        }
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
    for (cap_value_t c : allowed_caps) {
        // Only keep capabilities currently present in effective/permitted
        cap_t cur = ::cap_get_proc();
        cap_flag_value_t flag = CAP_CLEAR;
        if (cur) {
            ::cap_get_flag(cur, c, CAP_PERMITTED, &flag);
            ::cap_free(cur);
        }
        if (flag == CAP_SET) {
            vec.push_back(c);
        }
    }

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

std::vector<int> default_blocked_syscalls() {
    std::vector<int> blocked = {
#ifdef __NR_kexec_load
        __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
        __NR_kexec_file_load,
#endif
#ifdef __NR_init_module
        __NR_init_module,
#endif
#ifdef __NR_finit_module
        __NR_finit_module,
#endif
#ifdef __NR_delete_module
        __NR_delete_module,
#endif
#ifdef __NR_reboot
        __NR_reboot,
#endif
#ifdef __NR_swapon
        __NR_swapon,
#endif
#ifdef __NR_swapoff
        __NR_swapoff,
#endif
#ifdef __NR_mount
        __NR_mount,
#endif
#ifdef __NR_umount2
        __NR_umount2,
#endif
#ifdef __NR_pivot_root
        __NR_pivot_root,
#endif
#ifdef __NR_acct
        __NR_acct,
#endif
#ifdef __NR_settimeofday
        __NR_settimeofday,
#endif
#ifdef __NR_adjtimex
        __NR_adjtimex,
#endif
#ifdef __NR_clock_settime
        __NR_clock_settime,
#endif
#ifdef __NR_ptrace
        __NR_ptrace,
#endif
#ifdef __NR_bpf
        __NR_bpf,
#endif
#ifdef __NR_perf_event_open
        __NR_perf_event_open,
#endif
#ifdef __NR_keyctl
        __NR_keyctl,
#endif
#ifdef __NR_add_key
        __NR_add_key,
#endif
#ifdef __NR_request_key
        __NR_request_key,
#endif
#ifdef __NR_open_by_handle_at
        __NR_open_by_handle_at,
#endif
#ifdef __NR_userfaultfd
        __NR_userfaultfd,
#endif
#ifdef __NR_io_uring_setup
        __NR_io_uring_setup,
#endif
    };
    return blocked;
}

SeccompProgram build_seccomp_filter(const std::vector<int>& blocked_syscalls) {
    SeccompProgram prog;
    uint32_t arch = host_audit_arch();
    if (arch == 0) {
        return prog;
    }

    // 1. Validate syscall architecture matches host ABI
    prog.instructions.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, arch))));
    prog.instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0));
    prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // 2. Load syscall number
    prog.instructions.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, nr))));

    // 3. Deny each blocked syscall with EPERM
    for (int nr : blocked_syscalls) {
        prog.instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(nr), 0, 1));
        prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & 0x0000FFFFU)));
    }

    // 4. Allow remaining syscalls
    prog.instructions.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    return prog;
}

void apply_default_seccomp_filter() {
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        throw std::system_error(errno, std::generic_category(), "prctl(PR_SET_NO_NEW_PRIVS)");
    }
    SeccompProgram prog = build_seccomp_filter(default_blocked_syscalls());
    if (prog.instructions.empty()) {
        return;
    }
    struct sock_fprog fprog{};
    fprog.len = static_cast<unsigned short>(prog.instructions.size());
    fprog.filter = prog.instructions.data();
    if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) != 0) {
        throw std::system_error(errno, std::generic_category(), "prctl(PR_SET_SECCOMP)");
    }
}

}  // namespace pieces
