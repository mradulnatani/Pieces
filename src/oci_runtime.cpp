#include "pieces/oci_runtime.hpp"

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <system_error>

#include "pieces/cgroup.hpp"
#include "pieces/filesystem.hpp"
#include "pieces/security.hpp"

namespace fs = std::filesystem;

namespace pieces {

namespace {

int ns_type_to_clone_flag(const std::string& type) {
    if (type == "pid") return CLONE_NEWPID;
    if (type == "network") return CLONE_NEWNET;
    if (type == "mount") return CLONE_NEWNS;
    if (type == "ipc") return CLONE_NEWIPC;
    if (type == "uts") return CLONE_NEWUTS;
    if (type == "user") return CLONE_NEWUSER;
    if (type == "cgroup") return CLONE_NEWCGROUP;
    return 0;
}

std::vector<OciHook> parse_hook_array(const JsonValue* arr_v) {
    std::vector<OciHook> hooks;
    if (!arr_v || !arr_v->is_array()) return hooks;
    for (const auto& item : arr_v->as_array()) {
        if (!item.is_object()) continue;
        OciHook hk;
        if (const auto* p = item.find("path"); p && p->is_string()) hk.path = p->as_string();
        if (hk.path.empty()) continue;
        if (const auto* args = item.find("args"); args && args->is_array()) {
            for (const auto& a : args->as_array()) {
                if (a.is_string()) hk.args.push_back(a.as_string());
            }
        }
        if (const auto* env = item.find("env"); env && env->is_array()) {
            for (const auto& e : env->as_array()) {
                if (e.is_string()) hk.env.push_back(e.as_string());
            }
        }
        if (const auto* t = item.find("timeout"); t && t->is_int()) {
            hk.timeout_sec = static_cast<int>(t->as_int());
        }
        hooks.push_back(std::move(hk));
    }
    return hooks;
}

std::vector<IdMapping> parse_id_mappings(const JsonValue* arr_v) {
    std::vector<IdMapping> out;
    if (!arr_v || !arr_v->is_array()) return out;
    for (const auto& item : arr_v->as_array()) {
        if (!item.is_object()) continue;
        IdMapping m;
        if (const auto* cid = item.find("containerID"); cid && cid->is_int()) m.container_id = static_cast<uint32_t>(cid->as_int());
        if (const auto* hid = item.find("hostID"); hid && hid->is_int()) m.host_id = static_cast<uint32_t>(hid->as_int());
        if (const auto* sz = item.find("size"); sz && sz->is_int()) m.size = static_cast<uint32_t>(sz->as_int());
        if (m.size > 0) out.push_back(m);
    }
    return out;
}

void write_state_file(const fs::path& state_dir, const JsonObject& state) {
    fs::create_directories(state_dir);
    fs::path p = state_dir / "state.json";
    fs::path tmp = p;
    tmp += ".tmp." + std::to_string(::getpid());
    {
        std::ofstream out(tmp);
        if (!out) throw std::runtime_error("Cannot write OCI state.json");
        out << JsonValue(state).dump(2) << "\n";
    }
    fs::rename(tmp, p);
}

JsonObject read_state_file(const fs::path& state_dir) {
    fs::path p = state_dir / "state.json";
    std::ifstream in(p);
    if (!in) throw std::runtime_error("OCI container state not found at " + p.string());
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    JsonValue v = JsonValue::parse(s);
    if (!v.is_object()) throw std::runtime_error("Corrupt OCI state.json");
    return v.as_object();
}

bool is_pid_alive(int pid) {
    if (pid <= 0) return false;
    if (::kill(pid, 0) == 0) return true;
    return errno == EPERM;
}

void run_oci_hooks(const std::vector<OciHook>& hooks, const JsonObject& state_json) {
    if (hooks.empty()) return;
    std::string state_payload = JsonValue(state_json).dump(0) + "\n";

    for (const auto& hk : hooks) {
        int in_pipe[2]{-1, -1};
        if (::pipe(in_pipe) != 0) throw std::system_error(errno, std::generic_category(), "pipe(hook)");

        pid_t child = ::fork();
        if (child < 0) {
            ::close(in_pipe[0]); ::close(in_pipe[1]);
            throw std::system_error(errno, std::generic_category(), "fork(hook)");
        }
        if (child == 0) {
            ::close(in_pipe[1]);
            ::dup2(in_pipe[0], STDIN_FILENO);
            ::close(in_pipe[0]);

            std::vector<std::string> args = hk.args.empty() ? std::vector<std::string>{hk.path} : hk.args;
            std::vector<char*> argv;
            for (auto& a : args) argv.push_back(a.data());
            argv.push_back(nullptr);

            if (!hk.env.empty()) {
                std::vector<char*> envp;
                for (auto& e : const_cast<std::vector<std::string>&>(hk.env)) envp.push_back(e.data());
                envp.push_back(nullptr);
                ::execvpe(hk.path.c_str(), argv.data(), envp.data());
            } else {
                ::execvp(hk.path.c_str(), argv.data());
            }
            ::_exit(127);
        }

        ::close(in_pipe[0]);
        [[maybe_unused]] ssize_t w = ::write(in_pipe[1], state_payload.data(), state_payload.size());
        ::close(in_pipe[1]);

        int st = 0;
        ::waitpid(child, &st, 0);
        int rc = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
        if (rc != 0) {
            throw std::runtime_error("OCI hook '" + hk.path + "' failed with exit code " + std::to_string(rc));
        }
    }
}

std::vector<VolumeMount> extract_bind_mounts_from_oci(const std::vector<OciMount>& mounts) {
    std::vector<VolumeMount> binds;
    for (const auto& m : mounts) {
        bool is_bind = (m.type == "bind");
        bool ro = false;
        for (const auto& opt : m.options) {
            if (opt == "bind" || opt == "rbind") is_bind = true;
            if (opt == "ro") ro = true;
        }
        if (is_bind && !m.source.empty() && !m.destination.empty()) {
            binds.push_back({m.source, m.destination, ro});
        }
    }
    return binds;
}

}  // namespace

std::string default_oci_state_root() {
    if (const char* env_dir = std::getenv("PIECES_STATE_DIR"); env_dir && *env_dir) {
        return std::string(env_dir);
    }
    if (::geteuid() == 0) {
        return "/run/pieces";
    }
    return ".pieces/oci-state";
}

OciSpec parse_oci_spec_json(const JsonValue& doc) {
    if (!doc.is_object()) {
        throw std::invalid_argument("OCI config.json root must be a JSON object");
    }
    OciSpec spec;
    if (const auto* v = doc.find("ociVersion"); v && v->is_string()) spec.oci_version = v->as_string();
    if (const auto* hn = doc.find("hostname"); hn && hn->is_string()) spec.hostname = hn->as_string();

    if (const auto* root = doc.find("root"); root && root->is_object()) {
        if (const auto* p = root->find("path"); p && p->is_string()) spec.root_path = p->as_string();
        if (const auto* ro = root->find("readonly"); ro && ro->is_bool()) {
            spec.root_readonly = std::get<bool>(ro->data);
        }
    }

    if (const auto* proc = doc.find("process"); proc && proc->is_object()) {
        if (const auto* args = proc->find("args"); args && args->is_array()) {
            for (const auto& a : args->as_array()) {
                if (a.is_string()) spec.args.push_back(a.as_string());
            }
        }
        if (const auto* env = proc->find("env"); env && env->is_array()) {
            for (const auto& e : env->as_array()) {
                if (e.is_string()) spec.env.push_back(e.as_string());
            }
        }
        if (const auto* cwd = proc->find("cwd"); cwd && cwd->is_string() && !cwd->as_string().empty()) {
            spec.cwd = cwd->as_string();
        }
        if (const auto* nnp = proc->find("noNewPrivileges"); nnp && nnp->is_bool()) {
            spec.no_new_privileges = std::get<bool>(nnp->data);
        }
        if (const auto* ap = proc->find("apparmorProfile"); ap && ap->is_string()) {
            spec.apparmor_profile = ap->as_string();
        }
        if (const auto* sl = proc->find("selinuxLabel"); sl && sl->is_string()) {
            spec.selinux_label = sl->as_string();
        }
        if (const auto* usr = proc->find("user"); usr && usr->is_object()) {
            if (const auto* u = usr->find("uid"); u && u->is_int()) spec.uid = static_cast<uid_t>(u->as_int());
            if (const auto* g = usr->find("gid"); g && g->is_int()) spec.gid = static_cast<gid_t>(g->as_int());
            if (const auto* ag = usr->find("additionalGids"); ag && ag->is_array()) {
                for (const auto& gitem : ag->as_array()) {
                    if (gitem.is_int()) spec.additional_gids.push_back(static_cast<gid_t>(gitem.as_int()));
                }
            }
        }
        if (const auto* caps = proc->find("capabilities"); caps && caps->is_object()) {
            std::set<cap_value_t> cap_set;
            for (const char* field : {"bounding", "effective", "permitted"}) {
                if (const auto* arr = caps->find(field); arr && arr->is_array()) {
                    for (const auto& cv : arr->as_array()) {
                        if (cv.is_string()) {
                            try {
                                cap_set.insert(parse_capability_name(cv.as_string()));
                            } catch (const std::exception&) {
                            }
                        }
                    }
                }
            }
            spec.capabilities = std::move(cap_set);
        }
    }

    if (const auto* mounts = doc.find("mounts"); mounts && mounts->is_array()) {
        for (const auto& m : mounts->as_array()) {
            if (!m.is_object()) continue;
            OciMount om;
            if (const auto* d = m.find("destination"); d && d->is_string()) om.destination = d->as_string();
            if (const auto* t = m.find("type"); t && t->is_string()) om.type = t->as_string();
            if (const auto* s = m.find("source"); s && s->is_string()) om.source = s->as_string();
            if (const auto* opts = m.find("options"); opts && opts->is_array()) {
                for (const auto& o : opts->as_array()) {
                    if (o.is_string()) om.options.push_back(o.as_string());
                }
            }
            spec.mounts.push_back(std::move(om));
        }
    }

    if (const auto* lnx = doc.find("linux"); lnx && lnx->is_object()) {
        if (const auto* nss = lnx->find("namespaces"); nss && nss->is_array()) {
            for (const auto& n : nss->as_array()) {
                if (!n.is_object()) continue;
                OciNamespace ons;
                if (const auto* t = n.find("type"); t && t->is_string()) ons.type = t->as_string();
                if (const auto* p = n.find("path"); p && p->is_string()) ons.path = p->as_string();
                if (!ons.type.empty()) spec.namespaces.push_back(std::move(ons));
            }
        }
        spec.uid_mappings = parse_id_mappings(lnx->find("uidMappings"));
        spec.gid_mappings = parse_id_mappings(lnx->find("gidMappings"));

        if (const auto* cg = lnx->find("cgroupsPath"); cg && cg->is_string()) {
            spec.cgroups_path = cg->as_string();
        }
        if (const auto* res = lnx->find("resources"); res && res->is_object()) {
            if (const auto* mem = res->find("memory"); mem && mem->is_object()) {
                if (const auto* lim = mem->find("limit"); lim && lim->is_int() && lim->as_int() > 0) {
                    spec.memory_limit_bytes = static_cast<uint64_t>(lim->as_int());
                }
            }
            if (const auto* cpu = res->find("cpu"); cpu && cpu->is_object()) {
                if (const auto* q = cpu->find("quota"); q && q->is_int() && q->as_int() > 0) {
                    spec.cpu_quota = q->as_int();
                }
                if (const auto* p = cpu->find("period"); p && p->is_int() && p->as_int() > 0) {
                    spec.cpu_period = p->as_int();
                }
            }
            if (const auto* pids = res->find("pids"); pids && pids->is_object()) {
                if (const auto* lim = pids->find("limit"); lim && lim->is_int() && lim->as_int() > 0) {
                    spec.pids_limit = static_cast<int>(lim->as_int());
                }
            }
        }
        if (const auto* sc = lnx->find("seccomp"); sc && sc->is_object()) {
            spec.seccomp = *sc;
        }
        if (const auto* mp = lnx->find("maskedPaths"); mp && mp->is_array()) {
            for (const auto& item : mp->as_array()) {
                if (item.is_string()) spec.masked_paths.push_back(item.as_string());
            }
        }
        if (const auto* rp = lnx->find("readonlyPaths"); rp && rp->is_array()) {
            for (const auto& item : rp->as_array()) {
                if (item.is_string()) spec.readonly_paths.push_back(item.as_string());
            }
        }
    }

    if (const auto* ann = doc.find("annotations"); ann && ann->is_object()) {
        for (const auto& [k, v] : ann->as_object()) {
            if (v.is_string()) spec.annotations[k] = v.as_string();
        }
    }

    if (const auto* hooks = doc.find("hooks"); hooks && hooks->is_object()) {
        spec.hooks.prestart = parse_hook_array(hooks->find("prestart"));
        spec.hooks.create_runtime = parse_hook_array(hooks->find("createRuntime"));
        spec.hooks.create_container = parse_hook_array(hooks->find("createContainer"));
        spec.hooks.start_container = parse_hook_array(hooks->find("startContainer"));
        spec.hooks.poststart = parse_hook_array(hooks->find("poststart"));
        spec.hooks.poststop = parse_hook_array(hooks->find("poststop"));
    }

    if (spec.args.empty()) {
        spec.args = {"/bin/sh"};
    }
    return spec;
}

OciSpec parse_oci_spec_file(const std::string& config_path) {
    std::ifstream in(config_path);
    if (!in) throw std::runtime_error("OCI config.json not found at '" + config_path + "'");
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return parse_oci_spec_json(JsonValue::parse(content));
}

JsonObject generate_default_oci_spec_json(bool rootless) {
    JsonArray nss = {
        JsonObject{{"type", "pid"}},
        JsonObject{{"type", "network"}},
        JsonObject{{"type", "ipc"}},
        JsonObject{{"type", "uts"}},
        JsonObject{{"type", "mount"}},
    };
    if (rootless) {
        nss.emplace_back(JsonObject{{"type", "user"}});
    }

    JsonObject linux_obj;
    linux_obj["namespaces"] = std::move(nss);
    linux_obj["maskedPaths"] = JsonArray{"/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"};
    linux_obj["readonlyPaths"] = JsonArray{"/proc/sys", "/proc/irq"};

    JsonObject root_obj;
    root_obj["path"] = "rootfs";
    root_obj["readonly"] = false;

    JsonObject proc_obj;
    proc_obj["terminal"] = true;
    proc_obj["user"] = JsonObject{{"uid", static_cast<int64_t>(0)}, {"gid", static_cast<int64_t>(0)}};
    proc_obj["args"] = JsonArray{"/bin/sh"};
    proc_obj["env"] = JsonArray{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm"};
    proc_obj["cwd"] = "/";
    proc_obj["noNewPrivileges"] = true;

    JsonObject spec;
    spec["ociVersion"] = "1.0.2";
    spec["hostname"] = "pieces";
    spec["root"] = std::move(root_obj);
    spec["process"] = std::move(proc_obj);
    spec["linux"] = std::move(linux_obj);
    return spec;
}

int parse_signal_name(const std::string& sig) {
    if (sig.empty()) return SIGTERM;
    if (std::all_of(sig.begin(), sig.end(), [](unsigned char c) { return std::isdigit(c); })) {
        return std::stoi(sig);
    }
    std::string up = sig;
    for (char& c : up) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (up.rfind("SIG", 0) == 0) up = up.substr(3);
    if (up == "TERM") return SIGTERM;
    if (up == "KILL") return SIGKILL;
    if (up == "INT") return SIGINT;
    if (up == "HUP") return SIGHUP;
    if (up == "USR1") return SIGUSR1;
    if (up == "USR2") return SIGUSR2;
    if (up == "QUIT") return SIGQUIT;
    if (up == "STOP") return SIGSTOP;
    if (up == "CONT") return SIGCONT;
    throw std::invalid_argument("Unsupported signal: '" + sig + "'");
}

int oci_create(
    const std::string& container_id,
    const std::string& bundle_dir,
    const std::string& pid_file,
    const std::string& state_root) {
    (void)validate_name(container_id, "container");
    std::string root = state_root.empty() ? default_oci_state_root() : state_root;
    fs::path bundle_abs = fs::weakly_canonical(fs::absolute(bundle_dir));
    OciSpec spec = parse_oci_spec_file((bundle_abs / "config.json").string());

    fs::path state_dir = fs::path(root) / container_id;
    if (fs::exists(state_dir)) {
        throw std::runtime_error("OCI container '" + container_id + "' already exists");
    }
    fs::create_directories(state_dir);
    fs::path fifo_path = state_dir / "exec.fifo";
    if (::mkfifo(fifo_path.c_str(), 0600) != 0) {
        throw std::system_error(errno, std::generic_category(), "mkfifo(exec.fifo)");
    }

    fs::path rootfs_path = fs::path(spec.root_path).is_absolute()
                               ? fs::path(spec.root_path)
                               : (bundle_abs / spec.root_path);
    auto bind_mounts = extract_bind_mounts_from_oci(spec.mounts);

    bool has_userns = false;
    int unshare_flags = 0;
    std::vector<std::string> join_paths;
    for (const auto& ns : spec.namespaces) {
        if (ns.type == "user") has_userns = true;
        if (!ns.path.empty()) {
            join_paths.push_back(ns.path);
        } else {
            unshare_flags |= ns_type_to_clone_flag(ns.type);
        }
    }
    bool rootless = has_userns || (::geteuid() != 0);
    if (rootless) unshare_flags |= CLONE_NEWUSER;

    std::optional<std::string> mem_str;
    if (spec.memory_limit_bytes.has_value()) {
        mem_str = std::to_string(*spec.memory_limit_bytes);
    }
    std::optional<double> cpu_cores;
    if (spec.cpu_quota.has_value() && spec.cpu_period > 0) {
        cpu_cores = static_cast<double>(*spec.cpu_quota) / static_cast<double>(spec.cpu_period);
    }
    CgroupManager cg(container_id, mem_str, cpu_cores, spec.pids_limit, CGROUP_ROOT, spec.cgroups_path);

    std::optional<SeccompProgram> seccomp_prog;
    if (spec.seccomp.has_value()) {
        seccomp_prog = build_seccomp_from_oci_json(*spec.seccomp);
    }

    std::set<cap_value_t> caps = spec.capabilities.has_value()
                                     ? *spec.capabilities
                                     : default_container_capabilities();

    uid_t host_uid = ::getuid();
    gid_t host_gid = ::getgid();
    int ready_pipe[2]{-1, -1};
    int userns_pipe[2]{-1, -1};
    if (::pipe(ready_pipe) != 0 || ::pipe(userns_pipe) != 0) {
        fs::remove_all(state_dir);
        throw std::system_error(errno, std::generic_category(), "pipe(oci_create)");
    }

    pid_t pid1 = ::fork();
    if (pid1 < 0) {
        ::close(ready_pipe[0]); ::close(ready_pipe[1]);
        ::close(userns_pipe[0]); ::close(userns_pipe[1]);
        fs::remove_all(state_dir);
        throw std::system_error(errno, std::generic_category(), "fork(oci_create)");
    }

    if (pid1 == 0) {
        ::close(ready_pipe[0]);
        ::close(userns_pipe[1]);
        ::setsid();
        try {
            // Join shared Pod Sandbox namespaces (e.g. network, ipc) in user->others order
            for (const auto& jp : join_paths) {
                join_namespace_path(jp);
            }
            if (unshare_flags != 0) {
                unshare_namespaces(unshare_flags);
            }

            std::string p1_msg = std::to_string(::getpid()) + "\n";
            [[maybe_unused]] ssize_t pw = ::write(ready_pipe[1], p1_msg.data(), p1_msg.size());

            char ubuf = 0;
            [[maybe_unused]] ssize_t ur = ::read(userns_pipe[0], &ubuf, 1);
            ::close(userns_pipe[0]);

            pid_t pid2 = ::fork();
            if (pid2 < 0) ::_exit(1);

            if (pid2 == 0) {
                try {
                    checked_sethostname(spec.hostname);
                    setup_container_mounts(
                        rootfs_path.string(),
                        bind_mounts,
                        rootless,
                        true,
                        spec.root_readonly,
                        spec.masked_paths,
                        spec.readonly_paths);

                    if (!spec.cwd.empty() && spec.cwd != "/") {
                        fs::create_directories(spec.cwd);
                        if (::chdir(spec.cwd.c_str()) != 0) ::_exit(1);
                    }

                    if (spec.apparmor_profile.has_value()) apply_apparmor_profile(*spec.apparmor_profile);
                    if (spec.selinux_label.has_value()) apply_selinux_label(*spec.selinux_label);

                    drop_capabilities_to_set(caps);
                    if (seccomp_prog.has_value()) {
                        apply_seccomp_program(*seccomp_prog);
                    } else {
                        apply_default_seccomp_filter();
                    }

                    std::string p2_msg = std::to_string(::getpid()) + "\n";
                    [[maybe_unused]] ssize_t w2 = ::write(ready_pipe[1], p2_msg.data(), p2_msg.size());
                    ::close(ready_pipe[1]);

                    // Block on exec.fifo until `pieces start` writes 1 byte
                    int fifo_fd = ::open(fifo_path.c_str(), O_RDONLY);
                    if (fifo_fd >= 0) {
                        char go = 0;
                        [[maybe_unused]] ssize_t r = ::read(fifo_fd, &go, 1);
                        ::close(fifo_fd);
                    }

                    apply_process_user(spec.uid, spec.gid, spec.additional_gids, false);

                    std::vector<char*> argv_ptrs;
                    for (auto& a : spec.args) argv_ptrs.push_back(a.data());
                    argv_ptrs.push_back(nullptr);

                    std::vector<char*> env_ptrs;
                    for (auto& e : spec.env) env_ptrs.push_back(e.data());
                    env_ptrs.push_back(nullptr);

                    ::execvpe(argv_ptrs[0], argv_ptrs.data(), env_ptrs.data());
                    ::_exit(127);
                } catch (const std::exception& exc) {
                    std::cerr << "OCI CREATE ERROR: " << exc.what() << "\n";
                    ::close(ready_pipe[1]);
                    ::_exit(1);
                }
            } else {
                ::close(ready_pipe[1]);
                int st2 = 0;
                ::waitpid(pid2, &st2, 0);
                ::_exit(WIFEXITED(st2) ? WEXITSTATUS(st2) : 1);
            }
        } catch (const std::exception& exc) {
            std::cerr << "OCI CREATE ERROR: " << exc.what() << "\n";
            ::close(ready_pipe[1]);
            ::close(userns_pipe[0]);
            ::_exit(1);
        }
    }

    ::close(ready_pipe[1]);
    ::close(userns_pipe[0]);

    auto read_line_fd = [](int fd) -> std::string {
        std::string s;
        char c = 0;
        while (::read(fd, &c, 1) == 1) {
            if (c == '\n') break;
            if (c != '\r') s.push_back(c);
        }
        return s;
    };

    std::string p1_s = read_line_fd(ready_pipe[0]);
    if (rootless && !p1_s.empty() && std::all_of(p1_s.begin(), p1_s.end(), ::isdigit)) {
        setup_rootless_user_namespace(
            static_cast<pid_t>(std::stoi(p1_s)),
            host_uid,
            host_gid,
            spec.uid_mappings,
            spec.gid_mappings);
    }
    [[maybe_unused]] ssize_t uw = ::write(userns_pipe[1], "1", 1);
    ::close(userns_pipe[1]);

    std::string p2_s = read_line_fd(ready_pipe[0]);
    ::close(ready_pipe[0]);

    if (p2_s.empty() || !std::all_of(p2_s.begin(), p2_s.end(), ::isdigit)) {
        fs::remove_all(state_dir);
        throw std::runtime_error("Failed to create OCI container process");
    }

    int container_pid = std::stoi(p2_s);
    cg.setup(container_pid);

    if (!pid_file.empty()) {
        std::ofstream pf(pid_file);
        if (!pf) throw std::runtime_error("Cannot write pid-file: " + pid_file);
        pf << container_pid;
    }

    JsonObject ann_obj;
    for (const auto& [k, v] : spec.annotations) ann_obj[k] = v;

    JsonObject state_obj;
    state_obj["ociVersion"] = spec.oci_version;
    state_obj["id"] = container_id;
    state_obj["status"] = "created";
    state_obj["pid"] = static_cast<int64_t>(container_pid);
    state_obj["bundle"] = bundle_abs.string();
    state_obj["cgroupsPath"] = cg.group_dir();
    state_obj["annotations"] = std::move(ann_obj);
    write_state_file(state_dir, state_obj);

    run_oci_hooks(spec.hooks.create_runtime, state_obj);
    run_oci_hooks(spec.hooks.create_container, state_obj);
    return 0;
}

int oci_start(const std::string& container_id, const std::string& state_root) {
    std::string root = state_root.empty() ? default_oci_state_root() : state_root;
    fs::path state_dir = fs::path(root) / container_id;
    JsonObject state_obj = read_state_file(state_dir);
    std::string bundle = state_obj.at("bundle").as_string();
    OciSpec spec = parse_oci_spec_file((fs::path(bundle) / "config.json").string());

    run_oci_hooks(spec.hooks.prestart, state_obj);

    fs::path fifo_path = state_dir / "exec.fifo";
    int fifo_fd = ::open(fifo_path.c_str(), O_WRONLY);
    if (fifo_fd < 0) {
        throw std::system_error(errno, std::generic_category(), "open(exec.fifo)");
    }
    [[maybe_unused]] ssize_t w = ::write(fifo_fd, "1", 1);
    ::close(fifo_fd);
    fs::remove(fifo_path);

    state_obj["status"] = "running";
    write_state_file(state_dir, state_obj);

    run_oci_hooks(spec.hooks.poststart, state_obj);
    return 0;
}

JsonObject oci_get_state(const std::string& container_id, const std::string& state_root) {
    std::string root = state_root.empty() ? default_oci_state_root() : state_root;
    fs::path state_dir = fs::path(root) / container_id;
    JsonObject state_obj = read_state_file(state_dir);

    auto pid_it = state_obj.find("pid");
    auto st_it = state_obj.find("status");
    if (pid_it != state_obj.end() && pid_it->second.is_int() &&
        st_it != state_obj.end() && st_it->second.is_string()) {
        std::string cur_status = st_it->second.as_string();
        int pid = static_cast<int>(pid_it->second.as_int());
        if ((cur_status == "created" || cur_status == "running") && !is_pid_alive(pid)) {
            state_obj["status"] = "stopped";
            state_obj["pid"] = static_cast<int64_t>(0);
            write_state_file(state_dir, state_obj);
        }
    }
    return state_obj;
}

int oci_print_state(const std::string& container_id, const std::string& state_root) {
    JsonObject state_obj = oci_get_state(container_id, state_root);
    // Keep standard OCI State keys in output
    JsonObject out;
    for (const char* key : {"ociVersion", "id", "status", "pid", "bundle", "annotations"}) {
        if (auto it = state_obj.find(key); it != state_obj.end()) {
            out[key] = it->second;
        }
    }
    std::cout << JsonValue(out).dump(2) << "\n";
    return 0;
}

int oci_kill(
    const std::string& container_id,
    const std::string& signal_str,
    const std::string& state_root) {
    JsonObject state_obj = oci_get_state(container_id, state_root);
    int pid = static_cast<int>(state_obj.at("pid").as_int());
    if (pid <= 0 || !is_pid_alive(pid)) {
        throw std::runtime_error("Container '" + container_id + "' is not running");
    }
    int sig = parse_signal_name(signal_str);
    if (::kill(pid, sig) != 0) {
        throw std::system_error(errno, std::generic_category(), "kill");
    }
    return 0;
}

int oci_delete(
    const std::string& container_id,
    bool force,
    const std::string& state_root) {
    std::string root = state_root.empty() ? default_oci_state_root() : state_root;
    fs::path state_dir = fs::path(root) / container_id;
    JsonObject state_obj = oci_get_state(container_id, state_root);
    std::string status = state_obj.at("status").as_string();
    int pid = static_cast<int>(state_obj.at("pid").as_int());

    if (status != "stopped" && pid > 0 && is_pid_alive(pid)) {
        if (!force) {
            throw std::runtime_error("Cannot delete non-stopped container '" + container_id + "' without --force");
        }
        ::kill(pid, SIGKILL);
    }

    if (auto cg_it = state_obj.find("cgroupsPath"); cg_it != state_obj.end() && cg_it->second.is_string()) {
        ::rmdir(cg_it->second.as_string().c_str());
    }

    if (auto b_it = state_obj.find("bundle"); b_it != state_obj.end() && b_it->second.is_string()) {
        try {
            OciSpec spec = parse_oci_spec_file((fs::path(b_it->second.as_string()) / "config.json").string());
            run_oci_hooks(spec.hooks.poststop, state_obj);
        } catch (const std::exception&) {
        }
    }

    fs::remove_all(state_dir);
    return 0;
}

}  // namespace pieces
