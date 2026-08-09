use std::collections::BTreeMap;
use std::io;
use waitson_schema::*;

pub struct StatLine {
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub ticks: u64,
}

pub fn parse_stat(s: &str) -> Option<StatLine> {
    // comm may contain spaces and parens: it spans the first '(' to the last ')'.
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_string();
    let fields: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
    let state = fields.first()?.chars().next()?;
    let ppid = fields.get(1)?.parse().ok()?;
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(StatLine { comm, state, ppid, ticks: utime + stime })
}

pub fn parse_syscall_line(s: &str) -> Option<(i64, [u64; 6])> {
    let mut it = s.split_whitespace();
    let nr: i64 = it.next()?.parse().ok()?;
    let mut args = [0u64; 6];
    for a in args.iter_mut() {
        let tok = it.next()?;
        *a = u64::from_str_radix(tok.trim_start_matches("0x"), 16).ok()?;
    }
    Some((nr, args))
}

pub fn syscall_name(nr: i64) -> Option<&'static str> {
    #[cfg(target_arch = "x86_64")]
    let table: &[(i64, &str)] = &[
        (0, "read"),
        (1, "write"),
        (7, "poll"),
        (23, "select"),
        (35, "nanosleep"),
        (43, "accept"),
        (45, "recvfrom"),
        (47, "recvmsg"),
        (61, "wait4"),
        (73, "flock"),
        (202, "futex"),
        (219, "restart_syscall"),
        (230, "clock_nanosleep"),
        (232, "epoll_wait"),
        (270, "pselect6"),
        (271, "ppoll"),
        (281, "epoll_pwait"),
        (288, "accept4"),
    ];
    #[cfg(target_arch = "aarch64")]
    let table: &[(i64, &str)] = &[
        (22, "epoll_pwait"),
        (32, "flock"),
        (63, "read"),
        (64, "write"),
        (72, "pselect6"),
        (73, "ppoll"),
        (98, "futex"),
        (101, "nanosleep"),
        (115, "clock_nanosleep"),
        (128, "restart_syscall"),
        (202, "accept"),
        (207, "recvfrom"),
        (212, "recvmsg"),
        (242, "accept4"),
        (260, "wait4"),
    ];
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let table: &[(i64, &str)] = &[];
    table.iter().find(|(n, _)| *n == nr).map(|(_, s)| *s)
}

pub fn decode_addr(s: &str) -> String {
    let Some((host, port)) = s.split_once(':') else {
        return s.to_string();
    };
    let port = u16::from_str_radix(port, 16).unwrap_or(0);
    if host.len() == 8 {
        // /proc/net stores IPv4 as the 32-bit word in host (little-endian) order.
        let v = u32::from_str_radix(host, 16).unwrap_or(0);
        let b = v.to_le_bytes();
        format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], port)
    } else {
        format!("[{host}]:{port}")
    }
}

fn tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "0A" => "LISTEN",
        _ => "OTHER",
    }
}

pub fn parse_net(proto: &str, body: &str, out: &mut BTreeMap<u64, SocketConn>) {
    for line in body.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let Ok(inode) = f[9].parse::<u64>() else { continue };
        if inode == 0 {
            continue;
        }
        let (tx, rx) = f[4]
            .split_once(':')
            .map(|(t, r)| {
                (
                    u64::from_str_radix(t, 16).unwrap_or(0),
                    u64::from_str_radix(r, 16).unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));
        out.entry(inode).or_insert_with(|| SocketConn {
            proto: proto.to_string(),
            local: decode_addr(f[1]),
            remote: decode_addr(f[2]),
            state: tcp_state(f[3]).to_string(),
            tx_queue: tx,
            rx_queue: rx,
        });
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::thread;
    use std::time::Duration;

    fn read(path: String) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn thread_ticks(pid: i32) -> BTreeMap<i32, u64> {
        let mut out = BTreeMap::new();
        let Ok(rd) = fs::read_dir(format!("/proc/{pid}/task")) else {
            return out;
        };
        for e in rd.flatten() {
            let Ok(tid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
            if let Some(st) = read(format!("/proc/{pid}/task/{tid}/stat")).as_deref().and_then(parse_stat) {
                out.insert(tid, st.ticks);
            }
        }
        out
    }

    // glibc pthread_mutex_t: __lock (the futex word) at +0, __owner tid at
    // +8. Garbage reads fail the caller's owner-is-a-thread check.
    fn read_futex_owner(pid: i32, uaddr: u64) -> Option<i32> {
        let mut buf = [0u8; 4];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: 4,
        };
        let remote = libc::iovec {
            iov_base: (uaddr.checked_add(8)?) as *mut libc::c_void,
            iov_len: 4,
        };
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n != 4 {
            return None;
        }
        let owner = i32::from_ne_bytes(buf);
        (owner > 0).then_some(owner)
    }

    fn fdinfo_flags(pid: i32, fd: i32) -> u32 {
        read(format!("/proc/{pid}/fdinfo/{fd}"))
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("flags:").map(|v| v.trim().to_string()))
            })
            .and_then(|v| u32::from_str_radix(&v, 8).ok())
            .unwrap_or(0)
    }

    fn epoll_registered(pid: i32, fd: i32) -> usize {
        read(format!("/proc/{pid}/fdinfo/{fd}"))
            .map(|s| s.lines().filter(|l| l.trim_start().starts_with("tfd:")).count())
            .unwrap_or(0)
    }

    fn collect_fds(pid: i32) -> Vec<FdEntry> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            return out;
        };
        for e in rd.flatten() {
            let Ok(fd) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
            let Ok(target) = fs::read_link(e.path()) else { continue };
            let t = target.to_string_lossy().to_string();
            let kind = if let Some(i) = t.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                FdKind::Socket { inode: i.parse().unwrap_or(0) }
            } else if let Some(i) = t.strip_prefix("pipe:[").and_then(|x| x.strip_suffix(']')) {
                FdKind::Pipe { inode: i.parse().unwrap_or(0) }
            } else if t.contains("eventpoll") {
                FdKind::Epoll { registered: epoll_registered(pid, fd) }
            } else if t.starts_with('/') {
                FdKind::File { path: t }
            } else {
                FdKind::Other { desc: t }
            };
            out.push(FdEntry { fd, kind, flags: fdinfo_flags(pid, fd) });
        }
        out.sort_by_key(|e| e.fd);
        out
    }

    // The target's own /proc net tables, so a container netns resolves.
    fn collect_sockets(pid: i32) -> BTreeMap<u64, SocketConn> {
        let mut out = BTreeMap::new();
        for (proto, file) in [("tcp", "tcp"), ("tcp", "tcp6"), ("udp", "udp"), ("udp", "udp6")] {
            let body = read(format!("/proc/{pid}/net/{file}"))
                .or_else(|| read(format!("/proc/net/{file}")));
            if let Some(body) = body {
                parse_net(proto, &body, &mut out);
            }
        }
        out
    }

    fn collect_children(pid: i32) -> Vec<ChildSnap> {
        let mut out = Vec::new();
        let Some(kids) = read(format!("/proc/{pid}/task/{pid}/children")) else {
            return out;
        };
        for tok in kids.split_whitespace() {
            let Ok(cpid) = tok.parse::<i32>() else { continue };
            if let Some(st) = read(format!("/proc/{cpid}/stat")).as_deref().and_then(parse_stat) {
                out.push(ChildSnap {
                    pid: cpid,
                    comm: st.comm,
                    state: TaskState::from_code(st.state),
                });
            }
        }
        out
    }

    fn collect_pipe_peers(inodes: &[u64], exclude: i32) -> BTreeMap<u64, Vec<PipePeer>> {
        let mut out: BTreeMap<u64, Vec<PipePeer>> = BTreeMap::new();
        if inodes.is_empty() {
            return out;
        }
        let Ok(rd) = fs::read_dir("/proc") else {
            return out;
        };
        for e in rd.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
            if pid == exclude {
                continue;
            }
            let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
            for f in fds.flatten() {
                let Ok(target) = fs::read_link(f.path()) else { continue };
                let t = target.to_string_lossy();
                let Some(inode) = t
                    .strip_prefix("pipe:[")
                    .and_then(|x| x.strip_suffix(']'))
                    .and_then(|x| x.parse::<u64>().ok())
                else {
                    continue;
                };
                if !inodes.contains(&inode) {
                    continue;
                }
                let Ok(fd) = f.file_name().to_string_lossy().parse::<i32>() else { continue };
                let Some(st) = read(format!("/proc/{pid}/stat")).as_deref().and_then(parse_stat) else { continue };
                let wchan = read(format!("/proc/{pid}/wchan")).unwrap_or_default();
                let reads = fdinfo_flags(pid, fd) & (libc::O_ACCMODE as u32) == libc::O_RDONLY as u32;
                out.entry(inode).or_default().push(PipePeer {
                    pid,
                    comm: st.comm,
                    state: TaskState::from_code(st.state),
                    wchan,
                    reads,
                });
            }
        }
        out
    }

    // Raw GETREGSET NT_PRSTATUS array of a blocked thread: briefly seize and
    // interrupt it (py-spy's pattern), read, detach. The waitpid is bounded
    // because a blocking wait never returns on a D-state thread.
    pub fn thread_regfile(tid: i32) -> Option<Vec<u64>> {
        const PTRACE_SEIZE: u32 = 0x4206;
        const PTRACE_INTERRUPT: u32 = 0x4207;
        const PTRACE_DETACH: u32 = 17;
        const PTRACE_GETREGSET: u32 = 0x4204;
        const NT_PRSTATUS: u32 = 1;

        unsafe {
            if libc::ptrace(PTRACE_SEIZE as _, tid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) != 0 {
                return None;
            }
            libc::ptrace(PTRACE_INTERRUPT as _, tid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
            let mut status = 0;
            let mut stopped = false;
            for _ in 0..50 {
                if libc::waitpid(tid, &mut status, libc::WNOHANG) == tid {
                    stopped = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !stopped {
                libc::ptrace(PTRACE_DETACH as _, tid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
                return None;
            }
            let mut regs = vec![0u64; 34];
            let mut iov = libc::iovec {
                iov_base: regs.as_mut_ptr().cast(),
                iov_len: std::mem::size_of::<u64>() * regs.len(),
            };
            let rc = libc::ptrace(PTRACE_GETREGSET as _, tid, NT_PRSTATUS as *mut libc::c_void, &mut iov as *mut _ as *mut libc::c_void);
            libc::ptrace(PTRACE_DETACH as _, tid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
            (rc == 0).then_some(regs)
        }
    }

    // pc, sp, fp, lr from the raw register file, for the frame-pointer walk.
    pub fn thread_registers(tid: i32) -> Option<(u64, u64, u64, u64)> {
        let regs = thread_regfile(tid)?;
        #[cfg(target_arch = "x86_64")]
        let out = (regs[16], regs[19], regs[4], 0);
        #[cfg(target_arch = "aarch64")]
        let out = (regs[32], regs[31], regs[29], regs[30]);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let out = (0, 0, 0, 0);
        Some(out)
    }

    pub fn read_mem(pid: i32, addr: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 || len > 1 << 20 {
            return None;
        }
        let mut buf = vec![0u8; len];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: len,
        };
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        (n == len as isize).then_some(buf)
    }

    pub fn socket_inode_owner(inode: u64, exclude: i32) -> Option<(i32, String)> {
        let rd = fs::read_dir("/proc").ok()?;
        for e in rd.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
            if pid == exclude {
                continue;
            }
            let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
            for f in fds.flatten() {
                let Ok(target) = fs::read_link(f.path()) else { continue };
                if target.to_string_lossy() == format!("socket:[{inode}]") {
                    let comm = read(format!("/proc/{pid}/stat"))
                        .as_deref()
                        .and_then(parse_stat)
                        .map(|s| s.comm)
                        .unwrap_or_default();
                    return Some((pid, comm));
                }
            }
        }
        None
    }

    // In /proc/locks a "->" row is a waiter; the plain row on the same
    // dev:inode is the holder. Path recovered from the holder's fd table.
    fn collect_lock_holders(pid: i32) -> Vec<LockHolder> {
        let Some(body) = read("/proc/locks".to_string()) else {
            return Vec::new();
        };
        let mut waiting_on: Vec<&str> = Vec::new();
        for line in body.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 7 && f[1] == "->" && f[5] == pid.to_string() {
                waiting_on.push(f[6]);
            }
        }
        let mut out = Vec::new();
        for line in body.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 6 && f[1] != "->" && waiting_on.contains(&f[5]) {
                let Ok(hpid) = f[4].parse::<i32>() else { continue };
                if hpid == pid {
                    continue;
                }
                let Some(st) = read(format!("/proc/{hpid}/stat")).as_deref().and_then(parse_stat) else { continue };
                let inode: u64 = f[5].rsplit(':').next().and_then(|s| s.parse().ok()).unwrap_or(0);
                out.push(LockHolder {
                    pid: hpid,
                    comm: st.comm,
                    state: TaskState::from_code(st.state),
                    path: path_of_inode(hpid, inode),
                });
            }
        }
        out
    }

    fn path_of_inode(pid: i32, inode: u64) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let rd = fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
        for e in rd.flatten() {
            let Ok(target) = fs::read_link(e.path()) else { continue };
            if !target.to_string_lossy().starts_with('/') {
                continue;
            }
            if fs::metadata(e.path()).is_ok_and(|m| m.ino() == inode) {
                return Some(target.to_string_lossy().into_owned());
            }
        }
        None
    }

    pub fn collect(pid: i32, window_ms: u64) -> io::Result<Snapshot> {
        let stat = read(format!("/proc/{pid}/stat"))
            .as_deref()
            .and_then(parse_stat)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no such process: {pid}")))?;

        let before = thread_ticks(pid);
        let started = std::time::Instant::now();
        thread::sleep(Duration::from_millis(window_ms));
        // Real elapsed time, or tick quantization reads over 100% busy.
        let elapsed_ms = started.elapsed().as_millis().max(1) as u64;

        let mut threads = Vec::new();
        let tids: Vec<i32> = {
            let Ok(rd) = fs::read_dir(format!("/proc/{pid}/task")) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("process exited: {pid}")));
            };
            let mut v: Vec<i32> = rd
                .flatten()
                .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
                .collect();
            v.sort_unstable();
            v
        };
        for tid in &tids {
            let tid = *tid;
            let Some(st) = read(format!("/proc/{pid}/task/{tid}/stat")).as_deref().and_then(parse_stat) else { continue };
            let wchan = read(format!("/proc/{pid}/task/{tid}/wchan")).unwrap_or_default();
            let syscall = read(format!("/proc/{pid}/task/{tid}/syscall"))
                .as_deref()
                .and_then(parse_syscall_line)
                .map(|(nr, args)| SyscallSnap {
                    nr,
                    name: syscall_name(nr).map(str::to_string),
                    args,
                });
            let futexish = wchan.contains("futex")
                || syscall.as_ref().and_then(|s| s.name.as_deref()) == Some("futex");
            let futex_owner = match (&syscall, futexish) {
                (Some(sc), true) if sc.args[0] != 0 => read_futex_owner(pid, sc.args[0]),
                _ => None,
            };
            threads.push(ThreadSnap {
                tid,
                comm: st.comm,
                state: TaskState::from_code(st.state),
                wchan,
                syscall,
                cpu_ticks: st.ticks,
                cpu_delta: st.ticks.saturating_sub(before.get(&tid).copied().unwrap_or(st.ticks)),
                futex_owner,
            });
        }
        for t in &mut threads {
            if let Some(owner) = t.futex_owner {
                if !tids.contains(&owner) {
                    t.futex_owner = None;
                }
            }
        }

        let fds = collect_fds(pid);
        let pipe_inodes: Vec<u64> = fds
            .iter()
            .filter_map(|e| match e.kind {
                FdKind::Pipe { inode } => Some(inode),
                _ => None,
            })
            .collect();

        Ok(Snapshot {
            pid,
            comm: stat.comm,
            cmdline: read(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .replace('\0', " ")
                .trim()
                .to_string(),
            window_ms: elapsed_ms,
            threads,
            fds,
            sockets: collect_sockets(pid),
            pipe_peers: collect_pipe_peers(&pipe_inodes, pid),
            children: collect_children(pid),
            lock_holders: collect_lock_holders(pid),
        })
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
    use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
    use libproc::libproc::proc_pid::{listpidinfo, name, pidinfo, ListThreads};
    use libproc::libproc::task_info::TaskAllInfo;
    use libproc::libproc::thread_info::ThreadInfo;
    use std::thread;
    use std::time::Duration;

    // libproc gives a same-user caller thread states, cpu, and sockets;
    // wait causes need task_for_pid (root).
    fn state_of(run_state: i32) -> TaskState {
        match run_state {
            1 => TaskState::Running,
            2 => TaskState::Stopped,
            3 => TaskState::Sleeping,
            4 => TaskState::DiskSleep,
            5 => TaskState::Dead,
            other => TaskState::Other(char::from_digit(other as u32 % 10, 10).unwrap_or('?')),
        }
    }

    fn thread_ticks(pid: i32) -> Vec<(u64, u64)> {
        let Ok(info) = pidinfo::<TaskAllInfo>(pid, 0) else {
            return Vec::new();
        };
        let Ok(tids) = listpidinfo::<ListThreads>(pid, info.ptinfo.pti_threadnum as usize) else {
            return Vec::new();
        };
        tids.iter()
            .filter_map(|tid| {
                pidinfo::<ThreadInfo>(pid, *tid)
                    .ok()
                    .map(|t| (*tid, (t.pth_user_time + t.pth_system_time) / 10_000_000))
            })
            .collect()
    }

    fn v4addr(raw: u32, port: i32) -> String {
        let b = raw.to_ne_bytes();
        format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], port)
    }

    fn tcp_state(code: i32) -> &'static str {
        match code {
            0 => "CLOSED",
            1 => "LISTEN",
            2 => "SYN_SENT",
            4 => "ESTABLISHED",
            _ => "OTHER",
        }
    }

    fn collect_sockets(pid: i32, fds: &mut Vec<FdEntry>, sockets: &mut BTreeMap<u64, SocketConn>) {
        let Ok(info) = pidinfo::<TaskAllInfo>(pid, 0) else { return };
        let Ok(list) = listpidinfo::<ListFDs>(pid, info.pbsd.pbi_nfiles as usize) else { return };
        for fd in list {
            let kind = match fd.proc_fdtype.into() {
                ProcFDType::Socket => {
                    let Ok(sock) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) else {
                        fds.push(FdEntry { fd: fd.proc_fd, kind: FdKind::Other { desc: "socket".into() }, flags: 0 });
                        continue;
                    };
                    let si = sock.psi;
                    let key = fd.proc_fd as u64;
                    match si.soi_kind.into() {
                        SocketInfoKind::Tcp => {
                            let tcp = unsafe { si.soi_proto.pri_tcp };
                            let ini = tcp.tcpsi_ini;
                            let (l, r) = unsafe {
                                (
                                    v4addr(ini.insi_laddr.ina_46.i46a_addr4.s_addr, u16::from_be(ini.insi_lport as u16) as i32),
                                    v4addr(ini.insi_faddr.ina_46.i46a_addr4.s_addr, u16::from_be(ini.insi_fport as u16) as i32),
                                )
                            };
                            sockets.insert(key, SocketConn {
                                proto: "tcp".into(),
                                local: l,
                                remote: r,
                                state: tcp_state(tcp.tcpsi_state).to_string(),
                                tx_queue: si.soi_snd.sbi_cc as u64,
                                rx_queue: si.soi_rcv.sbi_cc as u64,
                            });
                            FdKind::Socket { inode: key }
                        }
                        _ => FdKind::Other { desc: "socket".into() },
                    }
                }
                ProcFDType::Pipe => FdKind::Other { desc: "pipe".into() },
                _ => FdKind::Other { desc: "fd".into() },
            };
            fds.push(FdEntry { fd: fd.proc_fd, kind, flags: 0 });
        }
        fds.sort_by_key(|e| e.fd);
    }

    pub fn collect(pid: i32, window_ms: u64) -> io::Result<Snapshot> {
        let comm = name(pid).map_err(|e| {
            io::Error::new(io::ErrorKind::NotFound, format!("no such process: {pid} ({e})"))
        })?;
        let before: BTreeMap<u64, u64> = thread_ticks(pid).into_iter().collect();
        let started = std::time::Instant::now();
        thread::sleep(Duration::from_millis(window_ms));
        let elapsed_ms = started.elapsed().as_millis().max(1) as u64;

        let info = pidinfo::<TaskAllInfo>(pid, 0)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("process exited: {pid} ({e})")))?;
        let tids = listpidinfo::<ListThreads>(pid, info.ptinfo.pti_threadnum as usize)
            .map_err(|e| io::Error::other(format!("cannot list threads: {e}")))?;

        let mut threads = Vec::new();
        for (i, tid) in tids.iter().enumerate() {
            let Ok(t) = pidinfo::<ThreadInfo>(pid, *tid) else { continue };
            let ticks = (t.pth_user_time + t.pth_system_time) / 10_000_000;
            threads.push(ThreadSnap {
                // Subject selection keys main by tid == pid; macOS thread
                // ids are unrelated, so the first thread carries the pid.
                tid: if i == 0 { pid } else { *tid as i32 },
                comm: comm.clone(),
                state: state_of(t.pth_run_state),
                wchan: String::new(),
                syscall: None,
                cpu_ticks: ticks,
                cpu_delta: ticks.saturating_sub(before.get(tid).copied().unwrap_or(ticks)),
                futex_owner: None,
            });
        }

        let mut fds = Vec::new();
        let mut sockets = BTreeMap::new();
        collect_sockets(pid, &mut fds, &mut sockets);

        Ok(Snapshot {
            pid,
            comm,
            cmdline: String::new(),
            window_ms: elapsed_ms,
            threads,
            fds,
            sockets,
            pipe_peers: BTreeMap::new(),
            children: Vec::new(),
            lock_holders: Vec::new(),
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::{collect, read_mem, socket_inode_owner, thread_regfile, thread_registers};

#[cfg(target_os = "macos")]
pub use macos::collect;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect(_pid: i32, _window_ms: u64) -> io::Result<Snapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "waitson runs on linux and macOS for now",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn socket_inode_owner(_inode: u64, _exclude: i32) -> Option<(i32, String)> {
    None
}

#[cfg(not(target_os = "linux"))]
pub fn read_mem(_pid: i32, _addr: u64, _len: usize) -> Option<Vec<u8>> {
    None
}

#[cfg(not(target_os = "linux"))]
pub fn thread_registers(_tid: i32) -> Option<(u64, u64, u64, u64)> {
    None
}

#[cfg(not(target_os = "linux"))]
pub fn thread_regfile(_tid: i32) -> Option<Vec<u64>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parses_comm_with_spaces_and_parens() {
        let line = "42 (tmux: server (x)) S 1 42 42 0 -1 4194560 1 0 0 0 7 3 0 0 20 0 1 0 100 0 0";
        let st = parse_stat(line).unwrap();
        assert_eq!(st.comm, "tmux: server (x)");
        assert_eq!(st.state, 'S');
        assert_eq!(st.ppid, 1);
        assert_eq!(st.ticks, 10);
    }

    #[test]
    fn syscall_line_parses_blocked_and_rejects_running() {
        let (nr, args) = parse_syscall_line("202 0xdeadbeef 0x0 0x2 0x0 0x0 0x0 0x7f 0x55").unwrap();
        assert_eq!(nr, 202);
        assert_eq!(args[0], 0xdeadbeef);
        assert!(parse_syscall_line("running").is_none());
    }

    #[test]
    fn ipv4_addr_decodes_little_endian() {
        assert_eq!(decode_addr("0100007F:1538"), "127.0.0.1:5432");
        assert_eq!(decode_addr("00000000:0035"), "0.0.0.0:53");
    }

    #[test]
    fn net_lines_parse_queues_and_inode() {
        let body = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1538 0100007F:C350 01 00000000:00000010 00:00000000 00000000     0        0 12345 1 0000000000000000 20 4 30 10 -1\n";
        let mut out = BTreeMap::new();
        parse_net("tcp", body, &mut out);
        let c = out.get(&12345).unwrap();
        assert_eq!(c.local, "127.0.0.1:5432");
        assert_eq!(c.state, "ESTABLISHED");
        assert_eq!(c.rx_queue, 16);
    }
}
