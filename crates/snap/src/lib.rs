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

    // glibc pthread_mutex_t layout: __lock (the futex word) at +0, __owner tid at +8.
    // A garbage read (condvar futexes, other libcs) is rejected by the caller's
    // "owner must be a thread of this process" check.
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

    // Read the socket table through the target's own /proc entry: for a
    // containerized pid that is its network namespace, not the host's.
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

    pub fn collect(pid: i32, window_ms: u64) -> io::Result<Snapshot> {
        let stat = read(format!("/proc/{pid}/stat"))
            .as_deref()
            .and_then(parse_stat)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no such process: {pid}")))?;

        let before = thread_ticks(pid);
        let started = std::time::Instant::now();
        thread::sleep(Duration::from_millis(window_ms));
        // cpu share is computed against the window; use the real elapsed time,
        // not the nominal sleep, or tick quantization reads as >100% busy.
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
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::{collect, socket_inode_owner};

#[cfg(not(target_os = "linux"))]
pub fn collect(_pid: i32, _window_ms: u64) -> io::Result<Snapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "waitson reads /proc; linux only for now (run inside a container on this machine)",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn socket_inode_owner(_inode: u64, _exclude: i32) -> Option<(i32, String)> {
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
