use waitson_schema::*;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Wait<'a> {
    Futex { owner: Option<i32> },
    OnFd { call: &'a str, fd: i32 },
    FileLock,
    Child,
    Poll,
    Sleep,
    Vfork,
    Disk(&'a str),
    Run,
    Unknown,
}

fn classify(t: &ThreadSnap) -> Wait<'_> {
    if t.state == TaskState::Running {
        return Wait::Run;
    }
    if t.state == TaskState::DiskSleep {
        // The vfork completion wait shows wchan vfork_done on older kernels and
        // kernel_clone on newer ones (the wait was inlined); a persistent D sleep
        // there is the vfork wait, nothing else sleeps long inside clone.
        return if t.wchan.contains("vfork") || t.wchan.contains("kernel_clone") {
            Wait::Vfork
        } else {
            Wait::Disk(&t.wchan)
        };
    }
    let name = t.syscall.as_ref().and_then(|s| s.name.as_deref());
    if t.wchan.contains("futex") || name == Some("futex") {
        return Wait::Futex { owner: t.futex_owner };
    }
    match name {
        Some(c @ ("read" | "recvfrom" | "recvmsg" | "write")) => Wait::OnFd {
            call: c,
            fd: t.syscall.as_ref().map(|s| s.args[0] as i32).unwrap_or(-1),
        },
        Some("flock") => Wait::FileLock,
        Some("wait4") => Wait::Child,
        Some("epoll_pwait" | "epoll_wait" | "poll" | "ppoll" | "select" | "pselect6") => Wait::Poll,
        Some("nanosleep" | "clock_nanosleep") => Wait::Sleep,
        _ if t.wchan.contains("do_wait") => Wait::Child,
        _ => Wait::Unknown,
    }
}

fn service_label(addr: &str) -> Option<&'static str> {
    let port: u16 = addr.rsplit(':').next()?.parse().ok()?;
    match port {
        53 => Some("dns"),
        80 => Some("http"),
        443 => Some("https"),
        3306 => Some("mysql"),
        5432 => Some("postgres"),
        6379 => Some("redis"),
        _ => None,
    }
}

fn state_word(s: TaskState) -> &'static str {
    match s {
        TaskState::Running => "running",
        TaskState::Sleeping => "sleeping",
        TaskState::DiskSleep => "in uninterruptible sleep",
        TaskState::Zombie => "a zombie",
        TaskState::Stopped => "stopped",
        TaskState::TracingStop => "in tracing stop",
        TaskState::Idle => "idle",
        TaskState::Dead => "dead",
        TaskState::Other(_) => "in an unknown state",
    }
}

fn top_py_frame(py: Option<&PySnapshot>, os_tid: i32) -> Option<String> {
    let t = py?
        .threads
        .iter()
        .find(|t| t.os_tid == Some(os_tid as u64))?;
    let f = t.frames.first()?;
    Some(format!("{} ({}:{})", f.name, f.filename, f.line))
}

fn gil_holder(py: Option<&PySnapshot>, not_tid: i32) -> Option<(Option<u64>, String)> {
    let t = py?
        .threads
        .iter()
        .find(|t| t.owns_gil && t.os_tid != Some(not_tid as u64))?;
    let frame = t
        .frames
        .first()
        .map(|f| format!("{} ({}:{})", f.name, f.filename, f.line))
        .unwrap_or_else(|| "<unknown frame>".into());
    Some((t.os_tid, frame))
}

fn verdict(class: VerdictClass, headline: String, chain: Vec<String>, evidence: Vec<String>) -> Verdict {
    Verdict { class, headline, chain, evidence }
}

fn decapitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

// How stuck a thread looks; the most-blocked thread is the story, and the
// main thread only wins ties. A busy or parked thread is never the story
// while a sibling is pinned on a lock, an fd, or the kernel.
fn interest(w: &Wait) -> u8 {
    match w {
        Wait::Vfork | Wait::Disk(_) => 6,
        Wait::Futex { owner: Some(_) } | Wait::FileLock => 5,
        Wait::OnFd { .. } => 4,
        Wait::Child => 3,
        Wait::Futex { owner: None } => 2,
        Wait::Unknown => 1,
        Wait::Poll | Wait::Sleep | Wait::Run => 0,
    }
}

fn choose_subject(s: &Snapshot) -> Option<&ThreadSnap> {
    let main = s.main_thread()?;
    let best = s
        .threads
        .iter()
        .max_by_key(|t| (interest(&classify(t)), t.tid == main.tid))?;
    Some(if interest(&classify(best)) > interest(&classify(main)) { best } else { main })
}

/// Which socket inode the subject is actually blocked on, if any.
/// LINK uses this to hop only where the evidence points.
pub fn blocking_socket_inode(s: &Snapshot) -> Option<u64> {
    let subject = choose_subject(s)?;
    if let Wait::OnFd { fd, .. } = classify(subject) {
        if let Some(FdKind::Socket { inode }) = s.fd(fd).map(|e| &e.kind) {
            return Some(*inode);
        }
    }
    None
}

pub fn judge(s: &Snapshot, links: &Links, py: Option<&PySnapshot>) -> Verdict {
    let Some(subject) = choose_subject(s) else {
        return verdict(
            VerdictClass::Refusal,
            format!("no verdict: pid {} has no readable threads", s.pid),
            vec![],
            vec![],
        );
    };
    let not_main = s.main_thread().is_some_and(|m| m.tid != subject.tid);
    let mut v = judge_thread(s, links, py, subject);
    if not_main {
        v.chain.insert(
            0,
            format!(
                "the main thread is not the story here; thread {} is the most-blocked one",
                subject.tid
            ),
        );
    }
    v
}

fn judge_thread(s: &Snapshot, links: &Links, py: Option<&PySnapshot>, subject: &ThreadSnap) -> Verdict {
    match classify(subject) {
        Wait::Futex { owner: Some(owner) } => futex_owned(s, py, subject, owner),
        Wait::Futex { owner: None } => futex_anonymous(s, py, subject),
        Wait::OnFd { call: "write", fd } => blocked_write(s, subject, fd),
        Wait::OnFd { call, fd } => blocked_read(s, links, subject, call, fd),
        Wait::FileLock => file_lock_wait(s, subject),
        Wait::Child => waiting_on_child(s, subject),
        Wait::Vfork => vfork_wait(s, subject),
        Wait::Disk(wchan) => verdict(
            VerdictClass::Partial,
            format!("in uninterruptible kernel sleep in {wchan} — trail ends in the kernel"),
            vec![format!("thread {} state D, wchan {}", subject.tid, wchan)],
            vec!["uninterruptible sleep is kernel- or IO-bound; not killable until it returns".into()],
        ),
        Wait::Run => running(s, py, subject),
        Wait::Poll => polling(s, py, subject),
        Wait::Sleep => verdict(
            VerdictClass::Observation,
            "not stuck — deliberately sleeping (nanosleep)".to_string(),
            vec![format!("thread {} blocked in a timed sleep", subject.tid)],
            vec![],
        ),
        Wait::Unknown => refusal(s, subject),
    }
}

fn futex_owned(s: &Snapshot, py: Option<&PySnapshot>, subject: &ThreadSnap, owner: i32) -> Verdict {
    // Follow the owner chain; revisiting a tid means a lock cycle.
    let mut chain_tids = vec![subject.tid];
    let mut cur = owner;
    for _ in 0..8 {
        if chain_tids.contains(&cur) {
            let names: Vec<String> = chain_tids
                .iter()
                .map(|tid| format!("thread {} ({})", tid, s.thread(*tid).map(|t| t.comm.as_str()).unwrap_or("?")))
                .collect();
            return verdict(
                VerdictClass::Causal,
                format!("deadlock: {} each hold a lock the other is waiting for", names.join(" and ")),
                chain_tids
                    .iter()
                    .map(|tid| format!("thread {} blocked in futex wait, lock owner read from mutex memory", tid))
                    .collect(),
                vec!["lock cycle proven from glibc mutex owner fields".into()],
            );
        }
        chain_tids.push(cur);
        match s.thread(cur).map(classify) {
            Some(Wait::Futex { owner: Some(next) }) => cur = next,
            Some(w) => {
                let owner_t = s.thread(cur).unwrap();
                let doing = match w {
                    Wait::Run => {
                        let frame = top_py_frame(py, cur)
                            .map(|f| format!(", running {f}"))
                            .unwrap_or_default();
                        format!("busy on cpu{frame}")
                    }
                    Wait::OnFd { call, fd } => describe_fd_wait(s, call, fd),
                    _ => format!("{} (wchan {})", state_word(owner_t.state), owner_t.wchan),
                };
                return verdict(
                    VerdictClass::Causal,
                    format!(
                        "blocked on a lock held by thread {} ({}), which is {}",
                        cur, owner_t.comm, doing
                    ),
                    vec![
                        format!("thread {} blocked in futex wait on the lock", subject.tid),
                        format!("lock owner {} read from the mutex owner field", cur),
                        format!("thread {} is {}", cur, doing),
                    ],
                    vec![format!("owner cpu over the window: {} ticks", owner_t.cpu_delta)],
                );
            }
            None => break,
        }
    }
    verdict(
        VerdictClass::Partial,
        format!("blocked on a lock owned by thread {owner}; the owner chain could not be fully followed"),
        vec![format!("thread {} in futex wait, owner {}", subject.tid, owner)],
        vec![],
    )
}

fn futex_anonymous(_s: &Snapshot, py: Option<&PySnapshot>, subject: &ThreadSnap) -> Verdict {
    if let Some((os_tid, frame)) = gil_holder(py, subject.tid) {
        let holder = os_tid.map(|t| t.to_string()).unwrap_or_else(|| "?".into());
        return verdict(
            VerdictClass::Causal,
            format!("waiting on the GIL, held by thread {holder} running {frame}"),
            vec![
                format!("main thread {} blocked in futex wait and does not own the GIL", subject.tid),
                format!("thread {holder} owns the GIL and is executing {frame}"),
            ],
            vec!["GIL ownership read from the interpreter's runtime state".into()],
        );
    }
    verdict(
        VerdictClass::Partial,
        "blocked on a futex (a lock or condition variable); the holder is not identifiable — trail ends at the futex word".to_string(),
        vec![format!("thread {} in futex wait, no owner field readable", subject.tid)],
        vec![],
    )
}

fn describe_fd_wait(s: &Snapshot, call: &str, fd: i32) -> String {
    match s.fd(fd).map(|e| &e.kind) {
        Some(FdKind::Socket { inode }) => match s.sockets.get(inode) {
            Some(c) => format!("blocked in {} from {} ({})", call, c.remote, c.proto),
            None => format!("blocked in {call} on a socket"),
        },
        Some(FdKind::Pipe { .. }) => format!("blocked in {call} on a pipe"),
        Some(FdKind::File { path }) => format!("blocked in {call} on {path}"),
        _ => format!("blocked in {call} on fd {fd}"),
    }
}

fn blocked_read(s: &Snapshot, links: &Links, subject: &ThreadSnap, call: &str, fd: i32) -> Verdict {
    match s.fd(fd).map(|e| &e.kind) {
        Some(FdKind::Socket { inode }) => {
            let Some(conn) = s.sockets.get(inode) else {
                return verdict(
                    VerdictClass::Partial,
                    format!("waiting on {} from a socket (inode {}) — connection details unreadable", call, inode),
                    vec![format!("thread {} blocked in {} on fd {}", subject.tid, call, fd)],
                    vec![],
                );
            };
            let label = service_label(&conn.remote).map(|l| format!(" ({l})")).unwrap_or_default();
            if let Some(peer) = links.socket_peers.get(inode) {
                let peer_doing = decapitalize(peer.headline.strip_prefix("not stuck — ").unwrap_or(&peer.headline));
                return verdict(
                    VerdictClass::Causal,
                    format!(
                        "waiting on a reply from {}{}, which is pid {} ({}) on this machine — {}",
                        conn.remote, label, peer.pid, peer.comm, peer_doing
                    ),
                    vec![
                        format!("thread {} blocked in {} on fd {}", subject.tid, call, fd),
                        format!("fd {} is a {} socket {} → {}", fd, conn.proto, conn.local, conn.remote),
                        format!("the other end resolved to pid {} ({}) and was diagnosed one hop deep", peer.pid, peer.comm),
                        format!("pid {}: {}", peer.pid, peer.headline),
                    ],
                    vec![format!(
                        "socket state {}, rx_queue {}, tx_queue {}",
                        conn.state, conn.rx_queue, conn.tx_queue
                    )],
                );
            }
            let is_dns = conn.proto == "udp" && service_label(&conn.remote) == Some("dns");
            let headline = if is_dns {
                format!("waiting on a DNS response from {} that has not arrived — trail ends at the wire", conn.remote)
            } else {
                format!("waiting on a reply from {}{} — nothing to read yet, trail ends at the wire", conn.remote, label)
            };
            verdict(
                VerdictClass::Partial,
                headline,
                vec![
                    format!("thread {} blocked in {} on fd {}", subject.tid, call, fd),
                    format!("fd {} is a {} socket {} → {}", fd, conn.proto, conn.local, conn.remote),
                    "the remote side owes the next byte; diagnose there".into(),
                ],
                vec![format!(
                    "socket state {}, rx_queue {}, tx_queue {}",
                    conn.state, conn.rx_queue, conn.tx_queue
                )],
            )
        }
        Some(FdKind::Pipe { inode }) => {
            let writer = s
                .pipe_peers
                .get(inode)
                .and_then(|ps| ps.iter().find(|p| !p.reads));
            match writer {
                Some(p) => verdict(
                    VerdictClass::Causal,
                    format!(
                        "waiting for data on a pipe whose write end is held by pid {} ({}), which is {} and not writing",
                        p.pid, p.comm, state_word(p.state)
                    ),
                    vec![
                        format!("thread {} blocked reading pipe inode {}", subject.tid, inode),
                        format!("write end found in pid {} ({}), state {}, wchan {}", p.pid, p.comm, state_word(p.state), p.wchan),
                    ],
                    vec![],
                ),
                None => verdict(
                    VerdictClass::Partial,
                    "waiting for data on a pipe; no process holds the write end — it will never arrive".into(),
                    vec![format!("thread {} blocked reading pipe inode {}", subject.tid, inode)],
                    vec![],
                ),
            }
        }
        _ => verdict(
            VerdictClass::Partial,
            format!("blocked in {} on fd {} — {}", call, fd, describe_fd_wait(s, call, fd)),
            vec![format!("thread {} blocked in {}", subject.tid, call)],
            vec![],
        ),
    }
}

fn blocked_write(s: &Snapshot, subject: &ThreadSnap, fd: i32) -> Verdict {
    match s.fd(fd).map(|e| &e.kind) {
        Some(FdKind::Pipe { inode }) => {
            let reader = s
                .pipe_peers
                .get(inode)
                .and_then(|ps| ps.iter().find(|p| p.reads));
            match reader {
                Some(p) => verdict(
                    VerdictClass::Causal,
                    format!(
                        "pipe full: the read end is held by pid {} ({}), which is {} and not reading",
                        p.pid, p.comm, state_word(p.state)
                    ),
                    vec![
                        format!("thread {} blocked writing pipe inode {} (buffer full)", subject.tid, inode),
                        format!("read end found in pid {} ({}), state {}, wchan {}", p.pid, p.comm, state_word(p.state), p.wchan),
                        "until that process reads, this write cannot complete".into(),
                    ],
                    vec![],
                ),
                None => verdict(
                    VerdictClass::Partial,
                    "blocked writing a full pipe; the read-end holder could not be identified".into(),
                    vec![format!("thread {} blocked writing pipe inode {}", subject.tid, inode)],
                    vec![],
                ),
            }
        }
        Some(FdKind::Socket { inode }) => {
            let dest = s
                .sockets
                .get(inode)
                .map(|c| c.remote.clone())
                .unwrap_or_else(|| "an unknown peer".into());
            verdict(
                VerdictClass::Partial,
                format!("blocked sending to {dest} — the send buffer is full, the peer is not draining it"),
                vec![format!("thread {} blocked in write on socket fd {}", subject.tid, fd)],
                vec![],
            )
        }
        _ => verdict(
            VerdictClass::Partial,
            format!("blocked writing fd {fd}"),
            vec![format!("thread {} blocked in write", subject.tid)],
            vec![],
        ),
    }
}

fn file_lock_wait(s: &Snapshot, subject: &ThreadSnap) -> Verdict {
    let Some(h) = s.lock_holders.first() else {
        return verdict(
            VerdictClass::Partial,
            "waiting on a file lock whose holder is not visible in /proc/locks".into(),
            vec![format!("thread {} blocked in flock", subject.tid)],
            vec![],
        );
    };
    let file = h.path.as_deref().unwrap_or("the same file");
    verdict(
        VerdictClass::Causal,
        format!(
            "waiting on a file lock on {} held by pid {} ({}), which is {}",
            file, h.pid, h.comm, state_word(h.state)
        ),
        vec![
            format!("thread {} blocked in flock", subject.tid),
            format!("/proc/locks names pid {} as the holder of that inode", h.pid),
            format!("the holder is {}; until it unlocks or exits, this wait cannot end", state_word(h.state)),
        ],
        vec![],
    )
}

fn waiting_on_child(s: &Snapshot, subject: &ThreadSnap) -> Verdict {
    let stopped = s.children.iter().find(|c| c.state == TaskState::Stopped);
    if let Some(c) = stopped {
        return verdict(
            VerdictClass::Causal,
            format!(
                "waiting on child pid {} ({}), which is STOPPED and will never exit until resumed",
                c.pid, c.comm
            ),
            vec![
                format!("thread {} blocked in wait4", subject.tid),
                format!("child {} is in state T (stopped, e.g. SIGSTOP)", c.pid),
                format!("kill -CONT {} would unblock the wait", c.pid),
            ],
            vec![],
        );
    }
    if let Some(c) = s.children.first() {
        return verdict(
            VerdictClass::Causal,
            format!("waiting on child pid {} ({}), which is {} — the wait ends when it exits", c.pid, c.comm, state_word(c.state)),
            vec![format!("thread {} blocked in wait4 on child {}", subject.tid, c.pid)],
            vec![],
        );
    }
    verdict(
        VerdictClass::Partial,
        "blocked in wait4 but no live child is visible".into(),
        vec![format!("thread {} blocked in wait4", subject.tid)],
        vec![],
    )
}

fn vfork_wait(s: &Snapshot, subject: &ThreadSnap) -> Verdict {
    let child = s
        .children
        .first()
        .map(|c| format!("child pid {} ({})", c.pid, c.comm))
        .unwrap_or_else(|| "its vfork child".into());
    verdict(
        VerdictClass::Causal,
        format!("vfork: uninterruptible until {child} calls exec or exits — the child is doing neither"),
        vec![
            format!("thread {} in D state, wchan {}", subject.tid, subject.wchan),
            format!("{child} shares this address space until exec/exit"),
        ],
        vec![],
    )
}

fn running(s: &Snapshot, py: Option<&PySnapshot>, subject: &ThreadSnap) -> Verdict {
    // 100 Hz ticks: delta * 10ms against the sampling window gives cpu share,
    // clamped to the physical ceiling of 100% per thread (tick quantization
    // can otherwise read a hair over).
    let total: u64 = s.threads.iter().map(|t| t.cpu_delta).sum();
    let pct = ((total * 1000) / s.window_ms.max(1)).min(s.threads.len() as u64 * 100);
    let frame = top_py_frame(py, subject.tid)
        .or_else(|| {
            py.and_then(|p| p.threads.iter().find(|t| t.active))
                .and_then(|t| t.frames.first())
                .map(|f| format!("{} ({}:{})", f.name, f.filename, f.line))
        })
        .map(|f| format!(", in {f}"))
        .unwrap_or_default();
    verdict(
        VerdictClass::Observation,
        format!("not stuck — busy on cpu ({pct}% of the sampled window){frame}"),
        vec![format!(
            "thread {} runnable the whole window, {} ticks burned process-wide",
            subject.tid, total
        )],
        vec![format!("sampled over {}ms", s.window_ms)],
    )
}

fn is_asyncio(py: Option<&PySnapshot>, os_tid: i32) -> bool {
    py.map(|p| {
        p.threads
            .iter()
            .filter(|t| t.os_tid == Some(os_tid as u64) || p.threads.len() == 1)
            .flat_map(|t| &t.frames)
            .any(|f| f.filename.contains("asyncio"))
    })
    .unwrap_or(false)
}

fn polling(s: &Snapshot, py: Option<&PySnapshot>, subject: &ThreadSnap) -> Verdict {
    let total: u64 = s.threads.iter().map(|t| t.cpu_delta).sum();
    let registered: usize = s
        .fds
        .iter()
        .filter_map(|e| match e.kind {
            FdKind::Epoll { registered } => Some(registered),
            _ => None,
        })
        .sum();
    let pending: u64 = s
        .fds
        .iter()
        .filter_map(|e| match e.kind {
            FdKind::Socket { inode } => s.sockets.get(&inode).map(|c| c.rx_queue),
            _ => None,
        })
        .sum();
    if total == 0 && pending == 0 {
        let (what, hint) = if is_asyncio(py, subject.tid) {
            (
                "asyncio event loop is idle",
                "no runnable tasks; every task is awaiting the outside world, or an await nobody completes",
            )
        } else {
            (
                "idle by design: parked on the event loop with nothing ready",
                "no armed work is visible; it is waiting for the outside world",
            )
        };
        return verdict(
            VerdictClass::Observation,
            format!(
                "{} — {} fds registered, none with pending data, zero cpu",
                what, registered
            ),
            vec![
                format!("thread {} blocked in the poller with no timeout pressure", subject.tid),
                hint.into(),
            ],
            vec![format!("cpu over the window: 0 ticks; pending socket bytes: 0")],
        );
    }
    verdict(
        VerdictClass::Observation,
        "event loop is alive: polling with intermittent work".into(),
        vec![format!("thread {} in the poller; {} ticks burned in the window", subject.tid, total)],
        vec![],
    )
}

/// The JVM names its own monitors: a cycle in the blocked-on graph read
/// from a thread dump is a deadlock by the JVM's own account.
pub fn judge_jvm(_s: &Snapshot, jvm: &JvmSnapshot) -> Verdict {
    use std::collections::BTreeMap;
    let mut owner_of: BTreeMap<&str, &str> = BTreeMap::new();
    for t in &jvm.threads {
        for addr in &t.locked {
            owner_of.insert(addr.as_str(), t.name.as_str());
        }
    }
    let holder = |t: &JvmThread| {
        t.waiting_on
            .as_deref()
            .and_then(|a| owner_of.get(a).copied())
            .filter(|h| *h != t.name)
    };
    for start in jvm.threads.iter().filter(|t| t.state.starts_with("BLOCKED")) {
        let mut seen = vec![start.name.as_str()];
        let mut cur = start;
        while let Some(next) = holder(cur) {
            if seen.contains(&next) {
                return verdict(
                    VerdictClass::Causal,
                    format!(
                        "Java-level deadlock: {} each hold a monitor another is waiting for",
                        seen.join(" and ")
                    ),
                    seen.iter().map(|n| format!("thread \"{n}\" is BLOCKED inside the cycle")).collect(),
                    vec!["monitor ownership read from the JVM's own thread dump".into()],
                );
            }
            seen.push(next);
            let Some(n) = jvm.threads.iter().find(|t| t.name == next) else { break };
            cur = n;
        }
    }
    if let Some(t) = jvm.threads.iter().find(|t| t.state.starts_with("BLOCKED")) {
        let headline = match holder(t) {
            Some(h) => {
                let hstate = jvm
                    .threads
                    .iter()
                    .find(|x| x.name == h)
                    .map(|x| x.state.clone())
                    .unwrap_or_default();
                format!("thread \"{}\" is blocked on a monitor held by \"{h}\", which is {hstate}", t.name)
            }
            None => format!("thread \"{}\" is blocked on a monitor whose owner is not in the dump", t.name),
        };
        return verdict(
            VerdictClass::Causal,
            headline,
            vec!["monitor ownership read from the JVM's own thread dump".into()],
            vec![],
        );
    }
    let runnable = jvm.threads.iter().filter(|t| t.state.starts_with("RUNNABLE")).count();
    verdict(
        VerdictClass::Observation,
        format!(
            "not stuck at the JVM level: {} of {} threads runnable, the rest parked or waiting",
            runnable,
            jvm.threads.len()
        ),
        vec![],
        vec![],
    )
}

/// V8 keeps its JavaScript call stack in JIT-managed memory with no stable
/// external layout and no supported out-of-process reader (unlike CPython
/// and Go). A kernel-level verdict on the event loop would miss the JS
/// cause, so waitson refuses rather than mislead — the honest state until a
/// V8 reader exists.
pub fn node_refusal(s: &Snapshot) -> Verdict {
    let mut seen: Vec<String> = s
        .threads
        .iter()
        .map(|t| format!("tid {} {:?} wchan={} syscall={}", t.tid, t.state, t.wchan, t.syscall.as_ref().and_then(|x| x.name.as_deref()).unwrap_or("?")))
        .collect();
    for c in s.sockets.values() {
        if c.state == "ESTABLISHED" {
            seen.push(format!("open connection: {} → {} (rx {}, tx {})", c.local, c.remote, c.rx_queue, c.tx_queue));
        }
    }
    verdict(
        VerdictClass::Refusal,
        "a Node/V8 runtime: the JavaScript stack lives in JIT memory with no external reader yet, so the event-loop kernel view cannot name the JS cause — refusing rather than guessing".into(),
        vec![
            "the libuv event loop thread is almost always parked in epoll; that tells you nothing about which callback is stuck".into(),
            "the kernel-level facts gathered anyway are in the evidence".into(),
        ],
        seen,
    )
}

pub fn jvm_refusal(s: &Snapshot, reason: &str) -> Verdict {
    let seen: Vec<String> = s
        .threads
        .iter()
        .map(|t| format!("tid {} {:?} wchan={}", t.tid, t.state, t.wchan))
        .collect();
    verdict(
        VerdictClass::Refusal,
        format!("a JVM whose thread dump cannot be taken ({reason}) — refusing rather than guessing from the kernel view"),
        vec!["JVM monitors and thread states live above the kernel; only a thread dump tells the truth".into()],
        seen,
    )
}

/// Go parks every blocked goroutine behind the netpoller, so kernel-level
/// facts cannot distinguish a stuck Go program from an idle one. When the
/// goroutine layer cannot be read, refusing beats guessing.
pub fn go_refusal(s: &Snapshot, reason: &str) -> Verdict {
    let seen: Vec<String> = s
        .threads
        .iter()
        .map(|t| format!("tid {} {:?} wchan={}", t.tid, t.state, t.wchan))
        .collect();
    verdict(
        VerdictClass::Refusal,
        format!(
            "a Go runtime whose goroutines cannot be read ({reason}) — refusing rather than guessing from the kernel view"
        ),
        vec![
            "Go multiplexes goroutines over threads; a blocked program and an idle one look identical from outside".into(),
            "rebuild without -ldflags \"-s -w\" to keep the symbols and DWARF the reader needs".into(),
        ],
        seen,
    )
}

/// The goroutine layer is the truth for Go: statuses and wait reasons come
/// from the runtime's own state, read out of process memory.
pub fn judge_go(_s: &Snapshot, go: &GoSnapshot) -> Verdict {
    let internal = |r: &str| {
        r.starts_with("chan ")
            || r.starts_with("select")
            || r.starts_with("sync.")
            || r.starts_with("semacquire")
            || r.starts_with("wait for GC")
    };
    // Runtime housekeeping goroutines (GC helpers, finalizers) park in every
    // Go program; counting them would make the all-internal deadlock rule
    // unreachable. goid 1 stays: the main goroutine's func is runtime.main.
    let user: Vec<&GoRoutine> = go
        .goroutines
        .iter()
        .filter(|g| g.goid == 1 || !g.func.starts_with("runtime."))
        .collect();
    let active: Vec<&&GoRoutine> = user
        .iter()
        .filter(|g| matches!(g.status.as_str(), "running" | "runnable" | "syscall"))
        .collect();
    let waiting: Vec<&&GoRoutine> = user.iter().filter(|g| g.status == "waiting").collect();

    type Group<'a> = (usize, Option<&'a str>, Option<&'a str>, &'a [String]);
    let mut groups: std::collections::BTreeMap<(&str, &str), Group> = Default::default();
    for g in &waiting {
        let e = groups
            .entry((g.wait_reason.as_str(), g.func.as_str()))
            .or_insert((0, g.source.as_deref(), g.spawned_from.as_deref(), g.stack.as_slice()));
        e.0 += 1;
    }
    let mut summary: Vec<String> = groups
        .iter()
        .map(|((reason, func), (n, source, spawned, stack))| {
            let mut line = format!("{n}× {reason} in {func}");
            if let Some(src) = source {
                line += &format!(" ({src})");
            }
            if let Some(sp) = spawned.filter(|sp| !sp.starts_with("runtime.")) {
                line += &format!(", spawned from {sp}");
            }
            let user: Vec<&str> = stack
                .iter()
                .filter(|f| !f.starts_with("runtime."))
                .map(String::as_str)
                .take(6)
                .collect();
            if !user.is_empty() {
                line += &format!(" — blocked at {}", user.join(" ← "));
            }
            line
        })
        .collect();
    summary.truncate(6);
    let main_g = go.goroutines.iter().find(|g| g.goid == 1);
    let main_desc = main_g
        .map(|g| match g.status.as_str() {
            "waiting" => format!("the main goroutine is blocked in {}", g.wait_reason),
            other => format!("the main goroutine is {other}"),
        })
        .unwrap_or_else(|| "the main goroutine is gone".into());

    if !active.is_empty() {
        return verdict(
            VerdictClass::Observation,
            format!(
                "not stuck at the Go level: {} of {} goroutines are running or runnable — {}",
                active.len(),
                user.len(),
                main_desc
            ),
            summary,
            vec!["goroutine states read from the runtime's own memory".into()],
        );
    }
    if !waiting.is_empty() && waiting.iter().all(|g| internal(&g.wait_reason)) {
        return verdict(
            VerdictClass::Causal,
            format!(
                "Go-level deadlock: all {} goroutines are blocked on each other and none can run — {}",
                waiting.len(),
                main_desc
            ),
            summary,
            vec!["every wait reason is internal (channels/locks); no external event can wake them".into()],
        );
    }
    let external: Vec<String> = waiting
        .iter()
        .filter(|g| !internal(&g.wait_reason))
        .map(|g| format!("{} ({})", g.wait_reason, g.func))
        .take(3)
        .collect();
    verdict(
        VerdictClass::Partial,
        format!(
            "waiting at the Go level: {} — {} goroutines blocked, and only an external event can move it (still open: {})",
            main_desc,
            waiting.len(),
            external.join(", ")
        ),
        summary,
        vec!["goroutine wait reasons read from the runtime's own waitReasonStrings".into()],
    )
}

fn refusal(s: &Snapshot, subject: &ThreadSnap) -> Verdict {
    let mut seen: Vec<String> = s
        .threads
        .iter()
        .map(|t| format!("tid {} {:?} wchan={} syscall={}", t.tid, t.state, t.wchan, t.syscall.as_ref().and_then(|x| x.name.as_deref()).unwrap_or("?")))
        .collect();
    for c in s.sockets.values() {
        if c.state == "ESTABLISHED" {
            seen.push(format!(
                "open connection: {} → {} (rx {}, tx {})",
                c.local, c.remote, c.rx_queue, c.tx_queue
            ));
        }
    }
    let where_at = if subject.wchan.is_empty() {
        format!("main thread {} is {}", subject.tid, state_word(subject.state))
    } else {
        format!("main thread {} wchan={}", subject.tid, subject.wchan)
    };
    verdict(
        VerdictClass::Refusal,
        "no verdict: the wait does not match a known shape — here is everything seen".to_string(),
        vec![where_at],
        seen,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn thread(tid: i32, state: TaskState, wchan: &str, syscall: Option<(&str, [u64; 6])>, owner: Option<i32>) -> ThreadSnap {
        ThreadSnap {
            tid,
            comm: format!("t{tid}"),
            state,
            wchan: wchan.into(),
            syscall: syscall.map(|(name, args)| SyscallSnap { nr: 0, name: Some(name.into()), args }),
            cpu_ticks: 0,
            cpu_delta: 0,
            futex_owner: owner,
        }
    }

    fn snap(pid: i32, threads: Vec<ThreadSnap>) -> Snapshot {
        Snapshot {
            pid,
            comm: "test".into(),
            cmdline: String::new(),
            window_ms: 250,
            threads,
            fds: vec![],
            sockets: BTreeMap::new(),
            pipe_peers: BTreeMap::new(),
            children: vec![],
            lock_holders: vec![],
        }
    }

    #[test]
    fn ab_ba_cycle_is_a_deadlock() {
        let s = snap(1, vec![
            thread(1, TaskState::Sleeping, "futex_wait", Some(("futex", [0; 6])), Some(2)),
            thread(2, TaskState::Sleeping, "futex_wait", Some(("futex", [0; 6])), Some(1)),
        ]);
        let v = judge(&s, &Links::default(), None);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("deadlock"));
    }

    #[test]
    fn lock_held_by_busy_thread_names_the_owner() {
        let s = snap(1, vec![
            thread(1, TaskState::Sleeping, "futex_wait", Some(("futex", [0; 6])), Some(2)),
            thread(2, TaskState::Running, "", None, None),
        ]);
        let v = judge(&s, &Links::default(), None);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("held by thread 2"));
        assert!(v.headline.contains("busy"));
    }

    #[test]
    fn gil_wait_is_causal_when_a_holder_is_visible() {
        let s = snap(1, vec![
            thread(1, TaskState::Sleeping, "futex_wait", Some(("futex", [0; 6])), None),
            thread(2, TaskState::Running, "", None, None),
        ]);
        let py = PySnapshot {
            threads: vec![
                PyThread { os_tid: Some(1), owns_gil: false, active: false, frames: vec![] },
                PyThread {
                    os_tid: Some(2),
                    owns_gil: true,
                    active: true,
                    frames: vec![PyFrame { name: "hog".into(), filename: "gil.py".into(), line: 4 }],
                },
            ],
        };
        let v = judge(&s, &Links::default(), Some(&py));
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("GIL"));
        assert!(v.headline.contains("hog"));
    }

    #[test]
    fn full_pipe_names_the_absent_reader() {
        let mut s = snap(1, vec![thread(
            1,
            TaskState::Sleeping,
            "pipe_write",
            Some(("write", [7, 0, 0, 0, 0, 0])),
            None,
        )]);
        s.fds = vec![FdEntry { fd: 7, kind: FdKind::Pipe { inode: 99 }, flags: 1 }];
        s.pipe_peers.insert(99, vec![PipePeer {
            pid: 500,
            comm: "reader".into(),
            state: TaskState::Sleeping,
            wchan: "hrtimer_nanosleep".into(),
            reads: true,
        }]);
        let v = judge(&s, &Links::default(), None);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("pipe full"));
        assert!(v.headline.contains("500"));
    }

    #[test]
    fn socket_read_is_partial_and_ends_at_the_wire() {
        let mut s = snap(1, vec![thread(
            1,
            TaskState::Sleeping,
            "sk_wait_data",
            Some(("recvfrom", [3, 0, 0, 0, 0, 0])),
            None,
        )]);
        s.fds = vec![FdEntry { fd: 3, kind: FdKind::Socket { inode: 42 }, flags: 2 }];
        s.sockets.insert(42, SocketConn {
            proto: "tcp".into(),
            local: "127.0.0.1:50000".into(),
            remote: "127.0.0.1:5432".into(),
            state: "ESTABLISHED".into(),
            tx_queue: 0,
            rx_queue: 0,
        });
        let v = judge(&s, &Links::default(), None);
        assert_eq!(v.class, VerdictClass::Partial);
        assert!(v.headline.contains("5432"));
        assert!(v.headline.contains("postgres"));
    }

    #[test]
    fn resolved_local_peer_upgrades_socket_wait_to_causal() {
        let mut s = snap(1, vec![thread(
            1,
            TaskState::Sleeping,
            "sk_wait_data",
            Some(("recvfrom", [3, 0, 0, 0, 0, 0])),
            None,
        )]);
        s.fds = vec![FdEntry { fd: 3, kind: FdKind::Socket { inode: 42 }, flags: 2 }];
        s.sockets.insert(42, SocketConn {
            proto: "tcp".into(),
            local: "127.0.0.1:50000".into(),
            remote: "127.0.0.1:9000".into(),
            state: "ESTABLISHED".into(),
            tx_queue: 0,
            rx_queue: 0,
        });
        let mut links = Links::default();
        links.socket_peers.insert(42, SocketPeerDiag {
            pid: 777,
            comm: "python3".into(),
            class: VerdictClass::Observation,
            headline: "Not stuck — it is deliberately sleeping (nanosleep)".into(),
        });
        let v = judge(&s, &links, None);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("777"));
        assert!(v.headline.contains("sleeping"));
    }

    #[test]
    fn blocking_socket_inode_points_at_the_evidence() {
        let mut s = snap(1, vec![thread(
            1,
            TaskState::Sleeping,
            "sk_wait_data",
            Some(("recvfrom", [3, 0, 0, 0, 0, 0])),
            None,
        )]);
        s.fds = vec![FdEntry { fd: 3, kind: FdKind::Socket { inode: 42 }, flags: 2 }];
        assert_eq!(blocking_socket_inode(&s), Some(42));
    }

    #[test]
    fn stopped_child_is_the_cause() {
        let mut s = snap(1, vec![thread(1, TaskState::Sleeping, "do_wait", Some(("wait4", [0; 6])), None)]);
        s.children = vec![ChildSnap { pid: 9, comm: "kid".into(), state: TaskState::Stopped }];
        let v = judge(&s, &Links::default(), None);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.to_lowercase().contains("stopped"));
    }

    #[test]
    fn vfork_wait_is_recognized_under_both_wchan_names() {
        for wchan in ["vfork_done", "kernel_clone"] {
            let mut s = snap(1, vec![thread(1, TaskState::DiskSleep, wchan, None, None)]);
            s.children = vec![ChildSnap { pid: 9, comm: "kid".into(), state: TaskState::Sleeping }];
            let v = judge(&s, &Links::default(), None);
            assert_eq!(v.class, VerdictClass::Causal, "wchan {wchan}");
            assert!(v.headline.contains("vfork"));
        }
    }

    #[test]
    fn a_blocked_worker_outranks_an_idle_main_thread() {
        let mut s = snap(1, vec![
            thread(1, TaskState::Sleeping, "ep_poll", Some(("epoll_pwait", [0; 6])), None),
            thread(9, TaskState::Sleeping, "sk_wait_data", Some(("recvfrom", [3, 0, 0, 0, 0, 0])), None),
        ]);
        s.fds = vec![FdEntry { fd: 3, kind: FdKind::Socket { inode: 42 }, flags: 2 }];
        s.sockets.insert(42, SocketConn {
            proto: "tcp".into(),
            local: "127.0.0.1:50000".into(),
            remote: "127.0.0.1:9009".into(),
            state: "ESTABLISHED".into(),
            tx_queue: 0,
            rx_queue: 0,
        });
        let v = judge(&s, &Links::default(), None);
        assert_eq!(v.class, VerdictClass::Partial);
        assert!(v.headline.contains("9009"));
        assert!(v.chain[0].contains("thread 9"));
        assert_eq!(blocking_socket_inode(&s), Some(42));
    }

    fn gor(goid: u64, status: &str, reason: &str, func: &str) -> GoRoutine {
        GoRoutine {
            goid,
            status: status.into(),
            wait_reason: reason.into(),
            func: func.into(),
            source: None,
            spawned_from: None,
            stack: vec![],
        }
    }

    #[test]
    fn all_internal_waits_is_a_go_deadlock() {
        let go = GoSnapshot {
            goroutines: vec![
                gor(1, "waiting", "chan receive", "runtime.main"),
                gor(5, "waiting", "chan send", "main.worker"),
                gor(6, "waiting", "chan send", "main.worker"),
            ],
        };
        let v = judge_go(&snap(1, vec![]), &go);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("deadlock"));
        assert!(v.headline.contains("chan receive"));
    }

    #[test]
    fn runtime_housekeeping_cannot_mask_a_go_deadlock() {
        let go = GoSnapshot {
            goroutines: vec![
                gor(1, "waiting", "chan receive", "runtime.main"),
                gor(2, "waiting", "force gc (idle)", "runtime.forcegchelper"),
                gor(3, "waiting", "GC sweep wait", "runtime.gcenable.func1"),
                gor(5, "waiting", "chan send", "main.worker"),
            ],
        };
        let v = judge_go(&snap(1, vec![]), &go);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("deadlock"));
    }

    #[test]
    fn io_wait_keeps_the_go_verdict_partial() {
        let go = GoSnapshot {
            goroutines: vec![
                gor(1, "waiting", "chan receive", "runtime.main"),
                gor(7, "waiting", "IO wait", "main.listen"),
            ],
        };
        let v = judge_go(&snap(1, vec![]), &go);
        assert_eq!(v.class, VerdictClass::Partial);
        assert!(v.headline.contains("chan receive"));
    }

    #[test]
    fn runnable_goroutines_mean_not_stuck() {
        let go = GoSnapshot {
            goroutines: vec![gor(1, "running", "", "runtime.main")],
        };
        let v = judge_go(&snap(1, vec![]), &go);
        assert_eq!(v.class, VerdictClass::Observation);
    }

    #[test]
    fn monitor_cycle_in_a_thread_dump_is_a_java_deadlock() {
        let jvm = JvmSnapshot {
            threads: vec![
                JvmThread {
                    name: "left".into(),
                    state: "BLOCKED (on object monitor)".into(),
                    waiting_on: Some("0xb".into()),
                    locked: vec!["0xa".into()],
                },
                JvmThread {
                    name: "right".into(),
                    state: "BLOCKED (on object monitor)".into(),
                    waiting_on: Some("0xa".into()),
                    locked: vec!["0xb".into()],
                },
            ],
        };
        let v = judge_jvm(&snap(1, vec![]), &jvm);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("deadlock"));
        assert!(v.headline.contains("left"));
    }

    #[test]
    fn file_lock_names_holder_and_path() {
        let mut s = snap(1, vec![thread(
            1,
            TaskState::Sleeping,
            "locks_lock_inode_wait",
            Some(("flock", [3, 0, 0, 0, 0, 0])),
            None,
        )]);
        s.lock_holders = vec![LockHolder {
            pid: 900,
            comm: "python3".into(),
            state: TaskState::Sleeping,
            path: Some("/tmp/hb/lockfile".into()),
        }];
        let v = judge(&s, &Links::default(), None);
        assert_eq!(v.class, VerdictClass::Causal);
        assert!(v.headline.contains("900"));
        assert!(v.headline.contains("lockfile"));
    }

    #[test]
    fn unknown_shape_refuses_with_evidence() {
        let s = snap(1, vec![thread(1, TaskState::Sleeping, "mystery_wait", None, None)]);
        let v = judge(&s, &Links::default(), None);
        assert_eq!(v.class, VerdictClass::Refusal);
        assert!(!v.evidence.is_empty());
    }
}
