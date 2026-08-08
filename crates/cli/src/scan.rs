//! Fleet triage in two phases: a no-attach sweep over kernel facts flags
//! the processes that look stuck in anger, then only those suspects get
//! the full attach pipeline. Everything parked-and-healthy stays untouched.
use std::collections::BTreeMap;
use std::fs;

pub(crate) struct Sample {
    state: char,
    ticks: u64,
    comm: String,
}

// Stuck in anger means: uninterruptible the whole window, or a core burned
// across it (>=30 of the ~40 ticks a 400ms window holds, i.e. 75%).
pub(crate) fn suspects(
    first: &BTreeMap<i32, Sample>,
    second: &BTreeMap<i32, Sample>,
) -> Vec<(i32, String, String)> {
    let mut out = Vec::new();
    for (pid, b) in second {
        let Some(a) = first.get(pid) else { continue };
        if a.state == 'D' && b.state == 'D' {
            out.push((*pid, b.comm.clone(), "uninterruptible sleep across the window".into()));
        } else if a.state == 'R' && b.state == 'R' && b.ticks.saturating_sub(a.ticks) >= 30 {
            out.push((*pid, b.comm.clone(), "a full core burned across the window".into()));
        }
    }
    out
}

// A tcp receive queue that stays loaded across the window while its owner
// never drains it is the relational signal: someone is waiting ON this
// process. udp queues are excluded; they idle nonzero legitimately.
pub(crate) fn rx_map() -> BTreeMap<u64, u64> {
    let mut sockets = BTreeMap::new();
    for file in ["tcp", "tcp6"] {
        if let Ok(body) = std::fs::read_to_string(format!("/proc/net/{file}")) {
            waitson_snap::parse_net("tcp", &body, &mut sockets);
        }
    }
    sockets
        .into_iter()
        .filter(|(_, c)| c.rx_queue > 0 && c.state == "ESTABLISHED")
        .map(|(inode, c)| (inode, c.rx_queue))
        .collect()
}

pub(crate) fn socket_suspects(
    first: &BTreeMap<u64, u64>,
    second: &BTreeMap<u64, u64>,
    me: i32,
) -> Vec<(i32, String, String)> {
    let mut out = Vec::new();
    for (inode, rx) in second {
        if !first.contains_key(inode) {
            continue;
        }
        if let Some((pid, comm)) = waitson_snap::socket_inode_owner(*inode, me) {
            out.push((pid, comm, format!("unread socket data ({rx} bytes waiting)")));
        }
    }
    out
}

pub fn scan(json: bool) {
    if !cfg!(target_os = "linux") {
        eprintln!("waitson scan: the sweep reads /proc, linux only for now");
        std::process::exit(2);
    }
    let me = std::process::id() as i32;
    let first = sweep(me);
    let rx_first = rx_map();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let second = sweep(me);
    let mut suspects = suspects(&first, &second);
    for s in socket_suspects(&rx_first, &rx_map(), me) {
        if !suspects.iter().any(|(pid, _, _)| *pid == s.0) {
            suspects.push(s);
        }
    }
    suspects.truncate(6);

    let mut findings = Vec::new();
    for (pid, comm, reason) in &suspects {
        let verdict = waitson_snap::collect(*pid, 150)
            .map(|s| {
                let py = waitson_read::python_snapshot(*pid);
                waitson_judge::judge(&s, &waitson_schema::Links::default(), py.as_ref())
            })
            .ok();
        findings.push((pid, comm, reason, verdict));
    }

    if json {
        let rows: Vec<_> = findings
            .iter()
            .map(|(pid, comm, reason, v)| {
                serde_json::json!({
                    "pid": pid, "comm": comm, "reason": reason,
                    "verdict": v.as_ref().map(|v| serde_json::json!({"class": v.class, "headline": v.headline})),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "findings": rows })).unwrap());
        return;
    }
    if findings.is_empty() {
        println!("waitson scan: nothing on this machine looks stuck in anger ({} processes swept)", second.len());
        return;
    }
    println!("waitson scan: {} finding(s) among {} processes:", findings.len(), second.len());
    for (pid, comm, reason, v) in &findings {
        println!("  {pid:>7}  {comm:<16} {reason}");
        if let Some(v) = v {
            println!("           → {}", v.headline);
        }
    }
}

pub(crate) fn sweep(me: i32) -> BTreeMap<i32, Sample> {
    let mut out = BTreeMap::new();
    let Ok(rd) = fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        if pid == me {
            continue;
        }
        // Kernel threads have an empty cmdline; they are the kernel's business.
        match fs::read_to_string(format!("/proc/{pid}/cmdline")) {
            Ok(c) if !c.is_empty() => {}
            _ => continue,
        }
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        let Some(st) = waitson_snap::parse_stat(&stat) else { continue };
        out.insert(pid, Sample { state: st.state, ticks: st.ticks, comm: st.comm });
    }
    out
}
