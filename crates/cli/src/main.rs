use std::io::Read;
use std::process::exit;
use waitson_schema::{Links, Snapshot, Verdict, VerdictClass};

mod scan;
mod watch;

const USAGE: &str = "usage: waitson <pid | name | :port> [--json] [--window-ms N]
       waitson snap <pid | name | :port> [--window-ms N]
       waitson judge [--json]              (reads a snap from stdin)
       waitson scan [--json]
       waitson watch [--json]
       waitson doctor

exit codes: 0 a verdict; 1 a refusal; 2 could not run";

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let json = argv.iter().any(|a| a == "--json");
    match argv.first().map(String::as_str) {
        Some("doctor") => doctor(),
        Some("scan") => scan::scan(json),
        Some("watch") => watch::watch(json),
        Some("snap") => cmd_snap(&argv[1..]),
        Some("judge") => cmd_judge(json),
        Some(_) => diagnose(&argv, json),
        None => die(USAGE),
    }
}

fn diagnose(argv: &[String], json: bool) {
    let (target, window_ms) = parse_target_args(argv);
    let pid = resolve_target(&target).unwrap_or_else(|e| die(&e));

    let snap = collect_or_die(pid, window_ms);
    let links = waitson_link::resolve(&snap);
    let py = waitson_read::python_snapshot(pid);
    let verdict = if waitson_read::looks_go(pid) {
        match waitson_read::go_snapshot(pid) {
            Ok(go) => waitson_judge::judge_go(&snap, &go),
            Err(reason) => waitson_judge::go_refusal(&snap, &reason),
        }
    } else if waitson_read::looks_java(pid) {
        match waitson_read::jvm_snapshot(pid) {
            Ok(jvm) => waitson_judge::judge_jvm(&snap, &jvm),
            Err(reason) => waitson_judge::jvm_refusal(&snap, &reason),
        }
    } else if waitson_read::looks_node(pid) {
        waitson_judge::node_refusal(&snap)
    } else {
        waitson_judge::judge(&snap, &links, py.as_ref())
    };

    if json {
        let graph = waitson_link::waitgraph(&snap, &links);
        let payload = serde_json::json!({ "verdict": verdict, "graph": graph });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
    } else {
        render(pid, &snap.comm, &verdict);
    }
    exit_by_class(&verdict);
}

fn cmd_snap(rest: &[String]) {
    let (target, window_ms) = parse_target_args(rest);
    let pid = resolve_target(&target).unwrap_or_else(|e| die(&e));
    let snap = collect_or_die(pid, window_ms);
    println!("{}", serde_json::to_string_pretty(&snap).unwrap());
}

fn cmd_judge(json: bool) {
    let mut body = String::new();
    if std::io::stdin().read_to_string(&mut body).is_err() || body.trim().is_empty() {
        die("waitson judge: expected a snap on stdin (waitson snap <target> | waitson judge)");
    }
    let snap: Snapshot = serde_json::from_str(&body)
        .unwrap_or_else(|e| die(&format!("waitson judge: stdin is not a snap: {e}")));
    // Offline judging: the snap already carries pipe peers and lock holders,
    // but the live-only enrichments (socket hop, runtime readers) need the
    // process, so an offline verdict can be broader than a live one.
    let verdict = waitson_judge::judge(&snap, &Links::default(), None);
    if json {
        println!("{}", serde_json::to_string_pretty(&verdict).unwrap());
    } else {
        render(snap.pid, &snap.comm, &verdict);
    }
    exit_by_class(&verdict);
}

fn parse_target_args(args: &[String]) -> (String, u64) {
    let mut target: Option<String> = None;
    let mut window_ms: u64 = 250;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => {}
            "--window-ms" => {
                window_ms = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| die(USAGE));
            }
            _ => target = Some(a.clone()),
        }
    }
    (target.unwrap_or_else(|| die(USAGE)), window_ms)
}

fn collect_or_die(pid: i32, window_ms: u64) -> Snapshot {
    waitson_snap::collect(pid, window_ms).unwrap_or_else(|e| {
        die(&format!(
            "waitson: cannot read pid {pid}: {e} (does it exist? permissions may need sudo or CAP_SYS_PTRACE; try `waitson doctor`)"
        ))
    })
}

fn exit_by_class(v: &Verdict) -> ! {
    exit(if v.class == VerdictClass::Refusal { 1 } else { 0 })
}

/// The argument is whatever the user actually knows: a pid, a process
/// name, or :port for whoever owns that port on this machine.
fn resolve_target(arg: &str) -> Result<i32, String> {
    if let Ok(pid) = arg.parse::<i32>() {
        return Ok(pid);
    }
    if !cfg!(target_os = "linux") {
        return Err(format!(
            "waitson: name and :port targeting read /proc, linux only for now — pass a pid ({arg})"
        ));
    }
    if let Some(port) = arg.strip_prefix(':') {
        let port: u16 = port
            .parse()
            .map_err(|_| format!("waitson: not a port: {arg}"))?;
        return resolve_port(port)
            .ok_or_else(|| format!("waitson: nothing on this machine owns port {port}"));
    }
    resolve_name(arg)
}

fn resolve_port(port: u16) -> Option<i32> {
    let me = std::process::id() as i32;
    let mut sockets = std::collections::BTreeMap::new();
    for file in ["tcp", "tcp6", "udp", "udp6"] {
        if let Ok(body) = std::fs::read_to_string(format!("/proc/net/{file}")) {
            let proto = if file.starts_with("tcp") { "tcp" } else { "udp" };
            waitson_snap::parse_net(proto, &body, &mut sockets);
        }
    }
    let suffix = format!(":{port}");
    // Prefer the listener; fall back to any socket bound to the port.
    let pick = |listen_only: bool| {
        sockets.iter().find_map(|(inode, c)| {
            (c.local.ends_with(&suffix) && (!listen_only || c.state == "LISTEN" || c.proto == "udp"))
                .then_some(*inode)
        })
    };
    let inode = pick(true).or_else(|| pick(false))?;
    waitson_snap::socket_inode_owner(inode, me).map(|(pid, _)| pid)
}

fn resolve_name(name: &str) -> Result<i32, String> {
    let me = std::process::id() as i32;
    let mut hits: Vec<(i32, String)> = Vec::new();
    let rd = std::fs::read_dir("/proc").map_err(|e| format!("waitson: cannot read /proc: {e}"))?;
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        if pid == me {
            continue;
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
            .unwrap_or_default()
            .replace('\0', " ");
        if comm == name || cmdline.split_whitespace().next().is_some_and(|c| c.ends_with(name)) {
            hits.push((pid, comm));
        }
    }
    match hits.len() {
        0 => Err(format!("waitson: no process named {name}")),
        1 => Ok(hits[0].0),
        _ => Err(format!(
            "waitson: {name} is ambiguous, pick a pid:\n{}",
            hits.iter()
                .map(|(pid, comm)| format!("  {pid}  {comm}"))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

fn render(pid: i32, comm: &str, v: &Verdict) {
    println!("waitson: pid {pid} ({comm}) — {}", v.headline);
    for line in &v.chain {
        println!("  → {line}");
    }
    if !v.evidence.is_empty() {
        println!("  evidence: {}", v.evidence.join("; "));
    }
}

fn doctor() {
    if cfg!(target_os = "macos") {
        println!("waitson doctor: native macOS tier.");
        println!("  same-user processes: thread states, cpu, and socket endpoints are readable without sudo");
        println!("  wait causes and python internals need memory reads: run under sudo for the deep tier");
        println!("  scan/watch and name/:port targeting are linux-only for now; pass a pid");
        return;
    }
    if !cfg!(target_os = "linux") {
        println!("waitson doctor: this build diagnoses on linux and macOS for now.");
        return;
    }
    let euid = libc_geteuid();
    println!("waitson doctor:");
    println!("  running as uid {euid}{}", if euid == 0 { " (root: can attach to anything)" } else { "" });
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(v) => {
            let v = v.trim();
            let meaning = match v {
                "0" => "any process of your user is attachable",
                "1" => "only children are attachable without sudo or CAP_SYS_PTRACE",
                "2" => "only root or CAP_SYS_PTRACE can attach",
                "3" => "attaching is disabled entirely on this machine",
                _ => "unknown value",
            };
            println!("  yama ptrace_scope = {v}: {meaning}");
            if v != "0" && euid != 0 {
                println!("  fix: sudo waitson <target>, or setcap cap_sys_ptrace+ep on the binary");
            }
        }
        Err(_) => println!("  yama ptrace_scope: not present (no yama restriction)"),
    }
    println!("  memory reads use process_vm_readv; the same permission rules apply");
}

#[cfg(target_os = "linux")]
fn libc_geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(not(target_os = "linux"))]
fn libc_geteuid() -> u32 {
    0
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    exit(2)
}
