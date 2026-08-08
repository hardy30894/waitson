use std::process::exit;
use waitson_schema::Verdict;

const USAGE: &str = "usage: waitson <pid> [--json] [--window-ms N]";

fn main() {
    let mut pid: Option<i32> = None;
    let mut json = false;
    let mut window_ms: u64 = 250;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--json" => json = true,
            "--window-ms" => {
                window_ms = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| die(USAGE));
            }
            _ => match a.parse() {
                Ok(p) => pid = Some(p),
                Err(_) => die(&format!("waitson: not a pid: {a}\n{USAGE}")),
            },
        }
    }
    let Some(pid) = pid else { die(USAGE) };

    let snap = waitson_snap::collect(pid, window_ms).unwrap_or_else(|e| {
        die(&format!(
            "waitson: cannot read pid {pid}: {e} (does it exist? permissions may need sudo or CAP_SYS_PTRACE)"
        ))
    });
    let py = waitson_read::python_snapshot(pid);
    let verdict = waitson_judge::judge(&snap, py.as_ref());

    if json {
        println!("{}", serde_json::to_string_pretty(&verdict).unwrap());
    } else {
        render(pid, &snap.comm, &verdict);
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

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    exit(2)
}
