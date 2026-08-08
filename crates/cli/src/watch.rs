//! Resident sentinel: sweeps kernel facts on a cadence and diagnoses a
//! process at the moment it turns stuck, once, when it happens. Nothing is
//! attached until something crosses the same triage rules scan uses.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

pub fn watch(json: bool) {
    let me = std::process::id() as i32;
    if !json {
        println!("waitson watch: sweeping every 500ms; a finding prints the moment something turns stuck (ctrl-c to stop)");
    }
    let mut prev = crate::scan::sweep(me);
    let mut flagged: BTreeSet<i32> = BTreeSet::new();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let cur = crate::scan::sweep(me);
        flagged.retain(|pid| cur.contains_key(pid));
        for (pid, comm, reason) in crate::scan::suspects(&prev, &cur) {
            if !flagged.insert(pid) {
                continue;
            }
            let headline = waitson_snap::collect(pid, 150)
                .map(|s| {
                    let py = waitson_read::python_snapshot(pid);
                    waitson_judge::judge(&s, &waitson_schema::Links::default(), py.as_ref()).headline
                })
                .unwrap_or_else(|e| format!("gone before diagnosis: {e}"));
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "pid": pid, "comm": comm, "reason": reason, "headline": headline })
                );
            } else {
                println!("  {pid:>7}  {comm:<16} {reason}");
                println!("           → {headline}");
            }
            let _ = std::io::stdout().flush();
        }
        prev = cur;
    }
}
