//! JVM thread dumps via jstack, the JVM's own supported external mechanism.
//! Parsing stays separate from judging: this file produces facts, the judge
//! finds the monitor cycle.
use std::process::Command;
use waitson_schema::{JvmSnapshot, JvmThread};

pub fn looks_java(pid: i32) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
        .is_some_and(|f| f == "java")
}

pub fn jvm_snapshot(pid: i32) -> Result<JvmSnapshot, String> {
    let out = Command::new("jstack")
        .arg(pid.to_string())
        .output()
        .map_err(|e| format!("jstack not runnable ({e}); a JDK provides it"))?;
    if !out.status.success() {
        return Err(format!(
            "jstack failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let snap = parse_jstack(&String::from_utf8_lossy(&out.stdout));
    if snap.threads.is_empty() {
        return Err("jstack produced no threads".into());
    }
    Ok(snap)
}

pub fn parse_jstack(dump: &str) -> JvmSnapshot {
    let mut threads: Vec<JvmThread> = Vec::new();
    let mut cur: Option<JvmThread> = None;
    for line in dump.lines() {
        let lt = line.trim();
        if let Some(rest) = lt.strip_prefix('"') {
            if let Some(t) = cur.take() {
                threads.push(t);
            }
            if let Some(end) = rest.find('"') {
                cur = Some(JvmThread {
                    name: rest[..end].to_string(),
                    state: String::new(),
                    waiting_on: None,
                    locked: Vec::new(),
                });
            }
        } else if let Some(t) = cur.as_mut() {
            if let Some(rest) = lt.strip_prefix("java.lang.Thread.State: ") {
                t.state = rest.to_string();
            } else if let Some(rest) = lt.strip_prefix("- waiting to lock <") {
                if let Some(end) = rest.find('>') {
                    t.waiting_on = Some(rest[..end].to_string());
                }
            } else if let Some(rest) = lt.strip_prefix("- locked <") {
                if let Some(end) = rest.find('>') {
                    t.locked.push(rest[..end].to_string());
                }
            }
        }
    }
    if let Some(t) = cur.take() {
        threads.push(t);
    }
    JvmSnapshot { threads }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jstack_dump_parses_monitors_and_states() {
        let dump = r#"
"left" #14 prio=5 tid=0x1 nid=0x2 waiting for monitor entry
   java.lang.Thread.State: BLOCKED (on object monitor)
	at Deadlock.lambda$main$0(Deadlock.java:7)
	- waiting to lock <0x00b> (a java.lang.Object)
	- locked <0x00a> (a java.lang.Object)

"right" #15 prio=5 tid=0x3 nid=0x4 waiting for monitor entry
   java.lang.Thread.State: BLOCKED (on object monitor)
	- waiting to lock <0x00a> (a java.lang.Object)
	- locked <0x00b> (a java.lang.Object)
"#;
        let s = parse_jstack(dump);
        assert_eq!(s.threads.len(), 2);
        assert_eq!(s.threads[0].name, "left");
        assert!(s.threads[0].state.starts_with("BLOCKED"));
        assert_eq!(s.threads[0].waiting_on.as_deref(), Some("0x00b"));
        assert_eq!(s.threads[1].locked, vec!["0x00b".to_string()]);
    }
}
