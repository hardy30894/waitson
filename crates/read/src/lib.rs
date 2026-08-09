use waitson_schema::{PyFrame, PySnapshot, PyThread};

mod cdp;
mod go;
mod jvm;
mod native;
mod pclntab;
pub use cdp::cooperate;
pub use go::go_snapshot;
pub use jvm::{jvm_snapshot, looks_java};
pub use native::native_stack;

pub fn python_snapshot(pid: i32) -> Option<PySnapshot> {
    if !looks_python(pid) {
        return None;
    }
    let config = py_spy::Config::default();
    let mut spy = py_spy::PythonSpy::new(pid, &config).ok()?;
    let traces = spy.get_stack_traces().ok()?;
    Some(PySnapshot {
        threads: traces
            .into_iter()
            .map(|t| PyThread {
                os_tid: t.os_thread_id,
                owns_gil: t.owns_gil,
                active: t.active,
                frames: t
                    .frames
                    .into_iter()
                    .map(|f| PyFrame {
                        name: f.name,
                        filename: f.filename,
                        line: f.line,
                    })
                    .collect(),
            })
            .collect(),
    })
}

fn looks_python(pid: i32) -> bool {
    exe_name(pid).is_some_and(|f| f.contains("python"))
}

/// JS runtime and its engine; JIT stacks have no external reader.
pub fn looks_js(pid: i32) -> Option<(&'static str, &'static str)> {
    match exe_name(pid)?.as_str() {
        "node" | "nodejs" => Some(("Node", "V8")),
        "bun" => Some(("Bun", "JavaScriptCore")),
        "deno" => Some(("Deno", "V8")),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn exe_name(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
}

#[cfg(not(target_os = "linux"))]
fn exe_name(pid: i32) -> Option<String> {
    libproc::libproc::proc_pid::pidpath(pid)
        .ok()
        .and_then(|p| std::path::Path::new(&p).file_name().map(|f| f.to_string_lossy().to_string()))
}

/// "Go buildinf:" sits near the front of every Go binary; 4MB covers it.
pub fn looks_go(pid: i32) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let Ok(n) = f.read(&mut buf) else { return false };
    buf[..n].windows(12).any(|w| w == b"Go buildinf:")
}
