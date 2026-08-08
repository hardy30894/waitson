use waitson_schema::{PyFrame, PySnapshot, PyThread};

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
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
        .map(|f| f.contains("python"))
        .unwrap_or(false)
}
