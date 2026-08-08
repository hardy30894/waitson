use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    TracingStop,
    Idle,
    Dead,
    Other(char),
}

impl TaskState {
    pub fn from_code(c: char) -> Self {
        match c {
            'R' => Self::Running,
            'S' => Self::Sleeping,
            'D' => Self::DiskSleep,
            'Z' => Self::Zombie,
            'T' => Self::Stopped,
            't' => Self::TracingStop,
            'I' => Self::Idle,
            'X' => Self::Dead,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallSnap {
    pub nr: i64,
    pub name: Option<String>,
    pub args: [u64; 6],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSnap {
    pub tid: i32,
    pub comm: String,
    pub state: TaskState,
    pub wchan: String,
    pub syscall: Option<SyscallSnap>,
    pub cpu_ticks: u64,
    pub cpu_delta: u64,
    pub futex_owner: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FdKind {
    Socket { inode: u64 },
    Pipe { inode: u64 },
    Epoll { registered: usize },
    File { path: String },
    Other { desc: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdEntry {
    pub fd: i32,
    pub kind: FdKind,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketConn {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub tx_queue: u64,
    pub rx_queue: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildSnap {
    pub pid: i32,
    pub comm: String,
    pub state: TaskState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipePeer {
    pub pid: i32,
    pub comm: String,
    pub state: TaskState,
    pub wchan: String,
    pub reads: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockHolder {
    pub pid: i32,
    pub comm: String,
    pub state: TaskState,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub pid: i32,
    pub comm: String,
    pub cmdline: String,
    pub window_ms: u64,
    pub threads: Vec<ThreadSnap>,
    pub fds: Vec<FdEntry>,
    pub sockets: BTreeMap<u64, SocketConn>,
    pub pipe_peers: BTreeMap<u64, Vec<PipePeer>>,
    pub children: Vec<ChildSnap>,
    pub lock_holders: Vec<LockHolder>,
}

impl Snapshot {
    pub fn main_thread(&self) -> Option<&ThreadSnap> {
        self.threads
            .iter()
            .find(|t| t.tid == self.pid)
            .or_else(|| self.threads.first())
    }

    pub fn thread(&self, tid: i32) -> Option<&ThreadSnap> {
        self.threads.iter().find(|t| t.tid == tid)
    }

    pub fn fd(&self, fd: i32) -> Option<&FdEntry> {
        self.fds.iter().find(|e| e.fd == fd)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyFrame {
    pub name: String,
    pub filename: String,
    pub line: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyThread {
    pub os_tid: Option<u64>,
    pub owns_gil: bool,
    pub active: bool,
    pub frames: Vec<PyFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PySnapshot {
    pub threads: Vec<PyThread>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoRoutine {
    pub goid: u64,
    pub status: String,
    pub wait_reason: String,
    pub func: String,
    pub source: Option<String>,
    pub spawned_from: Option<String>,
    pub stack: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoSnapshot {
    pub goroutines: Vec<GoRoutine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JvmThread {
    pub name: String,
    pub state: String,
    pub waiting_on: Option<String>,
    pub locked: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JvmSnapshot {
    pub threads: Vec<JvmThread>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VerdictClass {
    Causal,
    Partial,
    Observation,
    Refusal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketPeerDiag {
    pub pid: i32,
    pub comm: String,
    pub class: VerdictClass,
    pub headline: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Links {
    pub socket_peers: BTreeMap<u64, SocketPeerDiag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub why: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WaitGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl WaitGraph {
    pub fn node(&mut self, id: impl Into<String>, label: impl Into<String>) -> String {
        let id = id.into();
        if !self.nodes.iter().any(|n| n.id == id) {
            self.nodes.push(GraphNode { id: id.clone(), label: label.into() });
        }
        id
    }

    pub fn edge(&mut self, from: impl Into<String>, to: impl Into<String>, why: impl Into<String>) {
        self.edges.push(GraphEdge { from: from.into(), to: to.into(), why: why.into() });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub class: VerdictClass,
    pub headline: String,
    pub chain: Vec<String>,
    pub evidence: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_roundtrips_with_uppercase_class() {
        let v = Verdict {
            class: VerdictClass::Causal,
            headline: "h".into(),
            chain: vec!["c".into()],
            evidence: vec![],
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"CAUSAL\""));
        let back: Verdict = serde_json::from_str(&s).unwrap();
        assert_eq!(back.class, VerdictClass::Causal);
    }
}
