use waitson_schema::*;

/// One hop across the wire: if the subject is blocked on a local socket,
/// find the process on the other end and diagnose it too (depth 1, no
/// further hops from the peer).
pub fn resolve(s: &Snapshot) -> Links {
    let mut links = Links::default();
    let Some(inode) = waitson_judge::blocking_socket_inode(s) else {
        return links;
    };
    let Some(conn) = s.sockets.get(&inode) else {
        return links;
    };
    if conn.proto != "tcp" {
        return links;
    }
    let peer_inode = s.sockets.iter().find_map(|(i, c)| {
        (*i != inode && c.proto == "tcp" && c.local == conn.remote && c.remote == conn.local)
            .then_some(*i)
    });
    let Some(peer_inode) = peer_inode else {
        return links;
    };
    let Some((pid, comm)) = waitson_snap::socket_inode_owner(peer_inode, s.pid) else {
        return links;
    };
    let Ok(peer_snap) = waitson_snap::collect(pid, 120) else {
        return links;
    };
    let peer_py = waitson_read::python_snapshot(pid);
    let v = waitson_judge::judge(&peer_snap, &Links::default(), peer_py.as_ref());
    links.socket_peers.insert(
        inode,
        SocketPeerDiag { pid, comm, class: v.class, headline: v.headline },
    );
    links
}

pub fn waitgraph(s: &Snapshot, links: &Links) -> WaitGraph {
    let mut g = WaitGraph::default();
    let me = g.node(format!("proc:{}", s.pid), format!("{} (pid {})", s.comm, s.pid));
    for t in &s.threads {
        if let Some(owner) = t.futex_owner {
            let a = g.node(format!("thread:{}", t.tid), format!("thread {}", t.tid));
            let b = g.node(format!("thread:{owner}"), format!("thread {owner}"));
            g.edge(a, b, "waits on a lock whose owner field names this thread");
        }
    }
    for e in &s.fds {
        match &e.kind {
            FdKind::Socket { inode } => {
                if let Some(c) = s.sockets.get(inode) {
                    if c.state == "ESTABLISHED" {
                        let sock = g.node(format!("sock:{inode}"), format!("{} {}", c.proto, c.remote));
                        g.edge(me.clone(), sock.clone(), format!("fd {} to {}", e.fd, c.remote));
                        if let Some(p) = links.socket_peers.get(inode) {
                            let peer = g.node(format!("proc:{}", p.pid), format!("{} (pid {})", p.comm, p.pid));
                            g.edge(sock, peer.clone(), "other end of the connection");
                            let state = g.node(format!("diag:{}", p.pid), p.headline.clone());
                            g.edge(peer, state, "diagnosed one hop deep");
                        }
                    }
                }
            }
            FdKind::Pipe { inode } => {
                let pipe = g.node(format!("pipe:{inode}"), format!("pipe {inode}"));
                g.edge(me.clone(), pipe.clone(), format!("fd {}", e.fd));
                for p in s.pipe_peers.get(inode).into_iter().flatten() {
                    let peer = g.node(format!("proc:{}", p.pid), format!("{} (pid {})", p.comm, p.pid));
                    let end = if p.reads { "holds the read end" } else { "holds the write end" };
                    g.edge(pipe.clone(), peer, end);
                }
            }
            _ => {}
        }
    }
    for c in &s.children {
        let kid = g.node(format!("proc:{}", c.pid), format!("{} (pid {})", c.comm, c.pid));
        g.edge(me.clone(), kid, "parent of");
    }
    g
}
