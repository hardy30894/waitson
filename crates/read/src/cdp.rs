//! Node's own inspector, activated post-hoc: SIGUSR1 starts it, the
//! DevTools protocol pauses V8 and returns the true JS stack. Opt-in only;
//! the debug port stays open on the target afterward.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use waitson_schema::JsStackView;

const PORT: u16 = 9229;

pub fn cooperate(pid: i32) -> Result<JsStackView, String> {
    if !target_listens(pid) {
        eprintln!("waitson: sending SIGUSR1 to {pid} to start its inspector (the debug port stays open)");
        let rc = unsafe { libc::kill(pid, libc::SIGUSR1) };
        if rc != 0 {
            return Err(format!("cannot signal pid {pid} (permissions?)"));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !target_listens(pid) {
            if Instant::now() > deadline {
                return Err("the target never opened its inspector port".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let ws_url = discover_ws_url()?;
    pause_and_read(&ws_url)
}

// The port must belong to the target, proven from its own fd table, before
// anything connects to it.
fn target_listens(pid: i32) -> bool {
    waitson_snap::collect(pid, 1)
        .map(|s| {
            s.sockets
                .values()
                .any(|c| c.state == "LISTEN" && c.local.ends_with(&format!(":{PORT}")))
        })
        .unwrap_or(false)
}

fn discover_ws_url() -> Result<String, String> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{PORT}").parse().unwrap(),
        Duration::from_secs(1),
    )
    .map_err(|e| format!("cannot reach the inspector port: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream
        .write_all(format!("GET /json HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut body = String::new();
    stream.read_to_string(&mut body).ok();
    let json = body.split("\r\n\r\n").nth(1).unwrap_or(&body);
    let targets: serde_json::Value =
        serde_json::from_str(json.trim()).map_err(|e| format!("inspector /json unreadable: {e}"))?;
    targets
        .as_array()
        .and_then(|a| a.first())
        .and_then(|t| t["webSocketDebuggerUrl"].as_str())
        .map(String::from)
        .ok_or_else(|| "inspector listed no debuggable targets".into())
}

fn pause_and_read(url: &str) -> Result<JsStackView, String> {
    let addr = format!("127.0.0.1:{PORT}");
    let stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(1))
        .map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_millis(300))).ok();
    let (mut ws, _) = tungstenite::client(url, stream).map_err(|e| format!("inspector handshake failed: {e}"))?;

    let send = |ws: &mut tungstenite::WebSocket<TcpStream>, msg: &str| {
        ws.send(tungstenite::Message::Text(msg.into())).map_err(|e| e.to_string())
    };
    send(&mut ws, r#"{"id":1,"method":"Debugger.enable"}"#)?;
    send(&mut ws, r#"{"id":2,"method":"Debugger.pause"}"#)?;

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut frames = Vec::new();
    let mut paused = false;
    // Script URLs arrive as scriptParsed events, not in the pause frames.
    let mut scripts: std::collections::HashMap<String, String> = Default::default();
    while Instant::now() < deadline {
        let msg = match ws.read() {
            Ok(tungstenite::Message::Text(t)) => t,
            Ok(_) => continue,
            Err(_) => continue,
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&msg) else { continue };
        if v["method"] == "Debugger.scriptParsed" {
            if let (Some(id), Some(url)) = (v["params"]["scriptId"].as_str(), v["params"]["url"].as_str()) {
                scripts.insert(id.to_string(), url.to_string());
            }
            continue;
        }
        if v["method"] == "Debugger.paused" {
            paused = true;
            if let Some(calls) = v["params"]["callFrames"].as_array() {
                for c in calls.iter().take(8) {
                    let name = match c["functionName"].as_str() {
                        Some("") | None => "(anonymous)".to_string(),
                        Some(n) => n.to_string(),
                    };
                    let url = c["url"]
                        .as_str()
                        .filter(|u| !u.is_empty())
                        .map(String::from)
                        .or_else(|| {
                            c["location"]["scriptId"].as_str().and_then(|id| scripts.get(id).cloned())
                        })
                        .unwrap_or_else(|| "?".into());
                    let url = url.trim_start_matches("file://").to_string();
                    let line = c["location"]["lineNumber"].as_u64().unwrap_or(0) as u32 + 1;
                    frames.push((name, url, line));
                }
            }
            break;
        }
    }
    if paused {
        send(&mut ws, r#"{"id":3,"method":"Debugger.resume"}"#).ok();
    }
    ws.close(None).ok();
    Ok(JsStackView { executing: paused, frames })
}
