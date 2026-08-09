//! Native C/C++/Rust stack of a blocked thread by frame-pointer walk,
//! symbolized per module. Frames are recovered where frame pointers are
//! intact; a broken chain stops rather than inventing frames.
use object::{Object, ObjectSegment, ObjectSymbol};
use std::collections::HashMap;

struct Module {
    start: u64,
    end: u64,
    path: String,
    bias: u64,
    syms: Vec<(u64, u64, String)>,
}

pub fn native_stack(pid: i32, tid: i32) -> Vec<String> {
    let Some((pc, _sp, fp, lr)) = waitson_snap::thread_registers(tid) else {
        return Vec::new();
    };
    let mut modules = load_modules(pid);
    let mut out = Vec::new();
    let mut sym = |addr: u64| symbolize(&mut modules, pid, addr);

    out.push(sym(pc));
    let mut cur = fp;
    let mut first_lr = lr;
    for _ in 0..64 {
        if cur == 0 || cur % 8 != 0 {
            break;
        }
        let Some(pair) = waitson_snap::read_mem(pid, cur, 16) else { break };
        let next_fp = u64::from_le_bytes(pair[0..8].try_into().unwrap());
        let mut ret = u64::from_le_bytes(pair[8..16].try_into().unwrap());
        if first_lr != 0 && out.len() == 1 {
            ret = first_lr;
            first_lr = 0;
        }
        if ret < 0x1000 {
            break;
        }
        out.push(sym(ret));
        if next_fp <= cur {
            break;
        }
        cur = next_fp;
    }
    out
}

fn symbolize(modules: &mut [Module], _pid: i32, addr: u64) -> String {
    let Some(m) = modules.iter().find(|m| addr >= m.start && addr < m.end) else {
        return format!("{addr:#x}");
    };
    let vaddr = addr.wrapping_sub(m.bias);
    let name = m
        .syms
        .partition_point(|(a, _, _)| *a <= vaddr)
        .checked_sub(1)
        .and_then(|i| m.syms.get(i))
        .filter(|(a, sz, _)| vaddr < a + sz.max(&1))
        .map(|(_, _, n)| n.clone());
    let base = m.path.rsplit('/').next().unwrap_or(&m.path);
    match name {
        Some(n) => format!("{n} [{base}]"),
        None => format!("{base}+{:#x}", vaddr),
    }
}

fn load_modules(pid: i32) -> Vec<Module> {
    struct Span {
        base: u64,
        exec_lo: u64,
        exec_hi: u64,
    }
    let mut spans: HashMap<String, Span> = HashMap::new();
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return Vec::new();
    };
    for line in maps.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || !f[5].starts_with('/') {
            continue;
        }
        let Some((lo, hi)) = f[0].split_once('-') else { continue };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16)) else { continue };
        let s = spans.entry(f[5].to_string()).or_insert(Span { base: start, exec_lo: u64::MAX, exec_hi: 0 });
        s.base = s.base.min(start);
        if f[1].contains('x') {
            s.exec_lo = s.exec_lo.min(start);
            s.exec_hi = s.exec_hi.max(end);
        }
    }
    let mut modules = Vec::new();
    for (path, s) in spans {
        if s.exec_hi == 0 {
            continue;
        }
        let mut m = Module { start: s.exec_lo, end: s.exec_hi, path, bias: 0, syms: Vec::new() };
        load_symbols(pid, &mut m, s.base);
        modules.push(m);
    }
    modules
}

fn load_symbols(pid: i32, m: &mut Module, base: u64) {
    let data = std::fs::read(format!("/proc/{pid}/root{}", m.path)).or_else(|_| std::fs::read(&m.path));
    let Ok(bytes) = data else { return };
    let Ok(file) = object::File::parse(&*bytes) else { return };
    let min_vaddr = file.segments().map(|s| s.address()).min().unwrap_or(0);
    m.bias = base.wrapping_sub(min_vaddr);
    let mut syms = Vec::new();
    for s in file.symbols().chain(file.dynamic_symbols()) {
        if s.kind() == object::SymbolKind::Text && s.size() > 0 {
            if let Ok(n) = s.name() {
                syms.push((s.address(), s.size(), n.to_string()));
            }
        }
    }
    syms.sort_by_key(|(a, _, _)| *a);
    syms.dedup_by_key(|(a, _, _)| *a);
    m.syms = syms;
}
