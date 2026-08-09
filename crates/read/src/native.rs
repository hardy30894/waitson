//! Native C/C++/Rust stack of a blocked thread. DWARF .eh_frame CFI walk
//! first (works through frame-pointer-less code), frame-pointer walk as the
//! fallback; symbolized per module. Frames stop rather than being invented.
use gimli::{BaseAddresses, CfaRule, EhFrame, Register, RegisterRule, RunTimeEndian, UnwindContext, UnwindSection};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use std::collections::HashMap;

#[cfg(target_arch = "x86_64")]
const SP_DWARF: u16 = 7;
#[cfg(not(target_arch = "x86_64"))]
const SP_DWARF: u16 = 31;

struct Module {
    start: u64,
    end: u64,
    path: String,
    bias: u64,
    syms: Vec<(u64, u64, String)>,
    eh_frame: Option<Vec<u8>>,
    eh_frame_addr: u64,
    text_addr: u64,
}

pub fn native_stack(pid: i32, tid: i32) -> Vec<String> {
    let Some(raw) = waitson_snap::thread_regfile(tid) else {
        return Vec::new();
    };
    let mut modules = load_modules(pid);
    let mut pcs = cfi_unwind(pid, &modules, &raw);
    if pcs.len() < 2 {
        pcs = fp_unwind(pid, &raw);
    }
    pcs.iter().map(|pc| symbolize(&mut modules, *pc)).collect()
}

fn regs_from_raw(raw: &[u64]) -> (Vec<u64>, u64) {
    let mut r = vec![0u64; 33];
    #[cfg(target_arch = "x86_64")]
    {
        let map = [10, 12, 11, 5, 13, 14, 4, 19, 9, 8, 7, 6, 3, 2, 1, 0, 16];
        for (dw, &raw_i) in map.iter().enumerate() {
            r[dw] = raw.get(raw_i).copied().unwrap_or(0);
        }
        (r, raw.get(16).copied().unwrap_or(0))
    }
    #[cfg(target_arch = "aarch64")]
    {
        for (i, slot) in r.iter_mut().enumerate().take(32) {
            *slot = raw.get(i).copied().unwrap_or(0);
        }
        (r, raw.get(32).copied().unwrap_or(0))
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        (r, 0)
    }
}

fn cfi_unwind(pid: i32, modules: &[Module], raw: &[u64]) -> Vec<u64> {
    let (mut regs, mut pc) = regs_from_raw(raw);
    let mut ctx = UnwindContext::new();
    let mut out = Vec::new();
    for i in 0..128 {
        if pc < 0x1000 {
            break;
        }
        out.push(pc);
        let Some(m) = modules.iter().find(|m| pc >= m.start && pc < m.end) else { break };
        let Some(eh_bytes) = &m.eh_frame else { break };
        let eh = EhFrame::new(eh_bytes, RunTimeEndian::Little);
        let bases = BaseAddresses::default().set_eh_frame(m.eh_frame_addr).set_text(m.text_addr);
        let lookup = if i == 0 { pc } else { pc - 1 };
        let Ok(fde) = eh.fde_for_address(&bases, lookup, EhFrame::cie_from_offset) else { break };
        let ra_reg = fde.cie().return_address_register();
        let Ok(row) = fde.unwind_info_for_address(&eh, &bases, &mut ctx, lookup) else { break };

        let cfa = match row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => {
                reg(&regs, *register).wrapping_add(*offset as u64)
            }
            _ => break,
        };

        let ra = match apply(pid, &regs, cfa, row.register(ra_reg)) {
            Some(v) if v >= 0x1000 => v,
            _ => break,
        };
        let mut next = regs.clone();
        for (r, rule) in row.registers() {
            if let Some(v) = apply(pid, &regs, cfa, rule.clone()) {
                set(&mut next, *r, v);
            }
        }
        set(&mut next, Register(SP_DWARF), cfa);
        regs = next;
        pc = ra;
    }
    out
}

fn reg(regs: &[u64], r: Register) -> u64 {
    regs.get(r.0 as usize).copied().unwrap_or(0)
}

fn set(regs: &mut [u64], r: Register, v: u64) {
    if let Some(slot) = regs.get_mut(r.0 as usize) {
        *slot = v;
    }
}

fn apply(pid: i32, regs: &[u64], cfa: u64, rule: RegisterRule<usize>) -> Option<u64> {
    match rule {
        RegisterRule::Offset(o) => read_u64(pid, cfa.wrapping_add(o as u64)),
        RegisterRule::ValOffset(o) => Some(cfa.wrapping_add(o as u64)),
        RegisterRule::Register(r) => Some(reg(regs, r)),
        RegisterRule::SameValue => None,
        _ => None,
    }
}

fn read_u64(pid: i32, addr: u64) -> Option<u64> {
    let b = waitson_snap::read_mem(pid, addr, 8)?;
    Some(u64::from_le_bytes(b.try_into().ok()?))
}

fn fp_unwind(pid: i32, raw: &[u64]) -> Vec<u64> {
    #[cfg(target_arch = "x86_64")]
    let (pc, fp, lr) = (raw.get(16).copied().unwrap_or(0), raw.get(4).copied().unwrap_or(0), 0u64);
    #[cfg(target_arch = "aarch64")]
    let (pc, fp, lr) = (raw.get(32).copied().unwrap_or(0), raw.get(29).copied().unwrap_or(0), raw.get(30).copied().unwrap_or(0));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let (pc, fp, lr): (u64, u64, u64) = (0, 0, 0);

    let mut out = vec![pc];
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
        out.push(ret);
        if next_fp <= cur {
            break;
        }
        cur = next_fp;
    }
    out
}

fn symbolize(modules: &mut [Module], addr: u64) -> String {
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
        None => format!("{base}+{vaddr:#x}"),
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
        let mut m = Module {
            start: s.exec_lo,
            end: s.exec_hi,
            path,
            bias: 0,
            syms: Vec::new(),
            eh_frame: None,
            eh_frame_addr: 0,
            text_addr: 0,
        };
        load_module(pid, &mut m, s.base);
        modules.push(m);
    }
    modules
}

fn load_module(pid: i32, m: &mut Module, base: u64) {
    let data = std::fs::read(format!("/proc/{pid}/root{}", m.path)).or_else(|_| std::fs::read(&m.path));
    let Ok(bytes) = data else { return };
    let Ok(file) = object::File::parse(&*bytes) else { return };
    let min_vaddr = file.segments().map(|s| s.address()).min().unwrap_or(0);
    m.bias = base.wrapping_sub(min_vaddr);

    if let Some(sec) = file.section_by_name(".eh_frame") {
        if let Ok(d) = sec.uncompressed_data() {
            m.eh_frame = Some(d.into_owned());
            m.eh_frame_addr = m.bias.wrapping_add(sec.address());
        }
    }
    m.text_addr = file
        .section_by_name(".text")
        .map(|s| m.bias.wrapping_add(s.address()))
        .unwrap_or(m.start);

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
