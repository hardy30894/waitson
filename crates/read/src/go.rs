//! Reads goroutines from a live Go process with no per-version tables:
//! struct offsets come from the binary's own DWARF, wait-reason names from
//! the runtime's own waitReasonStrings, so any Go the binary was built with
//! describes itself.
use std::borrow::Cow;
use std::collections::HashMap;
use object::{Object, ObjectSection, ObjectSymbol};
use waitson_schema::{GoRoutine, GoSnapshot};

const MAX_GOROUTINES: u64 = 10_000;

struct GOffsets {
    goid: u64,
    atomicstatus: u64,
    waitreason: u64,
    startpc: u64,
    gopc: u64,
    sched: u64,
    gobuf_sp: u64,
    gobuf_pc: u64,
    gobuf_lr: u64,
}

pub fn go_snapshot(pid: i32) -> Result<GoSnapshot, String> {
    let exe = std::fs::read(format!("/proc/{pid}/exe"))
        .map_err(|e| format!("cannot read the binary: {e}"))?;
    let file = object::File::parse(&*exe).map_err(|e| format!("not a readable ELF: {e}"))?;

    let mut allgs_addr = None;
    let mut reasons_sym = None;
    let mut gofunc_addr = None;
    let mut funcs: Vec<(u64, u64, String)> = Vec::new();
    for sym in file.symbols() {
        let Ok(name) = sym.name() else { continue };
        match name {
            "runtime.allgs" => allgs_addr = Some(sym.address()),
            "runtime.waitReasonStrings" => reasons_sym = Some((sym.address(), sym.size())),
            // go.func.* before Go 1.20, go:func.* after (the go: prefix change).
            "go:func.*" | "go.func.*" => gofunc_addr = Some(sym.address()),
            _ => {
                if sym.kind() == object::SymbolKind::Text && sym.size() > 0 {
                    funcs.push((sym.address(), sym.size(), name.to_string()));
                }
            }
        }
    }
    let allgs_addr = allgs_addr.ok_or("no runtime.allgs symbol (stripped binary)")?;
    let (reasons_addr, reasons_size) =
        reasons_sym.ok_or("no runtime.waitReasonStrings symbol (stripped binary)")?;
    funcs.sort_by_key(|(a, _, _)| *a);

    // PIE binaries land at an ASLR base; the bias between the mapped base
    // and the ELF's lowest load address relocates every symbol. Non-PIE
    // binaries derive a bias of zero from the same arithmetic.
    let bias = load_bias(pid, &file)?;
    let allgs_addr = allgs_addr.wrapping_add(bias);
    let reasons_addr = reasons_addr.wrapping_add(bias);

    let off = g_offsets(&file).map_err(|e| format!("no DWARF for runtime.g (stripped binary): {e}"))?;
    let reasons = read_wait_reasons(pid, reasons_addr, reasons_size)?;
    let pcln_data = file
        .section_by_name(".gopclntab")
        .or_else(|| file.section_by_name("__gopclntab"))
        .and_then(|s| s.uncompressed_data().ok());
    // go:func.* is the base the inline-tree funcdata offsets are measured
    // from; slice the section that contains it so inline frames resolve.
    let gofunc_section = gofunc_addr.and_then(|addr| {
        file.sections()
            .find(|s| addr >= s.address() && addr < s.address() + s.size())
            .map(|s| (s, addr))
    });
    let gofunc_data = gofunc_section.as_ref().and_then(|(s, _)| s.uncompressed_data().ok());
    let gofunc_slice = match (&gofunc_data, &gofunc_section) {
        (Some(d), Some((s, addr))) => d.get(((addr - s.address()) as usize)..),
        _ => None,
    };
    let pcln = pcln_data
        .as_deref()
        .and_then(|d| crate::pclntab::Pclntab::parse_with(d, gofunc_slice));

    let hdr = mem(pid, allgs_addr, 16)?;
    let arr = u64le(&hdr[0..8]);
    let len = u64le(&hdr[8..16]).min(MAX_GOROUTINES);
    let ptrs = mem(pid, arr, (len as usize) * 8)?;

    let mut goroutines = Vec::new();
    for i in 0..len as usize {
        let g = u64le(&ptrs[i * 8..i * 8 + 8]);
        if g == 0 {
            continue;
        }
        let Ok(goid_b) = mem(pid, g + off.goid, 8) else { continue };
        let Ok(status_b) = mem(pid, g + off.atomicstatus, 4) else { continue };
        let Ok(reason_b) = mem(pid, g + off.waitreason, 1) else { continue };
        let Ok(startpc_b) = mem(pid, g + off.startpc, 8) else { continue };
        let Ok(gopc_b) = mem(pid, g + off.gopc, 8) else { continue };
        // 0x1000 is the GC scan bit composed onto the base status.
        let status = u32::from_le_bytes(status_b[0..4].try_into().unwrap()) & !0x1000;
        let status_name = match status {
            0 => "idle",
            1 => "runnable",
            2 => "running",
            3 => "syscall",
            4 => "waiting",
            6 | 8 => continue,
            9 => "preempted",
            _ => "unknown",
        };
        let wait_reason = if status == 4 {
            let idx = reason_b[0] as usize;
            reasons.get(idx).cloned().unwrap_or_else(|| format!("reason {idx}"))
        } else {
            String::new()
        };
        let startpc = u64le(&startpc_b).wrapping_sub(bias);
        let gopc = u64le(&gopc_b).wrapping_sub(bias);
        // gopc is the return address after the go statement; backing up one
        // byte lands inside the call itself, the addr2line convention.
        let source = pcln
            .as_ref()
            .and_then(|t| t.resolve(startpc))
            .map(|(_, file, line)| format!("{}:{line}", short_path(&file)));
        let spawned_from = pcln
            .as_ref()
            .and_then(|t| t.resolve(gopc.wrapping_sub(1)))
            .map(|(name, file, line)| format!("{name} ({}:{line})", short_path(&file)));
        // sched is only trustworthy for parked goroutines; a running one
        // left stale values behind.
        let stack = if status == 4 {
            (|| -> Option<Vec<String>> {
                let sched = g + off.sched;
                let sp = u64le(&mem(pid, sched + off.gobuf_sp, 8).ok()?);
                let pc = u64le(&mem(pid, sched + off.gobuf_pc, 8).ok()?);
                let lr = u64le(&mem(pid, sched + off.gobuf_lr, 8).ok()?);
                Some(unwind(pid, pcln.as_ref()?, bias, pc, sp, lr))
            })()
            .unwrap_or_default()
        } else {
            Vec::new()
        };
        goroutines.push(GoRoutine {
            goid: u64le(&goid_b),
            status: status_name.to_string(),
            wait_reason,
            func: func_name(&funcs, startpc),
            source,
            spawned_from,
            stack,
        });
    }
    if goroutines.is_empty() {
        return Err("runtime.allgs was readable but empty".into());
    }
    goroutines.sort_by_key(|g| g.goid);
    Ok(GoSnapshot { goroutines })
}

fn load_bias(pid: i32, file: &object::File) -> Result<u64, String> {
    use object::ObjectSegment;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|e| format!("cannot resolve exe path: {e}"))?;
    let exe = exe.to_string_lossy();
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| format!("cannot read maps: {e}"))?;
    let base = maps
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 6 && f[2] == "00000000" && f[5] == exe)
                .then(|| u64::from_str_radix(f[0].split('-').next()?, 16).ok())
                .flatten()
        })
        .next()
        .ok_or("exe mapping not found in maps")?;
    let min_vaddr = file
        .segments()
        .map(|s| s.address())
        .min()
        .ok_or("no load segments")?;
    Ok(base.wrapping_sub(min_vaddr))
}

// The runtime's own unwind rules, replayed from outside: the pcsp table
// gives each frame's size; on arm64 the saved return address sits at the
// frame's lowest word (LR still in gobuf for size-zero leaves), on x86_64
// it sits above the frame where CALL pushed it. runtime.goexit is the
// bottom of every goroutine stack.
fn unwind(pid: i32, pcln: &crate::pclntab::Pclntab, bias: u64, mut pc: u64, mut sp: u64, lr: u64) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..32 {
        let lookup = pc.wrapping_sub(bias).wrapping_sub(if i == 0 { 0 } else { 1 });
        let Some((phys, _, _)) = pcln.resolve(lookup) else { break };
        if phys == "runtime.goexit" || phys.is_empty() {
            break;
        }
        // One physical frame expands to every source frame inlined into it,
        // innermost first, matching the runtime's own traceback.
        for (name, file, line) in pcln.resolve_frames(lookup) {
            out.push(format!("{name} ({}:{line})", short_path(&file)));
        }
        let Some(delta) = pcln.sp_delta(lookup) else { break };
        let delta = delta.max(0) as u64;
        let (ret, next_sp) = if cfg!(target_arch = "aarch64") {
            if delta == 0 {
                if i == 0 && lr != 0 { (lr, sp) } else { break }
            } else {
                let Some(b) = waitson_snap::read_mem(pid, sp, 8) else { break };
                (u64le(&b), sp + delta)
            }
        } else {
            let Some(b) = waitson_snap::read_mem(pid, sp + delta, 8) else { break };
            (u64le(&b), sp + delta + 8)
        };
        if ret == 0 || next_sp < sp {
            break;
        }
        pc = ret;
        sp = next_sp;
    }
    out
}

fn short_path(path: &str) -> String {
    let parts: Vec<&str> = path.rsplitn(3, '/').collect();
    match parts.as_slice() {
        [file, dir, _rest] => format!("{dir}/{file}"),
        _ => path.to_string(),
    }
}

fn mem(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>, String> {
    waitson_snap::read_mem(pid, addr, len)
        .ok_or_else(|| format!("memory read failed at {addr:#x}"))
}

fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[0..8].try_into().unwrap())
}

fn func_name(funcs: &[(u64, u64, String)], pc: u64) -> String {
    let i = funcs.partition_point(|(a, _, _)| *a <= pc);
    if i > 0 {
        let (a, size, name) = &funcs[i - 1];
        if pc < a + size.max(&1) {
            return name.clone();
        }
    }
    "?".into()
}

// waitReasonStrings is a fixed [N]string, so the symbol's own byte size is
// the count: N string headers of 16 bytes each, entry 0 the empty string.
fn read_wait_reasons(pid: i32, addr: u64, size: u64) -> Result<Vec<String>, String> {
    let len = (size / 16).clamp(1, 256) as usize;
    let heads = mem(pid, addr, len * 16)?;
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let sptr = u64le(&heads[i * 16..i * 16 + 8]);
        let slen = u64le(&heads[i * 16 + 8..i * 16 + 16]).min(64) as usize;
        let s = if sptr != 0 && slen > 0 {
            String::from_utf8_lossy(&mem(pid, sptr, slen)?).into_owned()
        } else {
            String::new()
        };
        out.push(s);
    }
    Ok(out)
}

fn g_offsets(file: &object::File) -> Result<GOffsets, String> {
    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let load = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
        Ok(file
            .section_by_name(id.name())
            .and_then(|s| s.uncompressed_data().ok())
            .unwrap_or(Cow::Borrowed(&[])))
    };
    let sections = gimli::DwarfSections::load(load).map_err(|e| e.to_string())?;
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, endian));

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| e.to_string())? {
        let unit = dwarf.unit(header).map_err(|e| e.to_string())?;
        let mut entries = unit.entries();
        let mut depth = 0isize;
        let mut in_struct: Option<(&str, isize)> = None;
        let mut members: HashMap<String, u64> = HashMap::new();
        let mut gobuf: HashMap<String, u64> = HashMap::new();
        while let Some((delta, entry)) = entries.next_dfs().map_err(|e| e.to_string())? {
            depth += delta;
            if let Some((which, sd)) = in_struct {
                if depth <= sd {
                    in_struct = None;
                } else {
                    if depth == sd + 1 && entry.tag() == gimli::DW_TAG_member {
                        let name = attr_name(&dwarf, &unit, entry);
                        let loc = entry
                            .attr_value(gimli::DW_AT_data_member_location)
                            .ok()
                            .flatten()
                            .and_then(|v| v.udata_value());
                        if let (Some(name), Some(loc)) = (name, loc) {
                            if which == "g" {
                                members.insert(name, loc);
                            } else {
                                gobuf.insert(name, loc);
                            }
                        }
                    }
                    continue;
                }
            }
            if entry.tag() == gimli::DW_TAG_structure_type {
                match attr_name(&dwarf, &unit, entry).as_deref() {
                    Some("runtime.g") => in_struct = Some(("g", depth)),
                    Some("runtime.gobuf") => in_struct = Some(("gobuf", depth)),
                    _ => {}
                }
            }
        }
        if !members.is_empty() && !gobuf.is_empty() {
            let get = |k: &str| members.get(k).copied().ok_or_else(|| format!("runtime.g has no member {k}"));
            let getb = |k: &str| gobuf.get(k).copied().ok_or_else(|| format!("runtime.gobuf has no member {k}"));
            return Ok(GOffsets {
                goid: get("goid")?,
                atomicstatus: get("atomicstatus")?,
                waitreason: get("waitreason")?,
                startpc: get("startpc")?,
                gopc: get("gopc")?,
                sched: get("sched")?,
                gobuf_sp: getb("sp")?,
                gobuf_pc: getb("pc")?,
                gobuf_lr: getb("lr")?,
            });
        }
    }
    Err("runtime.g not found in DWARF".into())
}

fn attr_name<'a>(
    dwarf: &gimli::Dwarf<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
    unit: &gimli::Unit<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
    entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
) -> Option<String> {
    let attr = entry.attr_value(gimli::DW_AT_name).ok().flatten()?;
    let s = dwarf.attr_string(unit, attr).ok()?;
    Some(s.to_string_lossy().into_owned())
}
