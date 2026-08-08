//! Go's own line tables. Every Go binary carries gopclntab so its runtime
//! can print stack traces; parsing it maps any pc to function, file, and
//! line with nothing guessed. Formats 1.18 (0xFFFFFFF0) and 1.20+
//! (0xFFFFFFF1) share every field read here.
pub struct Pclntab<'a> {
    data: &'a [u8],
    quantum: u64,
    nfunc: u64,
    text_start: u64,
    funcname_off: u64,
    cutab_off: u64,
    filetab_off: u64,
    pctab_off: u64,
    pcln_off: u64,
}

impl<'a> Pclntab<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 8 + 8 * 8 {
            return None;
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
        if magic != 0xFFFF_FFF0 && magic != 0xFFFF_FFF1 {
            return None;
        }
        let word = |i: usize| u64::from_le_bytes(data[8 + i * 8..16 + i * 8].try_into().unwrap());
        Some(Self {
            data,
            quantum: data[6] as u64,
            nfunc: word(0),
            text_start: word(2),
            funcname_off: word(3),
            cutab_off: word(4),
            filetab_off: word(5),
            pctab_off: word(6),
            pcln_off: word(7),
        })
    }

    fn func_at(&self, rel: u64) -> Option<(u64, usize)> {
        let entry = |i: u64| -> Option<u32> {
            let off = (self.pcln_off + i * 8) as usize;
            Some(u32::from_le_bytes(self.data.get(off..off + 4)?.try_into().ok()?))
        };
        let (mut lo, mut hi) = (0u64, self.nfunc);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if (entry(mid)? as u64) <= rel {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let idx = lo.checked_sub(1)?;
        let func_entry = entry(idx)? as u64;
        let funcoff_off = (self.pcln_off + idx * 8 + 4) as usize;
        let funcoff =
            u32::from_le_bytes(self.data.get(funcoff_off..funcoff_off + 4)?.try_into().ok()?) as u64;
        Some((func_entry, (self.pcln_off + funcoff) as usize))
    }

    fn field(&self, fi: usize, n: usize) -> Option<u32> {
        let off = fi + n * 4;
        Some(u32::from_le_bytes(self.data.get(off..off + 4)?.try_into().ok()?))
    }

    /// The frame size (sp delta) a function has grown at a given pc, from
    /// the pcsp table: what the runtime's own unwinder consults.
    pub fn sp_delta(&self, pc: u64) -> Option<i64> {
        let rel = pc.checked_sub(self.text_start)?;
        let (func_entry, fi) = self.func_at(rel)?;
        let pcsp = self.field(fi, 4)?;
        self.pcvalue(pcsp as u64, func_entry, rel)
    }

    /// pc (link-time address) -> (function, file, line).
    pub fn resolve(&self, pc: u64) -> Option<(String, String, u32)> {
        let rel = pc.checked_sub(self.text_start)?;
        let (func_entry, fi) = self.func_at(rel)?;
        let field = |n: usize| self.field(fi, n);
        let nameoff = field(1)?;
        let pcfile = field(5)?;
        let pcln = field(6)?;
        let cu_offset = field(8)?;

        let name = self.cstr((self.funcname_off + nameoff as u64) as usize)?;
        let line = self.pcvalue(pcln as u64, func_entry, rel)? as u32;
        let fileno = self.pcvalue(pcfile as u64, func_entry, rel)?;
        let cut = (self.cutab_off + (cu_offset as u64 + fileno as u64) * 4) as usize;
        let file_off = u32::from_le_bytes(self.data.get(cut..cut + 4)?.try_into().ok()?) as u64;
        let file = self.cstr((self.filetab_off + file_off) as usize)?;
        Some((name, file, line))
    }

    fn cstr(&self, off: usize) -> Option<String> {
        let rest = self.data.get(off..)?;
        let end = rest.iter().position(|b| *b == 0)?;
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    }

    // The pcvalue tables encode (value delta zigzag, pc delta) runs from
    // value -1 at the function entry, in units of the pc quantum.
    fn pcvalue(&self, off: u64, func_entry: u64, target: u64) -> Option<i64> {
        if off == 0 {
            return None;
        }
        let mut p = (self.pctab_off + off) as usize;
        let mut val: i64 = -1;
        let mut pc = func_entry;
        let mut first = true;
        loop {
            let (uv, n) = self.uvarint(p)?;
            if uv == 0 && !first {
                return None;
            }
            first = false;
            p += n;
            val += if uv & 1 != 0 { !(uv >> 1) as i64 } else { (uv >> 1) as i64 };
            let (pcd, n) = self.uvarint(p)?;
            p += n;
            pc += pcd * self.quantum;
            if target < pc {
                return Some(val);
            }
        }
    }

    fn uvarint(&self, off: usize) -> Option<(u64, usize)> {
        let mut out: u64 = 0;
        for i in 0..10 {
            let b = *self.data.get(off + i)?;
            out |= ((b & 0x7f) as u64) << (7 * i);
            if b & 0x80 == 0 {
                return Some((out, i + 1));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcvalue_decodes_a_hand_built_run() {
        // pctab at 90; one run at +6: value delta +6 (zigzag 12), 4 pc
        // quanta of coverage (16 bytes at quantum 4), then terminator.
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        data[6] = 4;
        let words: [u64; 8] = [1, 0, 0, 0, 0, 0, 90, 104];
        for (i, w) in words.iter().enumerate() {
            data[8 + i * 8..16 + i * 8].copy_from_slice(&w.to_le_bytes());
        }
        data[96] = 12;
        data[97] = 4;
        let t = Pclntab::parse(&data).unwrap();
        assert_eq!(t.pcvalue(0, 0, 8), None, "offset 0 means no table");
        assert_eq!(t.pcvalue(6, 0, 8), Some(5), "-1 + 6 = 5 while pc within the run");
        assert_eq!(t.pcvalue(6, 0, 100), None, "past the run, no value");
    }
}
