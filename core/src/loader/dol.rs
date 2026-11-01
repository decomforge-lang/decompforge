//! Cargador DOL (GameCube/Wii). PowerPC big-endian de 32 bits.
//!
//! El DOL no tiene firma magica, asi que se detecta validando que la cabecera
//! de 0x100 bytes sea coherente (offsets, tamanos y direcciones plausibles).

use super::{perms, LoadedBinary, Reader, Section};
use crate::arch::{Arch, Endian, Format};
use crate::error::{Error, Result};

const HEADER: u64 = 0x100;
const N_TEXT: u64 = 7;
const N_DATA: u64 = 11;
const MIN_ADDR: u64 = 0x8000_0000;

struct Seg {
    name: String,
    offset: u64,
    addr: u64,
    size: u64,
    exec: bool,
}

struct Header {
    segs: Vec<Seg>,
    bss_addr: u64,
    bss_size: u64,
    entry: u64,
}

fn parse(data: &[u8]) -> Result<Header> {
    if (data.len() as u64) < HEADER {
        return Err(Error::malformed("cabecera DOL incompleta"));
    }
    let r = Reader::new(data, Endian::Big);
    let mut segs = Vec::new();
    for i in 0..N_TEXT + N_DATA {
        let (o, a, s, name, exec) = if i < N_TEXT {
            (4 * i, 0x48 + 4 * i, 0x90 + 4 * i, format!(".text{i}"), true)
        } else {
            let j = i - N_TEXT;
            (0x1C + 4 * j, 0x64 + 4 * j, 0xAC + 4 * j, format!(".data{j}"), false)
        };
        let size = u64::from(r.u32(s)?);
        if size == 0 {
            continue;
        }
        segs.push(Seg {
            name,
            offset: u64::from(r.u32(o)?),
            addr: u64::from(r.u32(a)?),
            size,
            exec,
        });
    }
    Ok(Header {
        segs,
        bss_addr: u64::from(r.u32(0xD8)?),
        bss_size: u64::from(r.u32(0xDC)?),
        entry: u64::from(r.u32(0xE0)?),
    })
}

fn valid(h: &Header, len: u64) -> bool {
    let mut entry_in_text = false;
    for s in &h.segs {
        let end_file = s.offset.checked_add(s.size);
        let end_mem = s.addr.checked_add(s.size);
        if s.offset < HEADER || end_file.map_or(true, |e| e > len) || s.addr < MIN_ADDR {
            return false;
        }
        if end_mem.is_none() {
            return false;
        }
        if s.exec && h.entry >= s.addr && h.entry < s.addr + s.size {
            entry_in_text = true;
        }
    }
    entry_in_text && (h.bss_size == 0 || h.bss_addr >= MIN_ADDR)
}

pub fn looks_like_dol(data: &[u8]) -> bool {
    parse(data).is_ok_and(|h| valid(&h, data.len() as u64))
}

pub fn load(data: &[u8]) -> Result<LoadedBinary> {
    let h = parse(data)?;
    if !valid(&h, data.len() as u64) {
        return Err(Error::malformed("cabecera DOL incoherente"));
    }
    let mut sections: Vec<Section> = h
        .segs
        .iter()
        .map(|s| Section {
            name: s.name.clone(),
            start: s.addr,
            size: s.size,
            perms: perms(true, !s.exec, s.exec),
            file_offset: Some(s.offset),
        })
        .collect();
    if h.bss_size > 0 {
        sections.push(Section {
            name: ".bss".into(),
            start: h.bss_addr,
            size: h.bss_size,
            perms: perms(true, true, false),
            file_offset: None,
        });
    }
    Ok(LoadedBinary {
        format: Format::Dol,
        arch: Arch::PowerPc,
        endian: Endian::Big,
        bits: 32,
        entry: Some(h.entry),
        sections,
        notes: vec![],
    })
}
