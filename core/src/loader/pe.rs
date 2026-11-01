//! Cargador PE/COFF (Windows, Xbox original). Solo cabeceras y secciones.

use super::{perms, LoadedBinary, Reader, Section};
use crate::arch::{Arch, Endian, Format};
use crate::error::{Error, Result};

fn machine(m: u16) -> (Arch, Endian) {
    match m {
        0x014C => (Arch::X86, Endian::Little),
        0x8664 => (Arch::X86_64, Endian::Little),
        0x01C0 | 0x01C4 => (Arch::Arm, Endian::Little),
        0xAA64 => (Arch::Arm64, Endian::Little),
        0x01F0 | 0x01F1 => (Arch::PowerPc, Endian::Little),
        0x01F2 => (Arch::PowerPc, Endian::Big), // Xbox 360 (PPC big-endian)
        _ => (Arch::Unknown, Endian::Little),
    }
}

pub fn load(data: &[u8]) -> Result<LoadedBinary> {
    let r = Reader::new(data, Endian::Little);
    let pe_off = u64::from(r.u32(0x3C)?);
    if r.bytes(pe_off, 4)? != b"PE\0\0" {
        return Err(Error::malformed("firma PE no encontrada"));
    }
    let coff = pe_off + 4;
    let mach = r.u16(coff)?;
    let nsec = u64::from(r.u16(coff + 2)?);
    let opt_size = u64::from(r.u16(coff + 16)?);
    let opt = coff + 20;

    let magic = r.u16(opt)?;
    let (bits, image_base) = match magic {
        0x10B => (32, u64::from(r.u32(opt + 28)?)),
        0x20B => (64, r.u64(opt + 24)?),
        m => return Err(Error::malformed(format!("magic opcional PE invalido: 0x{m:x}"))),
    };
    let entry_rva = u64::from(r.u32(opt + 16)?);
    let (arch, endian) = machine(mach);

    let table = opt
        .checked_add(opt_size)
        .ok_or_else(|| Error::malformed("desbordamiento en tabla de secciones PE"))?;
    let mut sections = Vec::new();
    for i in 0..nsec {
        let h = table + i * 40;
        let name = r.cstr(h, 8);
        let vsize = u64::from(r.u32(h + 8)?);
        let vaddr = u64::from(r.u32(h + 12)?);
        let raw_size = u64::from(r.u32(h + 16)?);
        let raw_ptr = u64::from(r.u32(h + 20)?);
        let ch = r.u32(h + 36)?;
        let size = if vsize != 0 { vsize } else { raw_size };
        let file_offset = if raw_size == 0 {
            None
        } else {
            r.check_range(raw_ptr, raw_size, "seccion PE")?;
            Some(raw_ptr)
        };
        sections.push(Section {
            name,
            start: image_base.wrapping_add(vaddr),
            size,
            perms: perms(ch & 0x4000_0000 != 0, ch & 0x8000_0000 != 0, ch & 0x2000_0000 != 0),
            file_offset,
        });
    }

    let mut notes = Vec::new();
    if arch == Arch::Unknown {
        notes.push(format!("IMAGE_FILE_MACHINE 0x{mach:04x} no reconocido"));
    }
    Ok(LoadedBinary {
        format: Format::Pe,
        arch,
        endian,
        bits,
        entry: Some(image_base.wrapping_add(entry_rva)),
        sections,
        notes,
    })
}
