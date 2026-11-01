//! Cargador ELF de 32/64 bits, little/big endian.

use super::{perms, LoadedBinary, Reader, Section};
use crate::arch::{Arch, Endian, Format};
use crate::error::{Error, Result};

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHT_NULL: u32 = 0;
const SHT_NOBITS: u32 = 8;
const PT_LOAD: u32 = 1;

fn arch_from_machine(m: u16) -> Arch {
    match m {
        3 => Arch::X86,
        8 => Arch::Mips,
        20 | 21 => Arch::PowerPc,
        23 => Arch::Spu,
        40 => Arch::Arm,
        62 => Arch::X86_64,
        183 => Arch::Arm64,
        _ => Arch::Unknown,
    }
}

pub fn load(data: &[u8]) -> Result<LoadedBinary> {
    if data.len() < 0x34 {
        return Err(Error::malformed("cabecera ELF incompleta"));
    }
    let is64 = match data[4] {
        1 => false,
        2 => true,
        c => return Err(Error::malformed(format!("EI_CLASS invalido: {c}"))),
    };
    let endian = match data[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        d => return Err(Error::malformed(format!("EI_DATA invalido: {d}"))),
    };
    let r = Reader::new(data, endian);
    let machine = r.u16(0x12)?;
    let arch = arch_from_machine(machine);

    let word = |off: u64| -> Result<u64> {
        if is64 {
            r.u64(off)
        } else {
            r.u32(off).map(u64::from)
        }
    };

    let entry = word(0x18)?;
    // Offsets de campos segun la clase.
    let (phoff, shoff, base) = if is64 { (0x20, 0x28, 0x34) } else { (0x1C, 0x20, 0x28) };
    let phoff = word(phoff)?;
    let shoff = word(shoff)?;
    let phentsize = u64::from(r.u16(base + 2)?);
    let phnum = u64::from(r.u16(base + 4)?);
    let shentsize = u64::from(r.u16(base + 6)?);
    let shnum = u64::from(r.u16(base + 8)?);
    let shstrndx = u64::from(r.u16(base + 10)?);

    let mut notes = Vec::new();
    if arch == Arch::Unknown {
        notes.push(format!("e_machine {machine} no reconocido"));
    }
    if arch == Arch::Mips && endian == Endian::Little && !is64 {
        notes.push(
            "MIPS little-endian de 32 bits: compatible con PS2 (R5900) o PSP; \
             confirma la plataforma al crear el proyecto"
                .into(),
        );
    }

    let mut sections = Vec::new();
    let min_sh = if is64 { 0x40 } else { 0x28 };

    if shoff != 0 && shnum != 0 && shentsize >= min_sh {
        // Tabla de nombres de seccion.
        let shdr = |i: u64| -> Result<u64> {
            i.checked_mul(shentsize)
                .and_then(|o| o.checked_add(shoff))
                .filter(|&o| o < r.len())
                .ok_or_else(|| Error::malformed("tabla de secciones fuera del archivo"))
        };
        let (str_off, str_size) = if shstrndx < shnum {
            let h = shdr(shstrndx)?;
            if is64 {
                (r.u64(h + 0x18)?, r.u64(h + 0x20)?)
            } else {
                (u64::from(r.u32(h + 0x10)?), u64::from(r.u32(h + 0x14)?))
            }
        } else {
            (0, 0)
        };

        for i in 0..shnum {
            let h = shdr(i)?;
            let name_off = u64::from(r.u32(h)?);
            let kind = r.u32(h + 4)?;
            let (flags, addr, offset, size) = if is64 {
                (r.u64(h + 8)?, r.u64(h + 0x10)?, r.u64(h + 0x18)?, r.u64(h + 0x20)?)
            } else {
                (
                    u64::from(r.u32(h + 8)?),
                    u64::from(r.u32(h + 0xC)?),
                    u64::from(r.u32(h + 0x10)?),
                    u64::from(r.u32(h + 0x14)?),
                )
            };
            if kind == SHT_NULL || flags & SHF_ALLOC == 0 {
                continue;
            }
            let file_offset = if kind == SHT_NOBITS {
                None
            } else {
                r.check_range(offset, size, "seccion ELF")?;
                Some(offset)
            };
            let name = if name_off < str_size {
                r.cstr(str_off.saturating_add(name_off), str_size - name_off)
            } else {
                String::new()
            };
            sections.push(Section {
                name: if name.is_empty() { format!("section{i}") } else { name },
                start: addr,
                size,
                perms: perms(true, flags & SHF_WRITE != 0, flags & SHF_EXECINSTR != 0),
                file_offset,
            });
        }
    } else if phoff != 0 && phnum != 0 && phentsize >= if is64 { 0x38 } else { 0x20 } {
        // Sin tabla de secciones (binarios "stripped"): usamos los PT_LOAD.
        notes.push("sin tabla de secciones; se usan los segmentos PT_LOAD".into());
        for i in 0..phnum {
            let h = i
                .checked_mul(phentsize)
                .and_then(|o| o.checked_add(phoff))
                .filter(|&o| o < r.len())
                .ok_or_else(|| Error::malformed("tabla de segmentos fuera del archivo"))?;
            if r.u32(h)? != PT_LOAD {
                continue;
            }
            let (flags, offset, vaddr, filesz, memsz) = if is64 {
                (r.u32(h + 4)?, r.u64(h + 8)?, r.u64(h + 0x10)?, r.u64(h + 0x20)?, r.u64(h + 0x28)?)
            } else {
                (
                    r.u32(h + 0x18)?,
                    u64::from(r.u32(h + 4)?),
                    u64::from(r.u32(h + 8)?),
                    u64::from(r.u32(h + 0x10)?),
                    u64::from(r.u32(h + 0x14)?),
                )
            };
            r.check_range(offset, filesz, "segmento ELF")?;
            sections.push(Section {
                name: format!("LOAD{i}"),
                start: vaddr,
                size: memsz,
                perms: perms(flags & 4 != 0, flags & 2 != 0, flags & 1 != 0),
                file_offset: Some(offset),
            });
        }
    } else {
        notes.push("el ELF no tiene tabla de secciones ni de segmentos utilizable".into());
    }

    Ok(LoadedBinary {
        format: Format::Elf,
        arch,
        endian,
        bits: if is64 { 64 } else { 32 },
        entry: Some(entry),
        sections,
        notes,
    })
}
