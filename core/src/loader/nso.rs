//! Cargador de cabecera NSO0 (Nintendo Switch). ARM64 little-endian.
//!
//! Un NSO no esta cifrado, pero sus segmentos suelen ir comprimidos con LZ4.
//! Por ahora solo leemos la cabecera y el mapa de memoria; la descompresion
//! llegara con el analisis (Fase 1.x). La disposicion de la cabecera sigue la
//! documentacion de la comunidad (Switchbrew) y debe contrastarse con
//! ejecutables reales aportados por el usuario.

use super::{perms, LoadedBinary, Reader, Section};
use crate::arch::{Arch, Endian, Format};
use crate::error::Result;

pub fn load(data: &[u8]) -> Result<LoadedBinary> {
    let r = Reader::new(data, Endian::Little);
    let flags = r.u32(0x0C)?;

    // (nombre, offset de cabecera de segmento, offset del tamano comprimido, permisos)
    let defs = [
        (".text", 0x10u64, 0x60u64, perms(true, false, true)),
        (".rodata", 0x20, 0x64, perms(true, false, false)),
        (".data", 0x30, 0x68, perms(true, true, false)),
    ];
    let mut sections = Vec::new();
    let mut notes = Vec::new();
    for (i, (name, h, csize_off, p)) in defs.into_iter().enumerate() {
        let file_off = u64::from(r.u32(h)?);
        let mem_off = u64::from(r.u32(h + 4)?);
        let size = u64::from(r.u32(h + 8)?);
        let compressed = flags & (1 << i) != 0;
        let stored = if compressed { u64::from(r.u32(csize_off)?) } else { size };
        r.check_range(file_off, stored, "segmento NSO")?;
        if compressed {
            notes.push(format!("{name}: comprimido con LZ4 (descompresion pendiente)"));
        }
        sections.push(Section {
            name: name.into(),
            start: mem_off,
            size,
            perms: p,
            file_offset: Some(file_off),
        });
    }
    let bss = u64::from(r.u32(0x3C)?);
    if bss > 0 {
        let end = sections.last().map_or(0, |s| s.start + s.size);
        sections.push(Section {
            name: ".bss".into(),
            start: end,
            size: bss,
            perms: perms(true, true, false),
            file_offset: None,
        });
    }
    Ok(LoadedBinary {
        format: Format::Nso,
        arch: Arch::Arm64,
        endian: Endian::Little,
        bits: 64,
        entry: None,
        sections,
        notes,
    })
}
