//! Cargador NSO0 (Nintendo Switch). ARM64 little-endian.
//!
//! Un NSO no está cifrado, pero sus tres segmentos (`.text`, `.rodata`,
//! `.data`) pueden ir comprimidos con LZ4. Cada segmento comprimido es una
//! secuencia de bloques con esta forma:
//!
//! ```text
//! u32 compressed_size;   // bytes LZ4 que siguen
//! u32 decompressed_size; // bytes que produce el bloque
//! [compressed_size bytes LZ4]
//! ```
//!
//! El tamaño descomprimido total lo declara la cabecera (campos 0x18, 0x28 y
//! 0x38); los tamaños comprimidos están en 0x60, 0x64 y 0x68.
//!
//! Cuando hay compresión, el análisis no puede leer el archivo original: hace
//! falta una **imagen materializada** formada por el archivo seguido de los
//! segmentos descomprimidos. [`materialize`] la construye y [`load`] deja los
//! `file_offset` de las secciones apuntando a ella, de forma que
//! [`crate::analysis::Image`] traduce direcciones sin saber nada de LZ4
//! (ADR-013). Si ningún segmento está realmente comprimido, la imagen es el
//! propio archivo y no se copia nada.
//!
//! La disposición de la cabecera sigue la documentación de la comunidad
//! (Switchbrew) y debe contrastarse con ejecutables reales aportados por el
//! usuario.

use super::{perms, LoadedBinary, Reader, Section};
use crate::arch::{Arch, Endian, Format};
use crate::error::{Error, Result};

/// (nombre, offset de la cabecera del segmento, offset de su tamaño comprimido).
const SEGMENTS: [(&str, u64, u64); 3] =
    [(".text", 0x10, 0x60), (".rodata", 0x20, 0x64), (".data", 0x30, 0x68)];

/// Límite de la imagen materializada. Evita que una cabecera maliciosa agote
/// la memoria (RNF-03): tres segmentos de `u32::MAX` serían 12 GiB.
const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct Segment {
    name: &'static str,
    /// Posición del segmento en el archivo original.
    file_offset: u64,
    /// Dirección virtual del primer byte.
    memory_offset: u64,
    /// Tamaño descomprimido declarado.
    size: u64,
    /// Bytes que ocupa en el archivo (comprimidos o sin comprimir).
    stored_size: u64,
    /// La cabecera marca el segmento como comprimido.
    compressed: bool,
    /// Posición dentro de la imagen materializada.
    image_offset: u64,
}

impl Segment {
    /// Hay compresión real: el bloque LZ4 ocupa menos que el original.
    fn is_compressed(&self) -> bool {
        self.compressed && self.stored_size < self.size
    }
}

struct Header {
    segments: [Segment; 3],
    bss: u64,
    /// Tamaño de la imagen materializada (archivo + segmentos descomprimidos).
    image_size: u64,
}

fn parse(data: &[u8]) -> Result<Header> {
    let r = Reader::new(data, Endian::Little);
    if r.bytes(0, 4)? != b"NSO0" {
        return Err(Error::malformed("cabecera NSO0 ausente"));
    }
    let flags = r.u32(0x0C)?;
    let mut segments = [Segment {
        name: ".text",
        file_offset: 0,
        memory_offset: 0,
        size: 0,
        stored_size: 0,
        compressed: false,
        image_offset: 0,
    }; 3];
    // Los segmentos descomprimidos se añaden al final del archivo, en orden.
    let mut image_size = data.len() as u64;
    for (i, (name, header_off, csize_off)) in SEGMENTS.into_iter().enumerate() {
        let file_offset = u64::from(r.u32(header_off)?);
        let memory_offset = u64::from(r.u32(header_off + 4)?);
        let size = u64::from(r.u32(header_off + 8)?);
        let compressed = flags & (1 << i) != 0;
        let declared = u64::from(r.u32(csize_off)?);
        // `compressed_size == 0` o mayor o igual que el tamaño original
        // significa que el segmento se guardó tal cual.
        let stored_size =
            if compressed && declared > 0 && declared < size { declared } else { size };
        r.check_range(file_offset, stored_size, "segmento NSO")?;
        let is_compressed = compressed && stored_size < size;
        let image_offset = if is_compressed {
            let start = image_size;
            image_size = image_size.checked_add(size).ok_or_else(|| {
                Error::malformed(format!("{name}: tamaño de imagen NSO desbordado"))
            })?;
            start
        } else {
            file_offset
        };
        segments[i] = Segment {
            name,
            file_offset,
            memory_offset,
            size,
            stored_size,
            compressed,
            image_offset,
        };
    }
    if image_size > MAX_IMAGE_BYTES {
        return Err(Error::malformed(format!(
            "imagen NSO de 0x{image_size:x} bytes; el límite es 0x{MAX_IMAGE_BYTES:x}"
        )));
    }
    Ok(Header { segments, bss: u64::from(r.u32(0x3C)?), image_size })
}

/// Carga la cabecera y el mapa de memoria. No descomprime: los tamaños
/// descomprimidos ya están en la cabecera, así que los offsets de la imagen
/// materializada se pueden calcular sin tocar los datos.
pub fn load(data: &[u8]) -> Result<LoadedBinary> {
    let header = parse(data)?;
    let perms_list =
        [perms(true, false, true), perms(true, false, false), perms(true, true, false)];
    let mut sections = Vec::with_capacity(4);
    let mut notes = Vec::new();

    for (seg, p) in header.segments.iter().zip(perms_list) {
        if seg.is_compressed() {
            notes.push(format!(
                "{}: LZ4 0x{:x} -> 0x{:x} bytes",
                seg.name, seg.stored_size, seg.size
            ));
        } else if seg.compressed {
            notes.push(format!("{}: marcado como LZ4 pero se guarda sin comprimir", seg.name));
        }
        sections.push(Section {
            name: seg.name.into(),
            start: seg.memory_offset,
            size: seg.size,
            perms: p,
            file_offset: Some(seg.image_offset),
        });
    }
    if header.segments.iter().any(Segment::is_compressed) {
        notes.push(format!(
            "segmentos LZ4 descomprimidos en una imagen de 0x{:x} bytes; los offsets de \
             sección se refieren a esa imagen",
            header.image_size
        ));
    }

    let last = &header.segments[2];
    if header.bss > 0 {
        let end = last.memory_offset.checked_add(last.size).ok_or_else(|| {
            Error::malformed(".data: dirección final desbordada al situar .bss".to_string())
        })?;
        sections.push(Section {
            name: ".bss".into(),
            start: end,
            size: header.bss,
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

/// Construye la imagen que debe analizarse. Devuelve `None` si el archivo no
/// tiene ningún segmento comprimido: en ese caso la imagen es el propio
/// archivo y el llamador puede evitar la copia.
pub fn materialize(data: &[u8]) -> Result<Option<Vec<u8>>> {
    let header = parse(data)?;
    if !header.segments.iter().any(Segment::is_compressed) {
        return Ok(None);
    }
    let extra = header.image_size - data.len() as u64;
    let mut image = Vec::new();
    image
        .try_reserve_exact(
            data.len()
                + usize::try_from(extra).map_err(|_| {
                    Error::malformed("imagen NSO demasiado grande para este proceso".to_string())
                })?,
        )
        .map_err(|_| Error::malformed("sin memoria para la imagen NSO".to_string()))?;
    image.extend_from_slice(data);
    for seg in header.segments.iter().filter(|s| s.is_compressed()) {
        if image.len() as u64 != seg.image_offset {
            return Err(Error::malformed(format!(
                "{}: offset de imagen incoherente (0x{:x} != 0x{:x})",
                seg.name,
                image.len(),
                seg.image_offset
            )));
        }
        let r = Reader::new(data, Endian::Little);
        let stored = r.bytes(seg.file_offset, seg.stored_size)?;
        decompress_segment(seg, stored, &mut image)?;
    }
    if image.len() as u64 != header.image_size {
        return Err(Error::malformed("la imagen NSO no tiene el tamaño declarado"));
    }
    Ok(Some(image))
}

fn decompress_segment(seg: &Segment, stored: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let mut input = stored;
    let mut produced = 0u64;
    while !input.is_empty() {
        if input.len() < 8 {
            return Err(Error::malformed(format!("{}: bloque LZ4 truncado", seg.name)));
        }
        let csize = u32::from_le_bytes(input[0..4].try_into().expect("4 bytes")) as usize;
        let dsize = u32::from_le_bytes(input[4..8].try_into().expect("4 bytes")) as usize;
        let rest = &input[8..];
        if csize == 0 && dsize == 0 {
            // Relleno final: solo se acepta si el resto son ceros.
            if rest.iter().any(|&b| b != 0) {
                return Err(Error::malformed(format!(
                    "{}: bloque LZ4 vacío seguido de datos",
                    seg.name
                )));
            }
            break;
        }
        if dsize == 0 || csize == 0 || csize > rest.len() {
            return Err(Error::malformed(format!(
                "{}: bloque LZ4 con tamaños inválidos (0x{csize:x} -> 0x{dsize:x})",
                seg.name
            )));
        }
        produced = produced.checked_add(dsize as u64).ok_or_else(|| {
            Error::malformed(format!("{}: tamaño descomprimido desbordado", seg.name))
        })?;
        if produced > seg.size {
            return Err(Error::malformed(format!(
                "{}: los bloques LZ4 producen más de 0x{:x} bytes",
                seg.name, seg.size
            )));
        }
        let start = out.len();
        out.resize(start + dsize, 0);
        let written = lz4_flex::block::decompress_into(&rest[..csize], &mut out[start..])
            .map_err(|e| Error::malformed(format!("{}: bloque LZ4 inválido: {e}", seg.name)))?;
        if written != dsize {
            return Err(Error::malformed(format!(
                "{}: el bloque LZ4 produjo 0x{written:x} bytes y declaraba 0x{dsize:x}",
                seg.name
            )));
        }
        input = &rest[csize..];
    }
    if produced != seg.size {
        return Err(Error::malformed(format!(
            "{}: se descomprimieron 0x{produced:x} bytes y la cabecera declara 0x{:x}",
            seg.name, seg.size
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_magic_is_rejected() {
        let mut data = crate::synthetic::nso_arm64(false);
        data[..4].copy_from_slice(b"NSO1");
        assert!(parse(&data).is_err());
    }

    #[test]
    fn block_with_impossible_sizes_is_rejected() {
        let bin = crate::synthetic::nso_arm64_lz4();
        // El tamaño comprimido del primer bloque está en 0x100.
        let mut bad = bin.clone();
        bad[0x100..0x104].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(materialize(&bad).is_err());
        // El tamaño descomprimido no puede superar el declarado por la cabecera.
        let mut bad = bin;
        bad[0x104..0x108].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert!(materialize(&bad).is_err());
    }
}
