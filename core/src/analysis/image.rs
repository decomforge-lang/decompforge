//! Mapa de memoria del binario cargado: traduce direcciones virtuales a bytes
//! del archivo original.
//!
//! El proyecto SQLite **no guarda el binario** (ADR-009 y ADR-010). Para
//! analizar hay que volver a aportar el mismo archivo; `Project::analyze`
//! comprueba su SHA-256 antes de tocar nada. `Image` es la unica pieza que
//! conoce la relacion direccion -> offset de archivo.

use crate::loader::Section;

/// Region de memoria con datos respaldados por el archivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// Nombre de la seccion de origen.
    pub name: String,
    /// Direccion virtual del primer byte.
    pub start: u64,
    /// Fin exclusivo.
    pub end: u64,
    /// Posicion del primer byte dentro del archivo.
    pub file_offset: u64,
    /// La seccion tiene permiso de ejecucion.
    pub executable: bool,
}

impl Region {
    /// Numero de bytes de la region.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    fn contains(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end
    }
}

/// Vista de solo lectura del binario cargado.
#[derive(Debug, Clone)]
pub struct Image<'a> {
    data: &'a [u8],
    regions: Vec<Region>,
    warnings: Vec<String>,
}

impl<'a> Image<'a> {
    /// Construye el mapa a partir de las secciones persistidas. Las secciones
    /// sin datos (`bss`) o que se salen del archivo se omiten con un aviso; no
    /// se recorta ningun byte de forma silenciosa.
    pub fn from_sections(data: &'a [u8], sections: &[Section]) -> Self {
        let mut regions = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut warn = |msg: String| {
            if !warnings.contains(&msg) {
                warnings.push(msg);
            }
        };

        for s in sections {
            let Some(off) = s.file_offset else {
                continue; // sin datos en el archivo (bss)
            };
            let Ok(off_usize) = usize::try_from(off) else {
                warn(format!("seccion {}: offset de archivo fuera de rango", s.name));
                continue;
            };
            if off_usize >= data.len() {
                warn(format!("seccion {}: offset 0x{off:x} fuera del archivo", s.name));
                continue;
            }
            let available = data.len() - off_usize;
            let declared = usize::try_from(s.size).unwrap_or(usize::MAX);
            let usable = declared.min(available);
            if s.size > usable as u64 {
                warn(format!(
                    "seccion {}: la cabecera declara 0x{:x} bytes pero solo hay 0x{usable:x} en el archivo",
                    s.name, s.size
                ));
            }
            if usable == 0 {
                continue;
            }
            let Some(end) = s.start.checked_add(usable as u64) else {
                warn(format!("seccion {}: direccion final desbordada", s.name));
                continue;
            };
            regions.push(Region {
                name: s.name.clone(),
                start: s.start,
                end,
                file_offset: off,
                executable: s.perms.as_bytes().get(2) == Some(&b'x'),
            });
        }

        if !regions.iter().any(|r| r.executable) {
            warn(
                "no hay ninguna region ejecutable con datos: no se pueden detectar funciones"
                    .into(),
            );
        }
        regions.sort_by_key(|r| (r.start, r.end));
        Image { data, regions, warnings }
    }

    /// Avisos generados al construir el mapa (secciones truncadas u omitidas).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Regiones ordenadas por direccion de inicio.
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// Region mas especifica (la de menor tamano) que contiene la direccion.
    pub fn region_of(&self, addr: u64) -> Option<&Region> {
        self.regions.iter().filter(|r| r.contains(addr)).min_by_key(|r| r.size())
    }

    /// Indica si la direccion pertenece a una region ejecutable.
    pub fn is_executable(&self, addr: u64) -> bool {
        self.regions.iter().any(|r| r.executable && r.contains(addr))
    }

    /// Bytes disponibles en `addr` para decodificar una instruccion.
    pub fn read(&self, addr: u64, len: usize) -> Option<&'a [u8]> {
        if len == 0 {
            return Some(&[]);
        }
        let region = self.region_of(addr)?;
        let end = addr.checked_add(len as u64)?;
        if end > region.end {
            return None;
        }
        let start = usize::try_from(region.file_offset + (addr - region.start)).ok()?;
        let stop = start.checked_add(len)?;
        self.data.get(start..stop)
    }

    /// Como [`Image::read`], pero devuelve hasta `max` bytes disponibles sin
    /// cruzar el final de la region. Sirve para decodificar la ultima
    /// instruccion de una seccion corta (Capstone necesita una rebanada).
    pub fn read_up_to(&self, addr: u64, max: usize) -> Option<&'a [u8]> {
        let region = self.region_of(addr)?;
        let available = region.end.checked_sub(addr)?;
        let len = usize::try_from(available).ok()?.min(max);
        if len == 0 {
            return None;
        }
        let start = usize::try_from(region.file_offset + (addr - region.start)).ok()?;
        let stop = start.checked_add(len)?;
        self.data.get(start..stop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(name: &str, start: u64, size: u64, perms: &str, off: Option<u64>) -> Section {
        Section { name: name.into(), start, size, perms: perms.into(), file_offset: off }
    }

    #[test]
    fn maps_addresses_and_skips_bss() {
        let data = vec![0xAAu8; 32];
        let sections = [
            sec(".text", 0x1000, 16, "r-x", Some(0)),
            sec(".data", 0x2000, 16, "rw-", Some(16)),
            sec(".bss", 0x3000, 16, "rw-", None),
        ];
        let img = Image::from_sections(&data, &sections);
        assert!(img.warnings().is_empty());
        assert_eq!(img.read(0x1000, 4), Some(&[0xAA; 4][..]));
        assert_eq!(img.read(0x1004, 4), Some(&[0xAA; 4][..]));
        assert_eq!(img.read(0x2008, 8), Some(&[0xAA; 8][..]));
        assert_eq!(img.read(0x3000, 1), None); // bss: sin datos
        assert_eq!(img.read(0x100F, 2), None); // no cruza el fin de la region
        assert_eq!(img.read_up_to(0x100C, 16), Some(&[0xAA; 4][..]));
        assert_eq!(img.read_up_to(0x100F, 16), Some(&[0xAA; 1][..]));
        assert!(img.is_executable(0x1000));
        assert!(!img.is_executable(0x2000));
    }

    #[test]
    fn truncation_is_reported_not_silent() {
        let data = vec![0u8; 8];
        let sections = [sec(".text", 0x1000, 0x100, "r-x", Some(0))];
        let img = Image::from_sections(&data, &sections);
        assert!(img.warnings().iter().any(|w| w.contains("declara")));
        assert_eq!(img.read(0x1000, 8), Some(&[0u8; 8][..]));
        assert_eq!(img.read(0x1008, 1), None);
    }

    #[test]
    fn bad_offsets_are_ignored_with_a_warning() {
        let data = vec![0u8; 8];
        let sections = [sec(".text", 0x1000, 8, "r-x", Some(0x100))];
        let img = Image::from_sections(&data, &sections);
        assert!(img.regions().is_empty());
        assert!(img.warnings().iter().any(|w| w.contains("fuera del archivo")));
    }
}
