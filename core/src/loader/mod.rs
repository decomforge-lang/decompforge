//! Deteccion de formato y cargadores (RF-01, RF-02).
//!
//! Politica legal (docs/ACCEPTABLE_USE.md): DecompForge nunca descifra ni
//! elude protecciones. Un SELF (siempre cifrado/firmado) se rechaza con
//! `Error::Protected`; el usuario debe aportar el ejecutable ya descifrado
//! por medios legitimos en su jurisdiccion.

mod dol;
mod elf;
mod nso;
mod pe;
mod reader;

pub use reader::Reader;

use crate::arch::{Arch, Endian, Format};
use crate::error::{Error, Result};
use serde::Serialize;
use std::borrow::Cow;

/// Una region de memoria del binario cargado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Section {
    /// Nombre de la seccion (p. ej. `.text`).
    pub name: String,
    /// Direccion virtual del primer byte.
    pub start: u64,
    /// Tamano declarado en la cabecera.
    pub size: u64,
    /// Permisos en forma `rwx` (con `-` para los ausentes).
    pub perms: String,
    /// Posicion en el archivo; `None` para regiones sin datos (bss).
    ///
    /// En un NSO comprimido apunta a [`image_data`]: la imagen materializada
    /// (archivo + segmentos descomprimidos), no al archivo original.
    pub file_offset: Option<u64>,
}

pub(crate) fn perms(r: bool, w: bool, x: bool) -> String {
    format!(
        "{}{}{}",
        if r { 'r' } else { '-' },
        if w { 'w' } else { '-' },
        if x { 'x' } else { '-' }
    )
}

/// Resultado de cargar un binario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadedBinary {
    /// Formato detectado.
    pub format: Format,
    /// Arquitectura detectada.
    pub arch: Arch,
    /// Orden de bytes.
    pub endian: Endian,
    /// Ancho de palabra en bits (32 o 64).
    pub bits: u8,
    /// Punto de entrada, si la cabecera lo declara.
    pub entry: Option<u64>,
    /// Regiones de memoria (secciones o segmentos `PT_LOAD`).
    pub sections: Vec<Section>,
    /// Avisos para el usuario (p. ej. segmentos comprimidos).
    pub notes: Vec<String>,
}

/// Descripcion de una ROM plana aportada por el usuario.
#[derive(Debug, Clone, Copy)]
pub struct FlatSpec {
    /// Arquitectura del codigo.
    pub arch: Arch,
    /// Orden de bytes.
    pub endian: Endian,
    /// Direccion virtual del primer byte del archivo.
    pub base: u64,
}

/// Opciones de carga.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    /// Si se indica y el formato no se reconoce, se carga como ROM plana.
    pub flat: Option<FlatSpec>,
}

/// Detecta el formato por cabeceras (sin validar a fondo).
pub fn detect(data: &[u8]) -> Result<Format> {
    if data.starts_with(b"\x7fELF") {
        Ok(Format::Elf)
    } else if data.starts_with(b"SCE\0") || data.starts_with(&[0x4f, 0x15, 0x3d, 0x1d]) {
        Ok(Format::Self_)
    } else if data.starts_with(b"XEX2") || data.starts_with(b"XEX1") {
        Ok(Format::Xex)
    } else if data.starts_with(b"NSO0") {
        Ok(Format::Nso)
    } else if data.starts_with(b"PFS0") {
        Err(Error::Unsupported {
            format: "pfs0 (NSP)",
            hint: "es un contenedor, no un ejecutable; aporta el NSO/NRO ya extraido".into(),
        })
    } else if data.starts_with(b"MZ") {
        Ok(Format::Pe)
    } else if data.len() > 0x8006 && &data[0x8001..0x8006] == b"CD001" {
        Ok(Format::Iso)
    } else if dol::looks_like_dol(data) {
        Ok(Format::Dol)
    } else {
        Err(Error::UnknownFormat)
    }
}

/// Carga un binario aportado por el usuario.
pub fn load(data: &[u8], opts: &LoadOptions) -> Result<LoadedBinary> {
    let format = match detect(data) {
        Ok(f) => f,
        Err(Error::UnknownFormat) if opts.flat.is_some() => Format::Flat,
        Err(e) => return Err(e),
    };
    match format {
        Format::Elf => elf::load(data),
        Format::Dol => dol::load(data),
        Format::Pe => pe::load(data),
        Format::Nso => nso::load(data),
        Format::Flat => load_flat(data, opts.flat.expect("comprobado arriba")),
        Format::Self_ => Err(Error::Protected {
            format: "SELF",
            hint: "los SELF van cifrados y firmados. DecompForge no descifra ni elude \
                   protecciones: aporta el ELF ya obtenido con medios legitimos en tu \
                   jurisdiccion."
                .into(),
        }),
        Format::Xex => Err(Error::Unsupported {
            format: "XEX",
            hint: "cargador pendiente. Los XEX cifrados se rechazaran siempre; \
                   aporta el ejecutable ya descifrado por medios legitimos."
                .into(),
        }),
        Format::Iso => Err(Error::Unsupported {
            format: "ISO 9660",
            hint: "es una imagen de disco, no un ejecutable; extrae el ejecutable del juego \
                   (p. ej. el ELF principal) y cargalo directamente."
                .into(),
        }),
    }
}

/// Devuelve los bytes que deben analizarse para `format`.
///
/// La mayoria de formatos se analizan directamente desde el archivo
/// (`Cow::Borrowed`). Un NSO con segmentos LZ4 necesita una imagen
/// materializada (`Cow::Owned`); sus secciones ya guardan los offsets de esa
/// imagen (ADR-013).
pub fn image_data<'a>(data: &'a [u8], format: Format) -> Result<Cow<'a, [u8]>> {
    match format {
        Format::Nso => match nso::materialize(data)? {
            Some(image) => Ok(Cow::Owned(image)),
            None => Ok(Cow::Borrowed(data)),
        },
        _ => Ok(Cow::Borrowed(data)),
    }
}

fn load_flat(data: &[u8], spec: FlatSpec) -> Result<LoadedBinary> {
    if data.is_empty() {
        return Err(Error::malformed("ROM plana vacia"));
    }
    let bits = match spec.arch {
        Arch::Arm64 | Arch::X86_64 => 64,
        _ => 32,
    };
    Ok(LoadedBinary {
        format: Format::Flat,
        arch: spec.arch,
        endian: spec.endian,
        bits,
        entry: None,
        sections: vec![Section {
            name: ".rom".into(),
            start: spec.base,
            size: data.len() as u64,
            perms: perms(true, true, true),
            file_offset: Some(0),
        }],
        notes: vec!["ROM plana: la arquitectura y la direccion base las indico el usuario".into()],
    })
}
