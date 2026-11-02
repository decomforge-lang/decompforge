//! Arquitecturas y orden de bytes soportados (RF-02).

use serde::Serialize;
use std::fmt;
use std::str::FromStr;

/// Orden de bytes (endianness) del binario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    /// Los bytes de menor peso van primero (MIPS LE, ARM, x86, PS4/Switch).
    Little,
    /// Los bytes de mayor peso van primero (PowerPC de GameCube/Wii/PS3, MIPS BE).
    Big,
}

impl Endian {
    /// Nombre usado en la CLI y en el JSON (`little` o `big`).
    pub fn as_str(self) -> &'static str {
        match self {
            Endian::Little => "little",
            Endian::Big => "big",
        }
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Endian {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "little" | "le" => Ok(Endian::Little),
            "big" | "be" => Ok(Endian::Big),
            other => Err(format!("endianness desconocida: '{other}' (usa little|big)")),
        }
    }
}

/// Arquitectura del procesador detectada en el binario (RF-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// MIPS32/64 (PS2, PSP, N64).
    Mips,
    /// PowerPC 32/64 (GameCube, Wii, PS3, Xbox 360).
    PowerPc,
    /// ARM de 32 bits (GBA, DS, 3DS).
    Arm,
    /// ARM de 64 bits / AArch64 (Switch).
    Arm64,
    /// x86 de 32 bits (Xbox original).
    X86,
    /// x86-64 / AMD64.
    X86_64,
    /// Cell SPU (PS3).
    Spu,
    /// No se pudo determinar.
    Unknown,
}

impl Arch {
    /// Nombre usado en la CLI, la base de datos y el JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::Mips => "mips",
            Arch::PowerPc => "ppc",
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Spu => "spu",
            Arch::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Arch {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "mips" => Ok(Arch::Mips),
            "ppc" | "powerpc" => Ok(Arch::PowerPc),
            "arm" => Ok(Arch::Arm),
            "arm64" | "aarch64" => Ok(Arch::Arm64),
            "x86" | "i386" => Ok(Arch::X86),
            "x86_64" | "x86-64" | "amd64" => Ok(Arch::X86_64),
            "spu" => Ok(Arch::Spu),
            other => Err(format!(
                "arquitectura desconocida: '{other}' (mips|ppc|arm|arm64|x86|x86_64|spu)"
            )),
        }
    }
}

/// Formato de ejecutable reconocido por el cargador.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// ELF 32/64, little o big endian.
    Elf,
    /// DOL de GameCube/Wii (sin magic; se valida la cabecera).
    Dol,
    /// PE/COFF de Windows o Xbox.
    Pe,
    /// NSO0 de Nintendo Switch.
    Nso,
    /// Contenedor SELF (PS3/PS4): siempre cifrado/firmado -> se rechaza.
    Self_,
    /// XEX de Xbox 360 (reconocido, sin cargador).
    Xex,
    /// Imagen de disco ISO 9660: no es un ejecutable.
    Iso,
    /// ROM plana: requiere arquitectura, endianness y direccion base explicitas.
    Flat,
}

impl Format {
    /// Nombre usado en la CLI, la base de datos y el JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Elf => "elf",
            Format::Dol => "dol",
            Format::Pe => "pe",
            Format::Nso => "nso",
            Format::Self_ => "self",
            Format::Xex => "xex",
            Format::Iso => "iso",
            Format::Flat => "flat",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "elf" => Ok(Format::Elf),
            "dol" => Ok(Format::Dol),
            "pe" => Ok(Format::Pe),
            "nso" => Ok(Format::Nso),
            "self" => Ok(Format::Self_),
            "xex" => Ok(Format::Xex),
            "iso" => Ok(Format::Iso),
            "flat" => Ok(Format::Flat),
            other => {
                Err(format!("formato desconocido: '{other}' (elf|dol|pe|nso|self|xex|iso|flat)"))
            }
        }
    }
}
