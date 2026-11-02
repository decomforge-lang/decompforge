//! Construccion del paquete de contexto que recibe un proveedor de nombres.
//!
//! El paquete es deliberadamente pequeno: el Documento Maestro (§7.3) pide la
//! funcion, hasta cinco llamadores y llamados, cadenas y constantes cercanas,
//! estructuras tocadas y ejemplos de estilo. Esta primera version cubre lo que
//! ya esta en el proyecto (ensamblador, xrefs, cadenas y constantes) y deja las
//! estructuras para TypeForge (Fase 3/5).
//!
//! Topes: 200 instrucciones, 16 cadenas y 24 constantes por funcion. Un binario
//! hostil no puede inflar el prompt ni el consumo de memoria.

use super::{infer_case, NameCase, NameForgeConfig};
use crate::analysis::{Disassembler, Image};
use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use std::collections::BTreeSet;

/// Maximo de instrucciones que se incluyen en el contexto de una funcion.
pub const MAX_CONTEXT_INSTRUCTIONS: usize = 200;
/// Maximo de cadenas cercanas que se incluyen.
pub const MAX_CONTEXT_STRINGS: usize = 16;
/// Maximo de constantes distintas que se incluyen.
pub const MAX_CONTEXT_CONSTANTS: usize = 24;
/// Maximo de ejemplos de nombres aceptados que se incluyen.
pub const MAX_STYLE_EXAMPLES: usize = 5;
/// Bytes maximos que se escanean por region al buscar cadenas.
const MAX_STRING_SCAN_BYTES: usize = 256 * 1024;
/// Maximo de cadenas que se recuerdan de todo el binario.
const MAX_STRINGS: usize = 4096;
/// Longitud maxima de una cadena incluida en el contexto.
const MAX_STRING_LEN: usize = 120;

/// Una instruccion tal como se muestra en el contexto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstructionText {
    /// Direccion virtual.
    pub address: u64,
    /// Mnemonico y operandos, sin la direccion (se muestra aparte).
    pub text: String,
}

/// Llamador o llamado con su nombre actual.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NamedReference {
    /// Direccion de la funcion referida.
    pub address: u64,
    /// Nombre actual o `sub_<direccion>` si aun no tiene uno.
    pub name: String,
    /// El nombre lo aprobo una persona (no es el relleno `sub_...`).
    pub named: bool,
}

/// Cadena de texto cercana a la funcion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringReference {
    /// Direccion virtual donde empieza la cadena.
    pub address: u64,
    /// Contenido imprimible (sin el terminador).
    pub value: String,
}

/// Convenciones de estilo que acompanan al contexto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StyleContext {
    /// Estilo configurado para generar nombres.
    pub case: NameCase,
    /// Estilo mayoritario deducido de los nombres ya aprobados, si hay muestra.
    pub inferred_case: Option<NameCase>,
    /// Prefijo configurado.
    pub prefix: String,
    /// Ejemplos de nombres aprobados por personas.
    pub examples: Vec<String>,
}

/// Paquete de contexto de una funcion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionContext {
    /// Direccion de entrada.
    pub address: u64,
    /// Tamano de la envolvente de la funcion.
    pub size: u64,
    /// Nombre actual, si lo tiene.
    pub current_name: Option<String>,
    /// Estado de la funcion (`detected`, `named`, ...).
    pub state: String,
    /// Instrucciones de la funcion (hasta `MAX_CONTEXT_INSTRUCTIONS`).
    pub instructions: Vec<InstructionText>,
    /// Se omitieron instrucciones por el tope.
    pub instructions_truncated: bool,
    /// Funciones que llaman a esta.
    pub callers: Vec<NamedReference>,
    /// Funciones llamadas por esta.
    pub callees: Vec<NamedReference>,
    /// Cadenas cercanas, ordenadas por distancia.
    pub strings: Vec<StringReference>,
    /// Constantes inmediatas usadas por la funcion.
    pub constants: Vec<String>,
    /// Convenciones de estilo.
    pub style: StyleContext,
}

/// Recorre las regiones no ejecutables y recoge cadenas imprimibles.
///
/// Es una aproximacion honesta: el contexto las presenta como *cercanas*, no
/// como referenciadas. La seleccion final por distancia se hace en [`build`].
pub fn collect_strings(image: &Image<'_>) -> Vec<StringReference> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for region in image.regions() {
        if region.executable || out.len() >= MAX_STRINGS {
            continue;
        }
        let size = usize::try_from(region.size()).unwrap_or(usize::MAX).min(MAX_STRING_SCAN_BYTES);
        let Some(bytes) = image.read(region.start, size) else {
            continue;
        };
        let mut start = None;
        for (i, &byte) in bytes.iter().enumerate() {
            let printable = (0x20..=0x7E).contains(&byte);
            match (printable, start) {
                (true, None) => start = Some(i),
                (false, Some(s)) => {
                    if i - s >= 4 {
                        push_string(&mut out, &mut seen, region.start + s as u64, &bytes[s..i]);
                    }
                    start = None;
                }
                _ => {}
            }
            if out.len() >= MAX_STRINGS {
                break;
            }
        }
        if let Some(s) = start {
            if bytes.len() - s >= 4 {
                push_string(&mut out, &mut seen, region.start + s as u64, &bytes[s..]);
            }
        }
    }
    out
}

fn push_string(
    out: &mut Vec<StringReference>,
    seen: &mut BTreeSet<String>,
    address: u64,
    bytes: &[u8],
) {
    if bytes.len() > MAX_STRING_LEN {
        return;
    }
    let Ok(value) = std::str::from_utf8(bytes) else {
        return;
    };
    let value = value.trim().to_string();
    if value.is_empty() || !seen.insert(value.clone()) {
        return;
    }
    out.push(StringReference { address, value });
}

/// Construye el contexto de una funcion a partir de la base de datos y la
/// imagen materializada del binario.
pub fn build(
    conn: &Connection,
    image: &Image<'_>,
    dis: &Disassembler,
    strings: &[StringReference],
    examples: &[String],
    address: u64,
    config: &NameForgeConfig,
) -> Result<FunctionContext> {
    let (size, name, state): (i64, Option<String>, String) = conn
        .query_row(
            "SELECT size, name, state FROM function WHERE address = ?1",
            [address as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| {
            Error::NameForge(format!(
                "no hay ninguna funcion en 0x{address:x}; ejecuta `analyze` primero"
            ))
        })?;

    let blocks = function_blocks(conn, address, size as u64)?;
    let mut instructions = Vec::new();
    let mut constants = BTreeSet::new();
    let mut truncated = false;
    'outer: for (start, end) in blocks {
        let mut pc = start;
        while pc < end {
            if instructions.len() >= MAX_CONTEXT_INSTRUCTIONS {
                truncated = true;
                break 'outer;
            }
            let Some(insn) = dis.decode(image, pc)? else {
                break;
            };
            if insn.address >= end {
                break;
            }
            let text = format!("{} {}", insn.mnemonic, insn.op_str).trim().to_string();
            collect_constants(&insn.op_str, &mut constants);
            instructions.push(InstructionText { address: insn.address, text });
            pc = insn.end();
        }
    }

    let callers = references(conn, address, true)?;
    let callees = references(conn, address, false)?;

    let mut nearby: Vec<&StringReference> = strings.iter().collect();
    nearby.sort_by_key(|s| (s.address.abs_diff(address), s.address));
    let strings = nearby.into_iter().take(MAX_CONTEXT_STRINGS).cloned().collect::<Vec<_>>();

    Ok(FunctionContext {
        address,
        size: size as u64,
        current_name: name,
        state,
        instructions,
        instructions_truncated: truncated,
        callers,
        callees,
        strings,
        constants: constants
            .into_iter()
            .take(MAX_CONTEXT_CONSTANTS)
            .map(|v| format!("0x{v:x}"))
            .collect(),
        style: StyleContext {
            case: config.style.case,
            inferred_case: infer_case(examples),
            prefix: config.style.prefix.clone(),
            examples: examples.iter().take(MAX_STYLE_EXAMPLES).cloned().collect(),
        },
    })
}

/// Bloques de la funcion; si el CFG aun no existe, la envolvente completa.
fn function_blocks(conn: &Connection, address: u64, size: u64) -> Result<Vec<(u64, u64)>> {
    let mut st = conn.prepare(
        "SELECT address, size FROM basic_block WHERE function_address = ?1 ORDER BY address",
    )?;
    let mut blocks = st
        .query_map([address as i64], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if blocks.is_empty() && size > 0 {
        blocks.push((address, size));
    }
    Ok(blocks.into_iter().map(|(start, len)| (start, start.saturating_add(len))).collect())
}

/// Llamadores (`callers = true`) o llamados de una funcion, con su nombre.
fn references(conn: &Connection, address: u64, callers: bool) -> Result<Vec<NamedReference>> {
    let sql = if callers {
        "SELECT f.address, f.name FROM xref x JOIN function f ON f.address = x.src
         WHERE x.dst = ?1 AND x.kind = 'call' ORDER BY f.address"
    } else {
        "SELECT f.address, f.name FROM xref x JOIN function f ON f.address = x.dst
         WHERE x.src = ?1 AND x.kind = 'call' ORDER BY f.address"
    };
    let mut st = conn.prepare(sql)?;
    let rows = st.query_map([address as i64], |r| {
        let addr = r.get::<_, i64>(0)? as u64;
        let name: Option<String> = r.get(1)?;
        let named = name.is_some();
        Ok(NamedReference {
            address: addr,
            name: name.unwrap_or_else(|| format!("sub_{addr:08x}")),
            named,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn collect_constants(op_str: &str, out: &mut BTreeSet<u64>) {
    for token in op_str.split(|c: char| {
        c == ',' || c == '(' || c == ')' || c == '[' || c == ']' || c.is_whitespace()
    }) {
        let value = if let Some(hex) = token.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            token.parse::<u64>().ok()
        };
        if let Some(v) = value {
            if v >= 0x10 {
                out.insert(v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::NameForgeConfig;
    use super::*;
    use crate::analysis::Image;
    use crate::loader::Section;

    fn sec(name: &str, start: u64, perms: &str, off: Option<u64>) -> Section {
        Section { name: name.into(), start, size: 64, perms: perms.into(), file_offset: off }
    }

    #[test]
    fn strings_are_collected_only_from_non_executable_regions() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"code");
        let mut rodata = vec![0u8; 64];
        rodata[0..13].copy_from_slice(b"player_speed\0");
        let mut all = vec![0u8; 128];
        all[0..64].copy_from_slice(&data);
        all[64..128].copy_from_slice(&rodata);
        let sections =
            [sec(".text", 0x1000, "r-x", Some(0)), sec(".rodata", 0x2000, "r--", Some(64))];
        let img = Image::from_sections(&all, &sections);
        let strings = collect_strings(&img);
        assert!(strings.iter().any(|s| s.value == "player_speed"));
        assert!(!strings.iter().any(|s| s.value == "code"));
    }

    #[test]
    fn constants_are_deduplicated_and_ignore_small_values() {
        let mut set = BTreeSet::new();
        collect_constants("$t0, $t1, 0x10", &mut set);
        collect_constants("$t0, 0x10, 8", &mut set);
        assert_eq!(set.into_iter().collect::<Vec<_>>(), [0x10]);
    }

    #[test]
    fn a_missing_function_is_an_explicit_error() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::migrate(&conn).unwrap();
        let data = vec![0u8; 16];
        let sections = [sec(".text", 0x1000, "r-x", Some(0))];
        let img = Image::from_sections(&data, &sections);
        let dis = Disassembler::new(crate::Arch::Mips, crate::Endian::Little, 32).unwrap();
        let config = NameForgeConfig::default();
        let err = build(&conn, &img, &dis, &[], &[], 0x1000, &config).unwrap_err();
        assert!(matches!(err, Error::NameForge(_)));
    }
}
