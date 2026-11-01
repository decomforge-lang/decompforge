//! Proyecto de DecompForge: un archivo SQLite con el estado verdadero del
//! trabajo (secciones, simbolos, funciones, tipos, auditoria).

use crate::analysis::{self, AnalysisOptions, AnalysisSummary, Image};
use crate::arch::{Arch, Endian};
use crate::db;
use crate::error::{Error, Result};
use crate::loader::{self, LoadOptions, LoadedBinary, Section};
use crate::timeutil::now_iso;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Version del formato de intercambio JSON (ver schemas/).
pub const EXCHANGE_SCHEMA_VERSION: &str = "1.0";

/// Version del documento de intercambio con herramientas de RE (Ghidra, IDA,
/// Binary Ninja). Ver `schemas/decompforge-re-1.0.schema.json`.
pub const RE_SCHEMA_VERSION: &str = "re-1.0";

/// Proyecto abierto: una conexion SQLite con el estado del trabajo.
pub struct Project {
    conn: Connection,
}

/// Campos de `project` necesarios para reanalizar sin guardar el binario.
type BinaryState = (Option<String>, Option<String>, Option<i64>, Option<i64>, Option<String>);

/// Resumen del estado del proyecto para `decompforge info`.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectInfo {
    /// Nombre del proyecto.
    pub name: String,
    /// Plataforma objetivo (p. ej. `ps2`), si se indico.
    pub platform: Option<String>,
    /// Hay un binario importado.
    pub loaded: bool,
    /// Formato del binario (`elf`, `dol`, ...).
    pub format: Option<String>,
    /// Arquitectura detectada.
    pub architecture: Option<String>,
    /// Orden de bytes detectado.
    pub endian: Option<String>,
    /// Ancho de palabra en bits.
    pub bits: Option<u8>,
    /// Punto de entrada.
    pub entry: Option<u64>,
    /// SHA-256 del binario importado.
    pub binary_sha256: Option<String>,
    /// Tamano del binario en bytes.
    pub binary_size: Option<u64>,
    /// Numero de secciones.
    pub sections: u64,
    /// Numero de simbolos.
    pub symbols: u64,
    /// Numero de funciones.
    pub functions: u64,
    /// Numero de funciones por estado (detected, named, ...).
    pub functions_by_state: BTreeMap<String, u64>,
}

/// Resultado de aplicar un documento `re-1.0` de tipo `updates`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateSummary {
    /// Funciones distintas afectadas.
    pub functions: u64,
    /// Nombres aplicados.
    pub names: u64,
    /// Firmas aplicadas.
    pub signatures: u64,
    /// Comentarios insertados o reemplazados.
    pub comments: u64,
}

/// Campos validados de una actualizacion, antes de tocar la base de datos.
struct PendingUpdate {
    address: u64,
    name: Option<String>,
    signature: Option<String>,
    comments: Vec<(u64, String)>,
}

fn parse_exchange_addr(s: &str) -> Result<u64> {
    let Some(h) = s.strip_prefix("0x") else {
        return Err(Error::Exchange(format!("direccion sin prefijo 0x: '{s}'")));
    };
    let valid = !h.is_empty()
        && h.len() <= 16
        && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !valid {
        return Err(Error::Exchange(format!(
            "direccion invalida: '{s}' (se espera 0x seguido de 1-16 digitos hexadecimales en minusculas)"
        )));
    }
    u64::from_str_radix(h, 16)
        .map_err(|e| Error::Exchange(format!("direccion fuera de rango '{s}': {e}")))
}

fn required_str<'a>(obj: &'a Value, key: &str, what: &str) -> Result<&'a str> {
    obj.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Exchange(format!("{what}: falta el campo de texto '{key}'")))
}

fn non_empty(value: &str, what: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::Exchange(format!("{what} no puede estar vacio")));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(Error::Exchange(format!("{what} contiene caracteres de control")));
    }
    Ok(trimmed.to_string())
}

/// Valida un documento `updates` completo antes de escribir nada.
fn parse_updates(doc: &Value) -> Result<Vec<PendingUpdate>> {
    let version = doc.get("schema_version").and_then(Value::as_str);
    if version != Some(RE_SCHEMA_VERSION) {
        return Err(Error::Exchange(format!(
            "schema_version debe ser \"{RE_SCHEMA_VERSION}\", no {version:?}"
        )));
    }
    let kind = doc.get("kind").and_then(Value::as_str);
    if kind != Some("updates") {
        return Err(Error::Exchange(format!("se esperaba kind=\"updates\", no {kind:?}")));
    }
    let raw = doc
        .get("functions")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Exchange("falta el array 'functions'".into()))?;

    let mut pending: Vec<PendingUpdate> = Vec::with_capacity(raw.len());
    let mut seen = BTreeSet::new();
    for (i, item) in raw.iter().enumerate() {
        let ctx = format!("functions[{i}]");
        let address = parse_exchange_addr(required_str(item, "address", &ctx)?)?;
        if !seen.insert(address) {
            return Err(Error::Exchange(format!("{ctx}: direccion duplicada 0x{address:x}")));
        }
        let name = match item.get("name") {
            None => None,
            Some(v) => {
                let s = v
                    .as_str()
                    .ok_or_else(|| Error::Exchange(format!("{ctx}.name debe ser texto")))?;
                let s = non_empty(s, &format!("{ctx}.name"))?;
                if s.chars().any(char::is_whitespace) {
                    return Err(Error::Exchange(format!("{ctx}.name no puede contener espacios")));
                }
                Some(s)
            }
        };
        let signature = match item.get("signature") {
            None => None,
            Some(v) => {
                let s = v
                    .as_str()
                    .ok_or_else(|| Error::Exchange(format!("{ctx}.signature debe ser texto")))?;
                Some(non_empty(s, &format!("{ctx}.signature"))?)
            }
        };
        let mut comments = Vec::new();
        if let Some(list) = item.get("comments") {
            let list = list
                .as_array()
                .ok_or_else(|| Error::Exchange(format!("{ctx}.comments debe ser un array")))?;
            for (j, c) in list.iter().enumerate() {
                let cctx = format!("{ctx}.comments[{j}]");
                let caddr = parse_exchange_addr(required_str(c, "address", &cctx)?)?;
                let text = required_str(c, "text", &cctx)?;
                comments.push((caddr, non_empty(text, &format!("{cctx}.text"))?));
            }
        }
        if name.is_none() && signature.is_none() && comments.is_empty() {
            return Err(Error::Exchange(format!(
                "{ctx}: incluye al menos name, signature o comments"
            )));
        }
        pending.push(PendingUpdate { address, name, signature, comments });
    }
    Ok(pending)
}

fn valid_kind(kind: &str) -> bool {
    let mut chars = kind.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn slug_kind(kind: &str) -> String {
    let mut out = String::new();
    for c in kind.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "other".into()
    } else if out.starts_with(|c: char| c.is_ascii_alphabetic()) {
        out
    } else {
        format!("type_{out}")
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0xF) as usize] as char);
    }
    out
}

fn addr(a: u64) -> String {
    format!("0x{a:08x}")
}

impl Project {
    /// Crea un proyecto nuevo. Falla si el archivo ya existe.
    pub fn create(path: &Path, name: &str, platform: Option<&str>) -> Result<Self> {
        if path.exists() {
            return Err(Error::Project(format!("{} ya existe", path.display())));
        }
        let conn = Connection::open(path)?;
        Self::init(conn, name, platform)
    }

    /// Proyecto en memoria (pruebas y datos sinteticos efimeros).
    pub fn in_memory(name: &str, platform: Option<&str>) -> Result<Self> {
        Self::init(Connection::open_in_memory()?, name, platform)
    }

    fn init(conn: Connection, name: &str, platform: Option<&str>) -> Result<Self> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Project("el nombre del proyecto no puede estar vacio".into()));
        }
        conn.pragma_update(None, "foreign_keys", true)?;
        db::migrate(&conn)?;
        conn.execute(
            "INSERT INTO project (id, name, platform, created_at) VALUES (1, ?1, ?2, ?3)",
            params![name, platform, now_iso()],
        )?;
        conn.execute(
            "INSERT INTO audit_log (actor, action, detail, created_at) VALUES ('system','init',?1,?2)",
            params![name, now_iso()],
        )?;
        Ok(Project { conn })
    }

    /// Abre un `.dfproj` existente y aplica las migraciones pendientes.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_file() {
            return Err(Error::Project(format!("{} no existe", path.display())));
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        db::migrate(&conn)?;
        let has_project: Option<i64> =
            conn.query_row("SELECT id FROM project WHERE id = 1", [], |r| r.get(0)).optional()?;
        if has_project.is_none() {
            return Err(Error::Project(format!(
                "{} no es un proyecto de DecompForge",
                path.display()
            )));
        }
        Ok(Project { conn })
    }

    /// Acceso de solo lectura a la conexion (pruebas e integraciones).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Carga el binario aportado por el usuario y registra secciones y punto
    /// de entrada. Todo o nada: si algo falla, el proyecto queda intacto.
    pub fn import_binary(
        &mut self,
        data: &[u8],
        opts: &LoadOptions,
        actor: &str,
    ) -> Result<LoadedBinary> {
        let already: Option<String> =
            self.conn
                .query_row("SELECT binary_sha256 FROM project WHERE id = 1", [], |r| r.get(0))?;
        if already.is_some() {
            return Err(Error::Project(
                "el proyecto ya tiene un binario cargado; crea otro proyecto para otro binario"
                    .into(),
            ));
        }
        // Antes de tocar la base de datos: si el formato se rechaza, no pasa nada.
        let bin = loader::load(data, opts)?;
        let sha = hex(&Sha256::digest(data));
        let now = now_iso();

        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE project SET architecture=?1, endian=?2, format=?3, bits=?4, entry=?5,
                    binary_sha256=?6, binary_size=?7 WHERE id = 1",
            params![
                bin.arch.as_str(),
                bin.endian.as_str(),
                bin.format.as_str(),
                bin.bits,
                bin.entry.map(|e| e as i64),
                sha,
                data.len() as i64
            ],
        )?;
        for s in &bin.sections {
            tx.execute(
                "INSERT INTO section (name, start, size, perms, file_offset) VALUES (?1,?2,?3,?4,?5)",
                params![s.name, s.start as i64, s.size as i64, s.perms, s.file_offset.map(|o| o as i64)],
            )?;
        }
        if let Some(e) = bin.entry {
            tx.execute(
                "INSERT INTO symbol (address, name, kind, origin) VALUES (?1,'_entry','entry','loader')",
                params![e as i64],
            )?;
        }
        tx.execute(
            "INSERT INTO audit_log (actor, action, detail, created_at) VALUES (?1,'load',?2,?3)",
            params![actor, format!("{} {} bytes sha256={}", bin.format, data.len(), sha), now],
        )?;
        tx.commit()?;
        Ok(bin)
    }

    /// Analiza el binario aportado y persiste funciones y llamadas.
    ///
    /// El proyecto no guarda el binario (ADR-009): hay que volver a aportarlo y
    /// su SHA-256 debe coincidir con el cargado. La reejecucion es idempotente:
    /// conserva nombres, estados y hashes de las funciones existentes y
    /// regenera solo las aristas de llamada de las funciones analizadas.
    pub fn analyze(&mut self, data: &[u8], actor: &str) -> Result<AnalysisSummary> {
        let (arch_text, endian_text, bits, entry, expected): BinaryState = self.conn.query_row(
            "SELECT architecture, endian, bits, entry, binary_sha256 FROM project WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let Some(expected) = expected else {
            return Err(Error::Project(
                "no hay binario cargado; usa `decompforge load <binario>` primero".into(),
            ));
        };
        let actual = hex(&Sha256::digest(data));
        if actual != expected {
            return Err(Error::Analysis(format!(
                "el binario no coincide con el cargado (sha256 {actual}, esperado {expected}); \
                 aporta exactamente el mismo archivo"
            )));
        }
        let arch = match arch_text.as_deref() {
            Some(s) if s != "unknown" => s
                .parse::<Arch>()
                .map_err(|e| Error::Analysis(format!("arquitectura del proyecto: {e}")))?,
            _ => {
                return Err(Error::Unsupported {
                    format: "desconocido",
                    hint: "el binario no declara una arquitectura que Capstone pueda desensamblar"
                        .into(),
                })
            }
        };
        let endian = endian_text
            .as_deref()
            .unwrap_or("little")
            .parse::<Endian>()
            .map_err(|e| Error::Analysis(format!("endianness del proyecto: {e}")))?;
        let bits = match bits {
            Some(b) => u8::try_from(b)
                .map_err(|_| Error::Analysis(format!("numero de bits invalido: {b}")))?,
            None => return Err(Error::Analysis("el proyecto no indica el numero de bits".into())),
        };
        let entry = entry.and_then(|e| u64::try_from(e).ok());

        let mut sections = Vec::new();
        {
            let mut st = self.conn.prepare(
                "SELECT name, start, size, perms, file_offset FROM section ORDER BY start, id",
            )?;
            for row in st.query_map([], |r| {
                Ok(Section {
                    name: r.get::<_, String>(0)?,
                    start: r.get::<_, i64>(1)? as u64,
                    size: r.get::<_, i64>(2)? as u64,
                    perms: r.get::<_, String>(3)?,
                    file_offset: r.get::<_, Option<i64>>(4)?.map(|o| o as u64),
                })
            })? {
                sections.push(row?);
            }
        }

        let image = Image::from_sections(data, &sections);
        let mut seeds: BTreeSet<u64> = BTreeSet::new();
        if let Some(e) = entry {
            if image.is_executable(e) {
                seeds.insert(e);
            }
        }
        // Sin entrada (ROM plana, ELF sin simbolos) el comienzo de cada region
        // ejecutable es una semilla razonable.
        for r in image.regions() {
            if r.executable {
                seeds.insert(r.start);
            }
        }
        {
            let mut st = self.conn.prepare("SELECT address FROM symbol ORDER BY address")?;
            for row in st.query_map([], |r| Ok(r.get::<_, i64>(0)? as u64))? {
                let a = row?;
                if image.is_executable(a) {
                    seeds.insert(a);
                }
            }
        }
        {
            let mut st = self.conn.prepare("SELECT address FROM function ORDER BY address")?;
            for row in st.query_map([], |r| Ok(r.get::<_, i64>(0)? as u64))? {
                let a = row?;
                if image.is_executable(a) {
                    seeds.insert(a);
                }
            }
        }

        let seed_list: Vec<u64> = seeds.into_iter().collect();
        let result =
            analysis::analyze(&image, arch, endian, bits, &seed_list, &AnalysisOptions::default())?;

        let tx = self.conn.transaction()?;
        let now = now_iso();
        for f in &result.functions {
            tx.execute(
                "INSERT INTO function (address, size, name, state, hash, updated_at)
                 VALUES (?1, ?2, NULL, 'detected', NULL, ?3)
                 ON CONFLICT(address) DO UPDATE SET
                     size = excluded.size,
                     updated_at = excluded.updated_at",
                params![f.address as i64, f.size as i64, now],
            )?;
            // Solo se regeneran las llamadas de las funciones analizadas; los
            // nombres, estados y hashes existentes no se tocan.
            tx.execute(
                "DELETE FROM xref WHERE src = ?1 AND kind = 'call'",
                params![f.address as i64],
            )?;
        }
        for e in &result.call_edges {
            tx.execute(
                "INSERT OR IGNORE INTO xref (src, dst, kind) VALUES (?1, ?2, 'call')",
                params![e.src as i64, e.dst as i64],
            )?;
        }
        let summary = result.summary();
        tx.execute(
            "INSERT INTO audit_log (actor, action, detail, created_at) VALUES (?1, 'analyze', ?2, ?3)",
            params![
                actor,
                format!(
                    "{} funciones, {} instrucciones, {} llamadas, truncado={}",
                    summary.functions, summary.instructions, summary.call_edges, summary.truncated
                ),
                now
            ],
        )?;
        tx.commit()?;
        Ok(summary)
    }

    /// Recopila el resumen del proyecto que muestra `decompforge info`.
    pub fn info(&self) -> Result<ProjectInfo> {
        let count = |table: &str| -> Result<u64> {
            Ok(self
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0))?
                as u64)
        };
        let mut info = self.conn.query_row(
            "SELECT name, platform, format, architecture, endian, bits, entry, binary_sha256, binary_size
             FROM project WHERE id = 1",
            [],
            |r| {
                let sha: Option<String> = r.get(7)?;
                Ok(ProjectInfo {
                    name: r.get(0)?,
                    platform: r.get(1)?,
                    loaded: sha.is_some(),
                    format: r.get(2)?,
                    architecture: r.get(3)?,
                    endian: r.get(4)?,
                    bits: r.get(5)?,
                    entry: r.get::<_, Option<i64>>(6)?.map(|e| e as u64),
                    binary_sha256: sha,
                    binary_size: r.get::<_, Option<i64>>(8)?.map(|s| s as u64),
                    sections: 0,
                    symbols: 0,
                    functions: 0,
                    functions_by_state: BTreeMap::new(),
                })
            },
        )?;
        info.sections = count("section")?;
        info.symbols = count("symbol")?;
        info.functions = count("function")?;
        let mut st = self.conn.prepare("SELECT state, COUNT(*) FROM function GROUP BY state")?;
        let rows =
            st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)))?;
        for row in rows {
            let (s, n) = row?;
            info.functions_by_state.insert(s, n);
        }
        Ok(info)
    }

    /// Exporta al formato de intercambio JSON (seccion 9.4 del documento).
    /// Determinista: no incluye marcas de tiempo y ordena todo (RNF-02).
    pub fn export_json(&self) -> Result<Value> {
        let info = self.info()?;

        let mut sections = Vec::new();
        let mut st = self.conn.prepare(
            "SELECT name, start, size, perms, file_offset FROM section ORDER BY start, id",
        )?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?.map(|o| o as u64),
            ))
        })? {
            let (name, start, size, perms, off) = row?;
            sections.push(json!({
                "name": name, "start": addr(start), "size": size, "perms": perms,
                "file_offset": off,
            }));
        }

        let mut symbols = Vec::new();
        let mut st = self
            .conn
            .prepare("SELECT address, name, kind, origin FROM symbol ORDER BY address, name")?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })? {
            let (a, name, kind, origin) = row?;
            symbols.push(json!({"address": addr(a), "name": name, "kind": kind, "origin": origin}));
        }

        let mut functions = Vec::new();
        let mut st = self
            .conn
            .prepare("SELECT id, address, size, name, state FROM function ORDER BY address")?;
        let mut calls = self
            .conn
            .prepare("SELECT dst FROM xref WHERE src = ?1 AND kind = 'call' ORDER BY dst")?;
        for row in st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
            ))
        })? {
            let (a, size, name, state) = row?;
            let callees: Vec<String> = calls
                .query_map([a as i64], |r| Ok(addr(r.get::<_, i64>(0)? as u64)))?
                .collect::<std::result::Result<_, _>>()?;
            functions.push(json!({
                "address": addr(a), "size": size, "name": name, "state": state, "calls": callees,
            }));
        }

        Ok(json!({
            "schema_version": EXCHANGE_SCHEMA_VERSION,
            "project": {
                "name": info.name,
                "platform": info.platform,
                "arch": info.architecture,
                "endian": info.endian,
                "format": info.format,
                "bits": info.bits,
                "entry": info.entry.map(addr),
                "binary_sha256": info.binary_sha256,
            },
            "sections": sections,
            "symbols": symbols,
            "functions": functions,
        }))
    }

    /// Aplica un documento `re-1.0` de tipo `updates` (nombres, firmas y
    /// comentarios) al proyecto.
    ///
    /// Todo o nada: primero se valida el documento completo y que cada funcion
    /// exista; si algo falla no se escribe nada. Renombrar una funcion en estado
    /// `detected` la pasa a `named`; los estados posteriores se conservan. Los
    /// comentarios se guardan por direccion, asi que sirven para funciones e
    /// instrucciones.
    pub fn apply_updates(&mut self, doc: &Value, actor: &str) -> Result<UpdateSummary> {
        let pending = parse_updates(doc)?;
        for u in &pending {
            let exists: Option<i64> = self
                .conn
                .query_row(
                    "SELECT 1 FROM function WHERE address = ?1",
                    params![u.address as i64],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(Error::Exchange(format!(
                    "no hay ninguna funcion en 0x{:x}; ejecuta `analyze` o revisa el documento",
                    u.address
                )));
            }
        }

        let now = now_iso();
        let mut summary =
            UpdateSummary { functions: pending.len() as u64, names: 0, signatures: 0, comments: 0 };
        let tx = self.conn.transaction()?;
        for u in &pending {
            if let Some(name) = &u.name {
                tx.execute(
                    "UPDATE function SET name = ?1,
                            state = CASE WHEN state = 'detected' THEN 'named' ELSE state END,
                            updated_at = ?2
                     WHERE address = ?3",
                    params![name, now, u.address as i64],
                )?;
                summary.names += 1;
            }
            if let Some(signature) = &u.signature {
                tx.execute(
                    "UPDATE function SET signature = ?1, updated_at = ?2 WHERE address = ?3",
                    params![signature, now, u.address as i64],
                )?;
                summary.signatures += 1;
            }
            for (caddr, text) in &u.comments {
                tx.execute(
                    "INSERT INTO comment (address, text, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(address) DO UPDATE SET text = excluded.text,
                                                       updated_at = excluded.updated_at",
                    params![*caddr as i64, text, now],
                )?;
                summary.comments += 1;
            }
        }
        tx.execute(
            "INSERT INTO audit_log (actor, action, detail, created_at) VALUES (?1, 'apply', ?2, ?3)",
            params![
                actor,
                format!(
                    "{} funciones, {} nombres, {} firmas, {} comentarios",
                    summary.functions, summary.names, summary.signatures, summary.comments
                ),
                now
            ],
        )?;
        tx.commit()?;
        Ok(summary)
    }

    /// Exporta el proyecto como documento `re-1.0` de tipo `export`, listo para
    /// que un plugin de Ghidra/IDA lo importe.
    ///
    /// Incluye funciones (con firma y comentarios), referencias cruzadas y
    /// tipos. No incluye ensamblador ni marcas de tiempo: las instrucciones las
    /// aporta la herramienta de RE, y omitir `generated_at` mantiene el
    /// resultado determinista (RNF-02).
    pub fn export_re_json(&self) -> Result<Value> {
        let info = self.info()?;
        let arch = info
            .architecture
            .as_deref()
            .ok_or_else(|| Error::Exchange("no hay binario cargado; importa uno primero".into()))?;
        let endian = info
            .endian
            .as_deref()
            .ok_or_else(|| Error::Exchange("el proyecto no indica el orden de bytes".into()))?;

        let mut functions = Vec::new();
        {
            let mut st = self
                .conn
                .prepare("SELECT address, size, name, signature FROM function ORDER BY address")?;
            let rows = st.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })?;
            for row in rows {
                let (a, size, name, signature) = row?;
                let mut comments = Vec::new();
                let end = a.saturating_add(size.max(1));
                let mut cs = self.conn.prepare(
                    "SELECT address, text FROM comment WHERE address >= ?1 AND address < ?2
                     ORDER BY address",
                )?;
                for c in cs.query_map(params![a as i64, end as i64], |r| {
                    Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
                })? {
                    let (ca, text) = c?;
                    comments.push(json!({"address": addr(ca), "text": text}));
                }
                let mut f = json!({
                    "address": addr(a),
                    "name": name.unwrap_or_else(|| format!("sub_{a:08x}")),
                    "size": size,
                });
                if let Some(sig) = signature {
                    f["signature"] = Value::String(sig);
                }
                if !comments.is_empty() {
                    f["comments"] = Value::Array(comments);
                }
                functions.push(f);
            }
        }

        let mut xrefs = Vec::new();
        {
            let mut st =
                self.conn.prepare("SELECT src, dst, kind FROM xref ORDER BY src, dst, kind")?;
            for row in st.query_map([], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64, r.get::<_, String>(2)?))
            })? {
                let (src, dst, kind) = row?;
                if valid_kind(&kind) {
                    xrefs.push(json!({"src": addr(src), "dst": addr(dst), "kind": kind}));
                }
            }
        }

        let mut types = Vec::new();
        {
            let mut st = self
                .conn
                .prepare("SELECT name, category, size, definition FROM \"type\" ORDER BY name")?;
            for row in st.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })? {
                let (name, category, size, definition) = row?;
                let mut t = json!({"name": name, "kind": slug_kind(&category)});
                if let Some(s) = size {
                    t["size"] = json!(s);
                }
                if let Some(d) = definition {
                    t["definition"] = Value::String(d);
                }
                types.push(t);
            }
        }

        // `bits` y `entry` son opcionales en el esquema: se omiten si el
        // proyecto no los conoce, en lugar de escribir `null`.
        let mut project = json!({
            "name": info.name,
            "arch": arch,
            "endian": endian,
        });
        if let Some(bits) = info.bits {
            project["bits"] = json!(bits);
        }
        if let Some(entry) = info.entry {
            project["entry"] = Value::String(addr(entry));
        }

        Ok(json!({
            "schema_version": RE_SCHEMA_VERSION,
            "kind": "export",
            "source": {
                "tool": "decompforge",
                "version": env!("CARGO_PKG_VERSION"),
                "program": info.name,
            },
            "project": project,
            "functions": functions,
            "xrefs": xrefs,
            "types": types,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_vector() {
        // Vector estandar FIPS 180-2: SHA-256("abc").
        assert_eq!(
            hex(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(addr(0x1234), "0x00001234");
        assert_eq!(addr(0x1_4000_1000), "0x140001000");
    }
}
