//! Esquema SQLite del proyecto (capitulo 9 del Documento Maestro) y migraciones.
//!
//! El formato de proyecto es un unico archivo SQLite (ADR-003). La version del
//! esquema vive en `PRAGMA user_version`.
//!
//! Convenciones: nombres de tabla y columna en ingles (como en el SQL de ejemplo
//! del documento); direcciones como INTEGER (u64 reinterpretado como i64).

use crate::error::{Error, Result};
use rusqlite::Connection;

/// Version del esquema SQLite que entiende este binario.
pub const SCHEMA_VERSION: i64 = 3;

const MIGRATION_1: &str = r#"
CREATE TABLE project (
  id             INTEGER PRIMARY KEY CHECK (id = 1),   -- un archivo = un proyecto
  name           TEXT NOT NULL,
  platform       TEXT,
  architecture   TEXT,
  endian         TEXT,
  toolchain_id   TEXT,
  format         TEXT,
  bits           INTEGER,
  entry          INTEGER,
  binary_sha256  TEXT,
  binary_size    INTEGER,
  created_at     TEXT NOT NULL
);

CREATE TABLE module (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  progress    REAL NOT NULL DEFAULT 0
);

CREATE TABLE section (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL,
  start       INTEGER NOT NULL,
  size        INTEGER NOT NULL,
  perms       TEXT NOT NULL,
  file_offset INTEGER
);

CREATE TABLE function (
  id         INTEGER PRIMARY KEY,
  address    INTEGER NOT NULL UNIQUE,
  size       INTEGER NOT NULL,
  name       TEXT,
  state      TEXT NOT NULL DEFAULT 'detected'
             CHECK (state IN ('detected','named','decompiled','matched','portable','verified')),
  module_id  INTEGER REFERENCES module(id),
  hash       BLOB,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_function_state ON function(state);
CREATE INDEX idx_function_module ON function(module_id);

CREATE TABLE symbol (
  id      INTEGER PRIMARY KEY,
  address INTEGER NOT NULL,
  name    TEXT NOT NULL,
  kind    TEXT NOT NULL,
  origin  TEXT NOT NULL,
  UNIQUE (address, name)
);

CREATE TABLE "type" (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  category   TEXT NOT NULL,
  definition TEXT,
  size       INTEGER
);

CREATE TABLE xref (
  src  INTEGER NOT NULL,
  dst  INTEGER NOT NULL,
  kind TEXT NOT NULL,
  PRIMARY KEY (src, dst, kind)
);
CREATE INDEX idx_xref_dst ON xref(dst);

CREATE TABLE source (
  function_id INTEGER NOT NULL REFERENCES function(id),
  c_code      TEXT NOT NULL,
  version     INTEGER NOT NULL,
  author      TEXT NOT NULL,
  origin      TEXT NOT NULL CHECK (origin IN ('human','ai')),
  PRIMARY KEY (function_id, version)
);

CREATE TABLE match_attempt (
  id          INTEGER PRIMARY KEY,
  function_id INTEGER NOT NULL REFERENCES function(id),
  mutation    TEXT NOT NULL,
  score       REAL NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE ai_suggestion (
  id          INTEGER PRIMARY KEY,
  function_id INTEGER NOT NULL REFERENCES function(id),
  kind        TEXT NOT NULL CHECK (kind IN ('name','type','mutation','doc')),
  proposal    TEXT NOT NULL,
  confidence  REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','rejected')),
  created_at  TEXT NOT NULL
);

CREATE TABLE verification (
  id          INTEGER PRIMARY KEY,
  function_id INTEGER NOT NULL REFERENCES function(id),
  method      TEXT NOT NULL,
  result      TEXT NOT NULL CHECK (result IN ('pass','fail','inconclusive')),
  evidence    TEXT
);

-- Registro de auditoria inmutable (RNF-08, seccion 13.2).
CREATE TABLE audit_log (
  id         INTEGER PRIMARY KEY,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  detail     TEXT,
  created_at TEXT NOT NULL
);
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log es inmutable'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log es inmutable'); END;
"#;

/// v2: firma y comentarios importados desde herramientas de ingenieria inversa.
/// Los comentarios se guardan por direccion (funcion o instruccion) para no
/// duplicar el mismo texto en cada funcion que los contiene.
const MIGRATION_2: &str = r#"
ALTER TABLE function ADD COLUMN signature TEXT;

CREATE TABLE comment (
  address    INTEGER PRIMARY KEY,
  text       TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"#;

/// v3: grafo de flujo de control derivado del analisis. Cada instruccion
/// pertenece como mucho a un bloque, y cada bloque a una funcion (`ownership`).
const MIGRATION_3: &str = r#"
CREATE TABLE basic_block (
  id               INTEGER PRIMARY KEY,
  function_address INTEGER NOT NULL,
  address          INTEGER NOT NULL UNIQUE,
  size             INTEGER NOT NULL,
  instructions     INTEGER NOT NULL
);
CREATE INDEX idx_basic_block_function ON basic_block(function_address);
CREATE INDEX idx_basic_block_range ON basic_block(address, size);

CREATE TABLE cfg_edge (
  src  INTEGER NOT NULL,
  dst  INTEGER NOT NULL,
  kind TEXT NOT NULL
       CHECK (kind IN ('fallthrough','branch','jump','call','tail_call')),
  PRIMARY KEY (src, dst, kind)
);
CREATE INDEX idx_cfg_edge_dst ON cfg_edge(dst);
"#;

/// Version y SQL de cada migracion, en orden.
const MIGRATIONS: &[(i64, &str)] = &[(1, MIGRATION_1), (2, MIGRATION_2), (3, MIGRATION_3)];

/// Aplica las migraciones pendientes. Rechaza bases creadas por una version
/// mas nueva del programa.
pub fn migrate(conn: &Connection) -> Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(Error::Project(format!(
            "el proyecto usa el esquema v{current}, mas nuevo que el soportado (v{SCHEMA_VERSION}); \
             actualiza DecompForge"
        )));
    }
    for &(version, sql) in MIGRATIONS {
        if current < version {
            conn.execute_batch("BEGIN;")?;
            let res = conn
                .execute_batch(sql)
                .and_then(|_| conn.execute_batch(&format!("PRAGMA user_version = {version};")));
            match res {
                Ok(()) => conn.execute_batch("COMMIT;")?,
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    return Err(e.into());
                }
            }
        }
    }
    Ok(())
}
