//! Tipos de error del nucleo.
//!
//! Distinguimos tres familias de rechazo de un binario porque la interfaz
//! debe explicarlas de forma distinta al usuario:
//! * `Malformed`: el archivo esta truncado o corrupto.
//! * `Protected`: el archivo esta cifrado/firmado. DecompForge NO lo descifra
//!   ni elude la proteccion (ver ACCEPTABLE_USE.md).
//! * `Unsupported`: formato reconocido pero que aun no tiene cargador.

use thiserror::Error;

/// Resultado del nucleo con el error propio de DecompForge.
pub type Result<T> = std::result::Result<T, Error>;

/// Error del nucleo.
#[derive(Debug, Error)]
pub enum Error {
    /// El archivo esta truncado, corrupto o usa valores fuera de rango.
    #[error("archivo truncado o corrupto: {0}")]
    Malformed(String),

    /// Ningun cargador reconoce la cabecera y no se indico una ROM plana.
    #[error("formato no reconocido; si es una ROM plana indica --arch, --endian y --base")]
    UnknownFormat,

    /// Formato cifrado o firmado: DecompForge no lo descifra ni elude protecciones.
    #[error("formato protegido ({format}): {hint}")]
    Protected {
        /// Nombre del formato (p. ej. `SELF`).
        format: &'static str,
        /// Explicacion de por que se rechaza y que debe aportar el usuario.
        hint: String,
    },

    /// Formato reconocido que aun no tiene cargador o analizador.
    #[error("formato reconocido pero aun no soportado ({format}): {hint}")]
    Unsupported {
        /// Nombre del formato (p. ej. `XEX`).
        format: &'static str,
        /// Alternativa recomendada al usuario.
        hint: String,
    },

    /// Estado invalido del proyecto (p. ej. ya tiene un binario cargado).
    #[error("proyecto: {0}")]
    Project(String),

    /// El analisis no puede continuar con los datos aportados.
    #[error("analisis: {0}")]
    Analysis(String),

    /// Documento de intercambio JSON invalido o incompatible.
    #[error("intercambio JSON: {0}")]
    Exchange(String),

    /// Error de SQLite.
    #[error("base de datos: {0}")]
    Db(#[from] rusqlite::Error),

    /// Error de entrada/salida.
    #[error("entrada/salida: {0}")]
    Io(#[from] std::io::Error),

    /// Error de serializacion o deserializacion JSON.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub(crate) fn malformed(msg: impl Into<String>) -> Self {
        Error::Malformed(msg.into())
    }
}
