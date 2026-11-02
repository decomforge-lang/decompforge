//! NameForge: propuestas de nombres con confianza y justificacion (RF-04).
//!
//! El modulo separa tres responsabilidades:
//!
//! 1. **Contexto** ([`FunctionContext`]): instantaneas acotadas de una funcion
//!    (ensamblador, llamadores, llamados, cadenas y constantes cercanas) para
//!    que un proveedor de IA pueda razonar sin recibir el binario completo.
//! 2. **Proveedor** ([`NameProvider`]): heuristica local determinista o un
//!    comando externo (por ejemplo, el servicio Python de `ai/`). El contrato
//!    es JSON por *stdin*/*stdout* y se valida antes de guardar nada.
//! 3. **Estilo** ([`NameForgeConfig`]): convenciones del proyecto (snake_case,
//!    camelCase o PascalCase, prefijo y nombres vetados) y ejemplos de nombres
//!    ya aceptados.
//!
//! La IA propone; el sistema no cambia ningun nombre. `Project` guarda las
//! propuestas y solo `accept_suggestion` aplica una, con confirmacion explicita
//! si la funcion ya tenia un nombre aprobado.

mod context;
mod heuristic;

pub use context::{
    build as build_context, collect_strings, FunctionContext, InstructionText, NamedReference,
    StringReference, StyleContext,
};
pub use heuristic::HeuristicProvider;

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Version del contrato JSON que recibe un proveedor externo de NameForge.
pub const PROVIDER_SCHEMA_VERSION: &str = "nameforge-1.0";

/// Maximo de propuestas que puede devolver un proveedor.
pub const MAX_SUGGESTIONS: usize = 3;

/// Longitud maxima por defecto de un identificador propuesto.
pub const DEFAULT_MAX_LENGTH: usize = 64;

/// Estilo de nombres del proyecto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameCase {
    /// `player_speed` (estilo por defecto).
    #[default]
    Snake,
    /// `playerSpeed`.
    Camel,
    /// `PlayerSpeed`.
    Pascal,
}

impl NameCase {
    /// Nombre estable que se guarda en la configuracion y se muestra al usuario.
    pub fn as_str(self) -> &'static str {
        match self {
            NameCase::Snake => "snake_case",
            NameCase::Camel => "camelCase",
            NameCase::Pascal => "PascalCase",
        }
    }
}

impl fmt::Display for NameCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Convenciones de nombrado configurables por el proyecto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StyleConfig {
    /// Estilo de los identificadores.
    pub case: NameCase,
    /// Prefijo comun (p. ej. `g` o `player`); se aplica como primera palabra.
    pub prefix: String,
    /// Nombres que nunca se deben proponer (comparacion sin distinguir mayusculas).
    pub banned: Vec<String>,
    /// Longitud maxima de un identificador.
    pub max_length: usize,
}

impl Default for StyleConfig {
    fn default() -> Self {
        StyleConfig {
            case: NameCase::Snake,
            prefix: String::new(),
            banned: Vec::new(),
            max_length: DEFAULT_MAX_LENGTH,
        }
    }
}

impl StyleConfig {
    /// Valida los valores de la configuracion.
    pub fn validate(&self) -> Result<()> {
        if !(8..=128).contains(&self.max_length) {
            return Err(Error::NameForge(format!(
                "style.max_length debe estar entre 8 y 128 (valor: {})",
                self.max_length
            )));
        }
        if !self.prefix.is_empty() && split_identifier_words(&self.prefix).is_empty() {
            return Err(Error::NameForge(format!(
                "style.prefix no es un identificador valido: {:?}",
                self.prefix
            )));
        }
        for name in &self.banned {
            if name.trim().is_empty() {
                return Err(Error::NameForge("style.banned no admite entradas vacias".into()));
            }
        }
        Ok(())
    }

    /// Convierte palabras sueltas en un identificador con el estilo configurado.
    ///
    /// Devuelve `None` si no queda ninguna palabra valida o si el nombre supera
    /// `max_length` incluso despues de recortar por palabras.
    pub fn make_name(&self, words: &[String]) -> Option<String> {
        let mut all: Vec<String> = Vec::new();
        if !self.prefix.is_empty() {
            all.extend(split_identifier_words(&self.prefix));
        }
        all.extend(
            words
                .iter()
                .map(|w| w.trim().to_ascii_lowercase())
                .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_alphanumeric())),
        );
        if all.is_empty() {
            return None;
        }

        loop {
            let name = match self.case {
                NameCase::Snake => all.join("_"),
                NameCase::Camel => {
                    let mut out = String::new();
                    for (i, word) in all.iter().enumerate() {
                        if i == 0 {
                            out.push_str(word);
                        } else {
                            out.push_str(&capitalize(word));
                        }
                    }
                    out
                }
                NameCase::Pascal => all.iter().map(|w| capitalize(w)).collect::<String>(),
            };
            if name.len() <= self.max_length {
                let banned = self.banned.iter().any(|b| b.eq_ignore_ascii_case(&name));
                return if banned { None } else { Some(name) };
            }
            if all.len() == 1 {
                return None;
            }
            all.pop();
        }
    }
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Divide un identificador o una cadena en palabras normalizadas.
///
/// Acepta `player_speed`, `playerSpeed`, `Player Speed` y `player-speed`.
/// Se descartan separadores no alfanumericos y se limita el resultado a cuatro
/// palabras para no generar nombres kilometricos.
pub(crate) fn split_identifier_words(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.trim().chars().collect();
    let mut separated = String::with_capacity(value.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_ascii_alphanumeric() {
            if i > 0 {
                let prev = chars[i - 1];
                let split = c.is_ascii_uppercase()
                    && (prev.is_ascii_lowercase()
                        || (prev.is_ascii_uppercase()
                            && i + 1 < chars.len()
                            && chars[i + 1].is_ascii_lowercase()));
                if split {
                    separated.push(' ');
                }
            }
            separated.push(c);
        } else {
            separated.push(' ');
        }
    }
    separated
        .split_whitespace()
        .filter(|w| !w.is_empty())
        .take(4)
        .map(|w| w.to_ascii_lowercase())
        .filter(|w| w.len() <= 24)
        .collect()
}

/// Indica si `name` es un identificador valido para `max_length`.
pub(crate) fn is_valid_identifier(name: &str, max_length: usize) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= max_length
        && (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Deduce el estilo mayoritario de una lista de nombres aprobados.
///
/// Devuelve `None` si no hay al menos dos ejemplos claros: una sola funcion no
/// basta para cambiar las convenciones del proyecto.
pub fn infer_case(names: &[String]) -> Option<NameCase> {
    let mut counts = [0usize; 3];
    for name in names {
        let mut chars = name.chars();
        let Some(first) = chars.next() else { continue };
        let has_upper = name.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
        if name.contains('_') && !has_upper {
            counts[0] += 1;
        } else if first.is_ascii_lowercase() && has_upper {
            counts[1] += 1;
        } else if first.is_ascii_uppercase() && has_lower {
            counts[2] += 1;
        }
    }
    let max = *counts.iter().max()?;
    if max < 2 {
        return None;
    }
    Some(if counts[0] == max {
        NameCase::Snake
    } else if counts[1] == max {
        NameCase::Camel
    } else {
        NameCase::Pascal
    })
}

/// Configuracion del proveedor de propuestas.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderConfig {
    /// Heuristica local determinista (sin red ni procesos externos).
    #[default]
    Heuristic,
    /// Comando externo que lee el contexto JSON por *stdin* y responde por
    /// *stdout* con `{"suggestions": [...]}`.
    Command {
        /// Programa y argumentos; el primero debe existir en el `PATH`.
        argv: Vec<String>,
        /// Tiempo maximo de espera antes de matar el proceso.
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
}

fn default_timeout() -> u64 {
    60
}

impl ProviderConfig {
    fn validate(&self) -> Result<()> {
        match self {
            ProviderConfig::Heuristic => Ok(()),
            ProviderConfig::Command { argv, timeout_secs } => {
                if argv.is_empty() || argv[0].trim().is_empty() {
                    return Err(Error::NameForge(
                        "provider.argv no puede estar vacio cuando kind = command".into(),
                    ));
                }
                if !(1..=600).contains(timeout_secs) {
                    return Err(Error::NameForge(format!(
                        "provider.timeout_secs debe estar entre 1 y 600 (valor: {timeout_secs})"
                    )));
                }
                Ok(())
            }
        }
    }
}

/// Configuracion completa de NameForge (estilo + proveedor).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NameForgeConfig {
    /// Convenciones de nombrado.
    pub style: StyleConfig,
    /// Proveedor de propuestas.
    pub provider: ProviderConfig,
}

impl NameForgeConfig {
    /// Valida la configuracion completa.
    pub fn validate(&self) -> Result<()> {
        self.style.validate()?;
        self.provider.validate()
    }

    /// Carga y valida un archivo JSON de configuracion.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::NameForge(format!("no se pudo leer {}: {e}", path.display())))?;
        let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
        let config: NameForgeConfig = serde_json::from_slice(bytes)
            .map_err(|e| Error::NameForge(format!("{}: JSON invalido: {e}", path.display())))?;
        config.validate()?;
        Ok(config)
    }
}

/// Propuesta de nombre devuelta por un proveedor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NameSuggestion {
    /// Identificador propuesto (sin validar todavia).
    pub name: String,
    /// Confianza entre 0 y 1.
    pub confidence: f64,
    /// Justificacion breve y auditable.
    pub reason: String,
}

/// Propuesta persistida en el proyecto.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SuggestionRecord {
    /// Identificador de la propuesta en SQLite.
    pub id: i64,
    /// Funcion a la que se refiere.
    pub function: u64,
    /// Nombre propuesto.
    pub name: String,
    /// Confianza entre 0 y 1.
    pub confidence: f64,
    /// Justificacion de la propuesta.
    pub reason: String,
    /// `pending`, `accepted` o `rejected`.
    pub state: String,
    /// Orden de la propuesta para esa funcion (1-3).
    pub seq: u8,
    /// Fecha de creacion (ISO 8601).
    pub created_at: String,
    /// Fecha de aceptacion o rechazo, si ya se decidio.
    pub decided_at: Option<String>,
}

/// Resultado de una tanda de propuestas.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SuggestionBatch {
    /// Funciones para las que se intento proponer un nombre.
    pub functions: u64,
    /// Propuestas validas guardadas.
    pub suggestions: u64,
    /// Propuestas descartadas por no cumplir el contrato.
    pub discarded: u64,
    /// Avisos no fatales (funciones omitidas, respuestas invalidas...).
    pub warnings: Vec<String>,
    /// Propuestas guardadas, ordenadas por funcion y orden.
    pub records: Vec<SuggestionRecord>,
}

/// Proveedor de nombres.
pub trait NameProvider {
    /// Genera hasta [`MAX_SUGGESTIONS`] propuestas para `context`.
    fn suggest(
        &self,
        context: &FunctionContext,
        config: &NameForgeConfig,
    ) -> Result<Vec<NameSuggestion>>;
}

/// Ejecuta el proveedor configurado.
pub fn propose(config: &NameForgeConfig, context: &FunctionContext) -> Result<Vec<NameSuggestion>> {
    match &config.provider {
        ProviderConfig::Heuristic => HeuristicProvider.suggest(context, config),
        ProviderConfig::Command { argv, timeout_secs } => {
            run_command(argv, *timeout_secs, context, config)
        }
    }
}

/// Valida y normaliza las propuestas de un proveedor.
///
/// Descarta nombres invalidos o vetados, confianzas fuera de rango y
/// justificaciones vacias. Devuelve las propuestas validas y los avisos
/// correspondientes; nunca deja pasar una propuesta sin justificacion.
pub fn validate_suggestions(
    suggestions: Vec<NameSuggestion>,
    style: &StyleConfig,
) -> (Vec<NameSuggestion>, Vec<String>) {
    let mut valid = Vec::new();
    let mut warnings = Vec::new();
    for mut s in suggestions {
        s.name = s.name.trim().to_string();
        s.reason = s.reason.trim().to_string();
        if !is_valid_identifier(&s.name, style.max_length) {
            warnings.push(format!("propuesta descartada: nombre invalido {:?}", s.name));
            continue;
        }
        if style.banned.iter().any(|b| b.eq_ignore_ascii_case(&s.name)) {
            warnings.push(format!("propuesta descartada: nombre vetado {:?}", s.name));
            continue;
        }
        if !s.confidence.is_finite() || !(0.0..=1.0).contains(&s.confidence) {
            warnings
                .push(format!("propuesta descartada: confianza fuera de [0,1] para {:?}", s.name));
            continue;
        }
        if s.reason.is_empty() || s.reason.chars().any(char::is_control) || s.reason.len() > 500 {
            warnings
                .push(format!("propuesta descartada: justificacion invalida para {:?}", s.name));
            continue;
        }
        if valid.iter().any(|v: &NameSuggestion| v.name.eq_ignore_ascii_case(&s.name)) {
            continue;
        }
        valid.push(s);
        if valid.len() == MAX_SUGGESTIONS {
            break;
        }
    }
    (valid, warnings)
}

/// Ejecuta un proveedor externo con el contrato JSON de [`PROVIDER_SCHEMA_VERSION`].
fn run_command(
    argv: &[String],
    timeout_secs: u64,
    context: &FunctionContext,
    config: &NameForgeConfig,
) -> Result<Vec<NameSuggestion>> {
    if argv.is_empty() {
        return Err(Error::NameForge("provider.argv esta vacio".into()));
    }
    let payload = serde_json::to_vec(&json!({
        "schema_version": PROVIDER_SCHEMA_VERSION,
        "context": context,
        "style": config.style,
        "max_suggestions": MAX_SUGGESTIONS,
    }))?;

    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::NameForge(format!("no se pudo ejecutar {:?}: {e}", argv[0])))?;

    // El payload esta acotado (instrucciones, cadenas y constantes tienen
    // topes), asi que cabe en la tuberia sin bloquear al hijo.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&payload)
            .map_err(|e| Error::NameForge(format!("no se pudo enviar el contexto: {e}")))?;
    }

    // Leer en hilos evita el interbloqueo si el hijo escribe mas que el tamano
    // del pipe mientras nosotros esperamos a que termine.
    let (tx, rx) = mpsc::channel();
    if let Some(mut stdout) = child.stdout.take() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let res = stdout.read_to_end(&mut buf).map(|_| buf);
            let _ = tx.send(("stdout", res));
        });
    }
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let res = stderr.read_to_end(&mut buf).map(|_| buf);
            let _ = tx.send(("stderr", res));
        });
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| Error::NameForge(format!("esperando al proveedor: {e}")))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::NameForge(format!(
                "el proveedor no respondio en {timeout_secs} s; se detuvo el proceso"
            )));
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    // El hijo ya termino; las lecturas pendientes se completan enseguida.
    for _ in 0..2 {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(("stdout", Ok(buf))) => stdout = buf,
            Ok(("stderr", Ok(buf))) => stderr = buf,
            Ok((_, Err(e))) => {
                return Err(Error::NameForge(format!("leyendo la respuesta del proveedor: {e}")))
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        return Err(Error::NameForge(format!(
            "el proveedor termino con {status}: {}",
            detail.trim()
        )));
    }
    let text = String::from_utf8(stdout)
        .map_err(|e| Error::NameForge(format!("la respuesta no es UTF-8: {e}")))?;
    let doc: Value = serde_json::from_str(&text)
        .map_err(|e| Error::NameForge(format!("respuesta JSON invalida: {e}")))?;
    let array = doc
        .get("suggestions")
        .and_then(Value::as_array)
        .or_else(|| doc.as_array())
        .ok_or_else(|| {
            Error::NameForge("la respuesta debe ser {\"suggestions\": [...]} o una lista".into())
        })?;

    let mut out = Vec::new();
    for item in array.iter().take(MAX_SUGGESTIONS) {
        out.push(NameSuggestion {
            name: item.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
            confidence: item.get("confidence").and_then(Value::as_f64).unwrap_or(f64::NAN),
            reason: item.get("reason").and_then(Value::as_str).unwrap_or_default().to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn styles_convert_words() {
        let words = vec!["player".to_string(), "speed".to_string()];
        let mut style = StyleConfig::default();
        assert_eq!(style.make_name(&words).as_deref(), Some("player_speed"));
        style.case = NameCase::Camel;
        assert_eq!(style.make_name(&words).as_deref(), Some("playerSpeed"));
        style.case = NameCase::Pascal;
        assert_eq!(style.make_name(&words).as_deref(), Some("PlayerSpeed"));
    }

    #[test]
    fn prefix_and_max_length_are_applied() {
        let mut style =
            StyleConfig { prefix: "g".into(), max_length: 12, ..StyleConfig::default() };
        let words = vec!["player".to_string(), "speed".to_string(), "x".to_string()];
        assert_eq!(style.make_name(&words).as_deref(), Some("g_player"));
        style.max_length = 8;
        assert_eq!(style.make_name(&words).as_deref(), Some("g_player"));
    }

    #[test]
    fn banned_names_are_not_generated() {
        let style = StyleConfig { banned: vec!["player_speed".into()], ..StyleConfig::default() };
        assert_eq!(style.make_name(&["player".into(), "speed".into()]), None);
    }

    #[test]
    fn identifiers_split_on_case_and_separators() {
        assert_eq!(split_identifier_words("PlayerSpeed"), ["player", "speed"]);
        assert_eq!(split_identifier_words("player-speed"), ["player", "speed"]);
        assert_eq!(split_identifier_words("__player__speed__"), ["player", "speed"]);
        assert_eq!(split_identifier_words("getHTTPResponse"), ["get", "http", "response"]);
    }

    #[test]
    fn invalid_identifiers_are_rejected() {
        assert!(is_valid_identifier("player_speed", 64));
        assert!(is_valid_identifier("_private", 64));
        assert!(!is_valid_identifier("1player", 64));
        assert!(!is_valid_identifier("player-speed", 64));
        assert!(!is_valid_identifier("a".repeat(65).as_str(), 64));
    }

    #[test]
    fn case_is_inferred_from_two_examples() {
        let snake = vec!["player_init".to_string(), "player_update".to_string()];
        assert_eq!(infer_case(&snake), Some(NameCase::Snake));
        let camel = vec!["playerInit".to_string(), "playerUpdate".to_string()];
        assert_eq!(infer_case(&camel), Some(NameCase::Camel));
        let pascal = vec!["PlayerInit".to_string(), "PlayerUpdate".to_string()];
        assert_eq!(infer_case(&pascal), Some(NameCase::Pascal));
        assert_eq!(infer_case(&["one".to_string()]), None);
    }

    #[test]
    fn validation_drops_bad_suggestions() {
        let style = StyleConfig::default();
        let (valid, warnings) = validate_suggestions(
            vec![
                NameSuggestion {
                    name: "good_name".into(),
                    confidence: 0.8,
                    reason: "cadena cercana".into(),
                },
                NameSuggestion { name: "bad-name".into(), confidence: 0.9, reason: "x".into() },
                NameSuggestion { name: "nan".into(), confidence: f64::NAN, reason: "x".into() },
                NameSuggestion { name: "no_reason".into(), confidence: 0.5, reason: " ".into() },
            ],
            &style,
        );
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].name, "good_name");
        assert_eq!(warnings.len(), 3);
    }

    #[test]
    fn config_validation_rejects_empty_commands_and_bad_timeouts() {
        let mut config = NameForgeConfig::default();
        assert!(config.validate().is_ok());
        config.provider = ProviderConfig::Command { argv: vec![], timeout_secs: 10 };
        assert!(config.validate().is_err());
        config.provider = ProviderConfig::Command { argv: vec!["x".into()], timeout_secs: 0 };
        assert!(config.validate().is_err());
    }
}
