//! Heuristica local de NameForge.
//!
//! No pretende sustituir a un modelo: es una linea base determinista y
//! verificable para el modo local y las pruebas. Solo propone nombres cuando hay
//! evidencia en el contexto (una cadena cercana o un unico llamado ya nombrado)
//! y declara una confianza baja o moderada. Si no hay evidencia, devuelve una
//! lista vacia en lugar de inventar.

use super::{
    split_identifier_words, validate_suggestions, FunctionContext, NameForgeConfig, NameProvider,
    NameSuggestion,
};
use crate::error::Result;

/// Proveedor heuristico local.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicProvider;

impl NameProvider for HeuristicProvider {
    fn suggest(
        &self,
        context: &FunctionContext,
        config: &NameForgeConfig,
    ) -> Result<Vec<NameSuggestion>> {
        let mut out = Vec::new();

        // Primero las cadenas que ya parecen identificadores; despues las
        // frases. Asi una cadena como `player_speed` no la tapa una frase
        // cercana menos informativa.
        for identifier_only in [true, false] {
            for string in &context.strings {
                if out.len() >= 3 {
                    break;
                }
                let Some(words) = usable_string_words(&string.value) else {
                    continue;
                };
                let identifier_like = is_identifier_like(&string.value);
                if identifier_like != identifier_only {
                    continue;
                }
                let Some(name) = config.style.make_name(&words) else {
                    continue;
                };
                let confidence = if identifier_like { 0.55 } else { 0.35 };
                out.push(NameSuggestion {
                    name,
                    confidence,
                    reason: format!("cadena cercana: {:?}", truncate(&string.value, 80)),
                });
            }
        }

        if out.len() < 3 && context.instructions.len() <= 6 {
            let named: Vec<_> = context.callees.iter().filter(|c| c.named).collect();
            if named.len() == 1 {
                let mut words = split_identifier_words(&named[0].name);
                if !words.is_empty() {
                    words.push("wrapper".into());
                    if let Some(name) = config.style.make_name(&words) {
                        out.push(NameSuggestion {
                            name,
                            confidence: 0.30,
                            reason: format!("funcion pequena que solo llama a {}", named[0].name),
                        });
                    }
                }
            }
        }

        let (valid, _) = validate_suggestions(out, &config.style);
        Ok(valid)
    }
}

/// Acepta solo cadenas con caracteres seguros para un identificador o una
/// frase corta. Descarta rutas, formatos y URLs para no generar ruido.
fn usable_string_words(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    if value.len() < 4 {
        return None;
    }
    let safe = value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-'));
    if !safe || value.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let words = split_identifier_words(value);
    if words.is_empty() || words.iter().all(|w| GENERIC.contains(&w.as_str())) {
        return None;
    }
    Some(words)
}

fn is_identifier_like(value: &str) -> bool {
    let value = value.trim();
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        let mut cut = max;
        while !value.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...", &value[..cut])
    }
}

/// Palabras demasiado genericas para convertirlas en un nombre por si solas.
const GENERIC: &[&str] = &[
    "the", "and", "for", "with", "from", "this", "that", "true", "false", "null", "none", "error",
    "warning", "info", "debug", "http", "https", "www", "com", "org", "bin", "data", "text",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nameforge::{InstructionText, NameCase, NamedReference, StyleConfig, StyleContext};

    fn context(
        strings: &[&str],
        callees: Vec<NamedReference>,
        instructions: usize,
    ) -> FunctionContext {
        FunctionContext {
            address: 0x1000,
            size: 0x40,
            current_name: None,
            state: "detected".into(),
            instructions: (0..instructions)
                .map(|i| InstructionText { address: 0x1000 + i as u64 * 4, text: "nop".into() })
                .collect(),
            instructions_truncated: false,
            callers: vec![],
            callees,
            strings: strings
                .iter()
                .enumerate()
                .map(|(i, s)| super::super::StringReference {
                    address: 0x2000 + i as u64 * 0x20,
                    value: (*s).into(),
                })
                .collect(),
            constants: vec![],
            style: StyleContext {
                case: NameCase::Snake,
                inferred_case: None,
                prefix: String::new(),
                examples: vec![],
            },
        }
    }

    #[test]
    fn string_identifiers_become_names_with_evidence() {
        let config = NameForgeConfig::default();
        let ctx = context(&["player_speed", "not a name"], vec![], 10);
        let s = HeuristicProvider.suggest(&ctx, &config).unwrap();
        assert_eq!(s[0].name, "player_speed");
        assert!(s[0].confidence >= 0.5);
        assert!(s[0].reason.contains("cadena cercana"));
    }

    #[test]
    fn phrases_are_lower_confidence_and_follow_the_style() {
        let config = NameForgeConfig {
            style: StyleConfig { case: NameCase::Camel, ..StyleConfig::default() },
            ..NameForgeConfig::default()
        };
        let ctx = context(&["player speed"], vec![], 10);
        let s = HeuristicProvider.suggest(&ctx, &config).unwrap();
        assert_eq!(s[0].name, "playerSpeed");
        assert!(s[0].confidence < 0.5);
    }

    #[test]
    fn unsafe_strings_are_ignored() {
        let config = NameForgeConfig::default();
        let ctx = context(&["%s: %d", "/usr/local/bin", "https://example.com"], vec![], 10);
        assert!(HeuristicProvider.suggest(&ctx, &config).unwrap().is_empty());
    }

    #[test]
    fn a_small_wrapper_of_a_named_function_is_proposed() {
        let config = NameForgeConfig::default();
        let callee = NamedReference { address: 0x2000, name: "player_update".into(), named: true };
        let ctx = context(&[], vec![callee], 4);
        let s = HeuristicProvider.suggest(&ctx, &config).unwrap();
        assert_eq!(s[0].name, "player_update_wrapper");
        assert!(s[0].confidence < 0.5);
    }

    #[test]
    fn no_evidence_means_no_proposals() {
        let config = NameForgeConfig::default();
        let ctx = context(&[], vec![], 40);
        assert!(HeuristicProvider.suggest(&ctx, &config).unwrap().is_empty());
    }

    #[test]
    fn at_most_three_unique_proposals() {
        let config = NameForgeConfig::default();
        let ctx = context(&["alpha", "alpha", "beta", "gamma", "delta"], vec![], 40);
        let s = HeuristicProvider.suggest(&ctx, &config).unwrap();
        assert!(s.len() <= 3);
        let mut names: Vec<_> = s.iter().map(|x| &x.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), s.len());
    }
}
