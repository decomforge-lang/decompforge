//! Deteccion de funciones por desensamblado recursivo (RF-03).
//!
//! El algoritmo es deliberadamente simple y verificable:
//!
//! 1. Las semillas son la entrada del binario, los simbolos en regiones
//!    ejecutables, las funciones que ya existian en el proyecto y el comienzo
//!    de cada region ejecutable.
//! 2. Cada semilla abre una funcion. Se sigue el flujo lineal, las ramas
//!    condicionales y los saltos directos dentro de la misma funcion.
//! 3. Cada llamada directa a una direccion ejecutable se registra como arista
//!    y se convierte en una nueva semilla.
//! 4. Todo esta acotado (`AnalysisOptions`): nunca se analiza un binario
//!    malicioso sin limite de tiempo ni de memoria.
//!
//! Limitacion conocida de la Fase 1: un salto directo incondicional se sigue
//! como parte de la funcion actual, de modo que puede unir una funcion con su
//! epilogo compartido. Las funciones se identifican por su punto de entrada y
//! el tamano es la envolvente de las instrucciones alcanzadas.

mod disasm;
mod image;

pub use disasm::{disassemble, Disassembler, Flow, Instruction};
pub use image::{Image, Region};

use crate::arch::{Arch, Endian};
use crate::error::Result;
use serde::Serialize;
use std::collections::BTreeSet;

/// Maximo de avisos que se conservan; el resto se resume en uno final.
pub const MAX_WARNINGS: usize = 64;

/// Limites del analisis. Los valores por defecto son holgados para un
/// ejecutable de consola y, a la vez, cortan bucles patologicos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisOptions {
    /// Tope de funciones detectadas (por defecto 65 536).
    pub max_functions: usize,
    /// Tope de instrucciones decodificadas (por defecto 5 000 000).
    pub max_instructions: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        AnalysisOptions { max_functions: 65_536, max_instructions: 5_000_000 }
    }
}

/// Funcion detectada (sin nombre: los nombres los aporta el usuario o la IA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedFunction {
    /// Direccion de entrada de la funcion.
    pub address: u64,
    /// Envolvente de las instrucciones alcanzadas.
    pub size: u64,
    /// Instrucciones decodificadas dentro de la funcion.
    pub instructions: u64,
}

/// Llamada directa entre dos funciones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallEdge {
    /// Funcion que llama.
    pub src: u64,
    /// Funcion llamada.
    pub dst: u64,
}

/// Resultado completo del analisis (lo usan las pruebas y la interfaz).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// Ordenadas por direccion.
    pub functions: Vec<DetectedFunction>,
    /// Ordenadas por (origen, destino).
    pub call_edges: Vec<CallEdge>,
    /// Total de instrucciones decodificadas.
    pub instructions: u64,
    /// Se alcanzo alguno de los limites de [`AnalysisOptions`].
    pub truncated: bool,
    /// Avisos deduplicados (secciones truncadas, flujo fuera de rango, limites).
    pub warnings: Vec<String>,
}

/// Resumen serializable que se muestra al usuario y se registra en auditoria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisSummary {
    /// Funciones detectadas.
    pub functions: u64,
    /// Instrucciones decodificadas.
    pub instructions: u64,
    /// Llamadas directas entre funciones.
    pub call_edges: u64,
    /// El analisis se detuvo por alcanzar un limite.
    pub truncated: bool,
    /// Avisos deduplicados.
    pub warnings: Vec<String>,
}

impl Analysis {
    /// Reduce el resultado a los contadores que se muestran y se auditan.
    pub fn summary(&self) -> AnalysisSummary {
        AnalysisSummary {
            functions: self.functions.len() as u64,
            instructions: self.instructions,
            call_edges: self.call_edges.len() as u64,
            truncated: self.truncated,
            warnings: self.warnings.clone(),
        }
    }
}

/// Avisos con deduplicacion y tope, para que un binario corrupto no genere
/// millones de lineas.
struct Warnings {
    messages: Vec<String>,
    suppressed: usize,
}

impl Warnings {
    fn new(initial: &[String]) -> Self {
        let mut w = Warnings { messages: Vec::new(), suppressed: 0 };
        for m in initial {
            w.push(m.clone());
        }
        w
    }

    fn push(&mut self, msg: String) {
        if self.messages.contains(&msg) {
            return;
        }
        if self.messages.len() < MAX_WARNINGS {
            self.messages.push(msg);
        } else {
            self.suppressed += 1;
        }
    }

    fn finish(mut self) -> Vec<String> {
        if self.suppressed > 0 {
            self.messages
                .push(format!("{} avisos mas omitidos para no saturar la salida", self.suppressed));
        }
        self.messages
    }
}

/// Detecta funciones y llamadas. `seeds` debe contener direcciones de puntos
/// de entrada conocidos (entrada, simbolos, funciones previas); las llamadas
/// directas descubiertas se anaden automaticamente.
pub fn analyze(
    image: &Image<'_>,
    arch: Arch,
    endian: Endian,
    bits: u8,
    seeds: &[u64],
    opts: &AnalysisOptions,
) -> Result<Analysis> {
    let dis = Disassembler::new(arch, endian, bits)?;
    let mut warnings = Warnings::new(image.warnings());

    let mut queue: BTreeSet<u64> = seeds.iter().copied().collect();
    if queue.is_empty() {
        warnings.push("el binario no tiene entrada ni simbolos ejecutables".into());
    } else if !queue.iter().any(|&a| image.is_executable(a)) {
        warnings.push("ninguna semilla cae en una region ejecutable".into());
    }

    let mut analyzed: BTreeSet<u64> = BTreeSet::new();
    let mut functions: Vec<DetectedFunction> = Vec::new();
    let mut edges: BTreeSet<CallEdge> = BTreeSet::new();
    let mut instructions: u64 = 0;
    let mut truncated = false;

    while let Some(start) = queue.pop_first() {
        if analyzed.contains(&start) {
            continue;
        }
        if !image.is_executable(start) {
            warnings
                .push(format!("semilla 0x{start:x}: no esta en una region ejecutable; se omite"));
            continue;
        }
        if functions.len() >= opts.max_functions {
            truncated = true;
            warnings.push(format!(
                "se alcanzo el limite de {} funciones; el analisis queda truncado",
                opts.max_functions
            ));
            break;
        }
        analyzed.insert(start);

        let mut visited: BTreeSet<u64> = BTreeSet::new();
        let mut pending: BTreeSet<u64> = BTreeSet::new();
        pending.insert(start);
        let mut max_end = start;
        let mut count: u64 = 0;
        let mut stop_function = false;

        while let Some(mut pc) = pending.pop_first() {
            loop {
                if instructions >= opts.max_instructions as u64 {
                    truncated = true;
                    warnings.push(format!(
                        "se alcanzo el limite de {} instrucciones; el analisis queda truncado",
                        opts.max_instructions
                    ));
                    stop_function = true;
                    break;
                }
                if !image.is_executable(pc) {
                    warnings.push(format!(
                        "0x{pc:x}: el flujo sale de las regiones ejecutables; se corta"
                    ));
                    break;
                }
                if !visited.insert(pc) {
                    break; // ya visto en esta funcion (bucle o rama de vuelta)
                }
                let Some(insn) = dis.decode(image, pc)? else {
                    warnings.push(format!("0x{pc:x}: no se pudo decodificar; fin de bloque"));
                    break;
                };

                instructions += 1;
                count += 1;
                max_end = max_end.max(insn.end());

                match insn.flow {
                    Flow::Next => pc = insn.end(),
                    Flow::Call(Some(target)) => {
                        if image.is_executable(target) {
                            edges.insert(CallEdge { src: start, dst: target });
                            queue.insert(target);
                        } else {
                            warnings.push(format!(
                                "0x{:x}: llamada a 0x{target:x}, que no es ejecutable",
                                insn.address
                            ));
                        }
                        pc = insn.end();
                    }
                    Flow::Call(None) => pc = insn.end(),
                    Flow::Jump(Some(target)) => {
                        if image.is_executable(target) {
                            pending.insert(target);
                        } else {
                            warnings.push(format!(
                                "0x{:x}: salto a 0x{target:x}, que no es ejecutable",
                                insn.address
                            ));
                        }
                        break; // el flujo lineal termina en el salto
                    }
                    Flow::Jump(None) => break,
                    Flow::CondJump(target) => {
                        if image.is_executable(target) {
                            pending.insert(target);
                        } else {
                            warnings.push(format!(
                                "0x{:x}: rama a 0x{target:x}, que no es ejecutable",
                                insn.address
                            ));
                        }
                        pc = insn.end(); // el fallthrough continua
                    }
                    Flow::Return | Flow::Stop => break,
                }
            }
            if stop_function {
                break;
            }
        }

        if count > 0 {
            functions.push(DetectedFunction {
                address: start,
                size: max_end - start,
                instructions: count,
            });
        } else {
            warnings
                .push(format!("semilla 0x{start:x}: no se pudo decodificar ninguna instruccion"));
        }
        if truncated {
            break;
        }
    }

    functions.sort_by_key(|f| f.address);
    if functions.is_empty() && !warnings.messages.is_empty() {
        warnings.push("no se detecto ninguna funcion".into());
    }

    Ok(Analysis {
        functions,
        call_edges: edges.into_iter().collect(),
        instructions,
        truncated,
        warnings: warnings.finish(),
    })
}
