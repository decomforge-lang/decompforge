//! Deteccion de funciones por desensamblado recursivo (RF-03).
//!
//! El algoritmo es deliberadamente simple y verificable:
//!
//! 1. Las semillas son la entrada del binario, los simbolos en regiones
//!    ejecutables, las funciones que ya existian en el proyecto y el comienzo
//!    de cada region ejecutable.
//! 2. Cada semilla abre una funcion. Se sigue el flujo lineal, las ramas
//!    condicionales y los saltos directos. Las llamadas directas se registran
//!    como aristas y se convierten en nuevas semillas.
//! 3. Cada instruccion pertenece a una sola funcion (*ownership*). Si el flujo
//!    entra en una instruccion ya adjudicada a otra funcion, o en una semilla
//!    conocida, se corta y la arista queda como salto o llamada final.
//! 4. Las instrucciones se agrupan en bloques basicos y el resultado incluye
//!    las aristas del grafo de flujo de control (CFG).
//! 5. En MIPS se decodifica el *delay slot* de ramas, saltos, llamadas y
//!    retornos: el hueco pertenece a la funcion y al bloque de la instruccion
//!    que transfiere el control.
//! 6. Todo esta acotado ([`AnalysisOptions`]): nunca se analiza un binario
//!    malicioso sin limite de tiempo ni de memoria.
//!
//! Limitaciones conocidas: un salto directo a una funcion anonima que todavia
//! no se ha descubierto puede unirla con la actual (no hay pre-pase de
//! llamadas). Las variantes *branch-likely* de MIPS se tratan como ramas
//! normales, de modo que el *delay slot* se considera siempre ejecutado.

mod disasm;
mod image;

pub use disasm::{disassemble, Disassembler, Flow, Instruction};
pub use image::{Image, Region};

use crate::arch::{Arch, Endian};
use crate::error::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

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

/// Tipo de arista del grafo de flujo de control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// El bloque continua en el siguiente sin transferir el control.
    Fallthrough,
    /// Rama condicional: la arista se toma cuando se cumple la condicion.
    Branch,
    /// Salto incondicional dentro de la misma funcion.
    Jump,
    /// Llamada directa; el destino es la entrada de otra funcion.
    Call,
    /// Salto final a otra funcion (cola de la funcion actual).
    TailCall,
}

impl EdgeKind {
    /// Nombre estable que se guarda en SQLite y se muestra en la interfaz.
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Fallthrough => "fallthrough",
            EdgeKind::Branch => "branch",
            EdgeKind::Jump => "jump",
            EdgeKind::Call => "call",
            EdgeKind::TailCall => "tail_call",
        }
    }
}

/// Bloque basico: instrucciones contiguas con un unico punto de entrada y una
/// unica salida. Los limites son `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    /// Funcion a la que pertenece el bloque.
    pub function: u64,
    /// Direccion del primer byte.
    pub start: u64,
    /// Direccion del primer byte del bloque siguiente.
    pub end: u64,
    /// Instrucciones decodificadas del bloque.
    pub instructions: u64,
}

impl BasicBlock {
    /// Numero de bytes del bloque.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

/// Arista del grafo de flujo de control. `src` y `dst` son direcciones de
/// bloque (o la entrada de una funcion en las aristas `call`/`tail_call`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CfgEdge {
    /// Bloque de origen.
    pub src: u64,
    /// Bloque o funcion de destino.
    pub dst: u64,
    /// Motivo de la arista.
    pub kind: EdgeKind,
}

/// Resultado completo del analisis (lo usan las pruebas y la interfaz).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// Ordenadas por direccion.
    pub functions: Vec<DetectedFunction>,
    /// Ordenadas por (origen, destino).
    pub call_edges: Vec<CallEdge>,
    /// Bloques basicos ordenados por direccion.
    pub blocks: Vec<BasicBlock>,
    /// Aristas del CFG ordenadas por (origen, destino, tipo).
    pub cfg_edges: Vec<CfgEdge>,
    /// Total de instrucciones decodificadas.
    pub instructions: u64,
    /// Se alcanzo alguno de los limites de [`AnalysisOptions`].
    pub truncated: bool,
    /// Avisos deduplicados (secciones truncadas, flujo fuera de rango, limites).
    pub warnings: Vec<String>,
    /// Direccion de instruccion -> funcion propietaria.
    owners: BTreeMap<u64, u64>,
}

impl Analysis {
    /// Funcion propietaria de la instruccion que empieza en `address`.
    ///
    /// Cada instruccion pertenece como mucho a una funcion; los huecos entre
    /// funciones no tienen propietario.
    pub fn owner(&self, address: u64) -> Option<u64> {
        self.owners.get(&address).copied()
    }
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
    /// Bloques basicos.
    pub basic_blocks: u64,
    /// Aristas del CFG (incluye saltos, ramas, llamadas y saltos finales).
    pub cfg_edges: u64,
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
            basic_blocks: self.blocks.len() as u64,
            cfg_edges: self.cfg_edges.len() as u64,
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

/// Instrucciones y limites descubiertos para una funcion.
struct FunctionGraph {
    start: u64,
    insns: BTreeMap<u64, Instruction>,
    /// Direcciones de instrucciones que son *delay slot* de otra.
    delay_slots: BTreeSet<u64>,
    /// Comienzos de bloque conocidos.
    leaders: BTreeSet<u64>,
    /// Destinos de llamadas directas (nuevas semillas).
    call_targets: BTreeSet<u64>,
    max_end: u64,
}

impl FunctionGraph {
    fn new(start: u64) -> Self {
        FunctionGraph {
            start,
            insns: BTreeMap::new(),
            delay_slots: BTreeSet::new(),
            leaders: BTreeSet::new(),
            call_targets: BTreeSet::new(),
            max_end: start,
        }
    }
}

/// Detecta funciones, bloques basicos y aristas de CFG. `seeds` debe contener
/// direcciones de puntos de entrada conocidos (entrada, simbolos, funciones
/// previas); las llamadas directas descubiertas se anaden automaticamente.
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
    let mut known_starts: BTreeSet<u64> = queue.iter().copied().collect();
    if queue.is_empty() {
        warnings.push("el binario no tiene entrada ni simbolos ejecutables".into());
    } else if !queue.iter().any(|&a| image.is_executable(a)) {
        warnings.push("ninguna semilla cae en una region ejecutable".into());
    }

    let mut done: BTreeSet<u64> = BTreeSet::new();
    let mut owner: BTreeMap<u64, u64> = BTreeMap::new();
    let mut functions: Vec<DetectedFunction> = Vec::new();
    let mut call_edges: BTreeSet<CallEdge> = BTreeSet::new();
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut cfg_edges: BTreeSet<CfgEdge> = BTreeSet::new();
    let mut instructions: u64 = 0;
    let mut truncated = false;

    while let Some(start) = queue.pop_first() {
        if !done.insert(start) {
            continue;
        }
        if !image.is_executable(start) {
            warnings
                .push(format!("semilla 0x{start:x}: no esta en una region ejecutable; se omite"));
            continue;
        }
        if let Some(&other) = owner.get(&start) {
            warnings.push(format!(
                "semilla 0x{start:x}: ya pertenece a la funcion 0x{other:x}; se omite"
            ));
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

        let graph = explore_function(
            start,
            image,
            &dis,
            opts,
            &mut instructions,
            &mut truncated,
            &mut warnings,
            &owner,
            &known_starts,
        )?;

        for &target in &graph.call_targets {
            known_starts.insert(target);
            if !done.contains(&target) {
                queue.insert(target);
            }
            call_edges.insert(CallEdge { src: start, dst: target });
        }

        if graph.insns.is_empty() {
            warnings
                .push(format!("semilla 0x{start:x}: no se pudo decodificar ninguna instruccion"));
            if truncated {
                break;
            }
            continue;
        }

        for &addr in graph.insns.keys() {
            owner.insert(addr, start);
        }
        let (fn_blocks, fn_edges) = build_cfg(&graph, image, &mut warnings);
        blocks.extend(fn_blocks);
        cfg_edges.extend(fn_edges);
        functions.push(DetectedFunction {
            address: start,
            size: graph.max_end - start,
            instructions: graph.insns.len() as u64,
        });

        if truncated {
            break;
        }
    }

    functions.sort_by_key(|f| f.address);
    blocks.sort_by_key(|b| b.start);
    if functions.is_empty() && !warnings.messages.is_empty() {
        warnings.push("no se detecto ninguna funcion".into());
    }

    Ok(Analysis {
        functions,
        call_edges: call_edges.into_iter().collect(),
        blocks,
        cfg_edges: cfg_edges.into_iter().collect(),
        instructions,
        truncated,
        warnings: warnings.finish(),
        owners: owner,
    })
}

/// Sigue el flujo alcanzable desde `start`. Las instrucciones se guardan en un
/// mapa (no se reclaman globalmente hasta terminar) para no dejar a medias una
/// funcion si se alcanza un limite.
#[allow(clippy::too_many_arguments)]
fn explore_function(
    start: u64,
    image: &Image<'_>,
    dis: &Disassembler,
    opts: &AnalysisOptions,
    instructions: &mut u64,
    truncated: &mut bool,
    warnings: &mut Warnings,
    owner: &BTreeMap<u64, u64>,
    known_starts: &BTreeSet<u64>,
) -> Result<FunctionGraph> {
    let mut graph = FunctionGraph::new(start);
    let mut pending: BTreeSet<u64> = BTreeSet::new();
    pending.insert(start);

    while let Some(path_start) = pending.pop_first() {
        if graph.insns.contains_key(&path_start) {
            continue;
        }
        if !image.is_executable(path_start) {
            warnings.push(format!(
                "0x{path_start:x}: el flujo sale de las regiones ejecutables; se corta"
            ));
            continue;
        }
        if owner.get(&path_start).is_some_and(|&o| o != start) {
            continue; // ya pertenece a otra funcion
        }
        if path_start != start && known_starts.contains(&path_start) {
            continue; // otra funcion declarada
        }

        let mut pc = path_start;
        loop {
            if *instructions >= opts.max_instructions as u64 {
                *truncated = true;
                warnings.push(format!(
                    "se alcanzo el limite de {} instrucciones; el analisis queda truncado",
                    opts.max_instructions
                ));
                return Ok(graph);
            }
            if graph.insns.contains_key(&pc) {
                break; // punto de union con codigo ya decodificado
            }
            if !image.is_executable(pc) {
                warnings
                    .push(format!("0x{pc:x}: el flujo sale de las regiones ejecutables; se corta"));
                break;
            }
            if owner.get(&pc).is_some_and(|&o| o != start) {
                break; // otra funcion ya posee esta instruccion
            }
            if pc != start && known_starts.contains(&pc) {
                warnings
                    .push(format!("0x{pc:x}: el flujo entra en otra funcion conocida; se corta"));
                break;
            }
            let Some(insn) = dis.decode(image, pc)? else {
                warnings.push(format!("0x{pc:x}: no se pudo decodificar; fin de bloque"));
                break;
            };

            *instructions += 1;
            graph.max_end = graph.max_end.max(insn.end());
            graph.insns.insert(insn.address, insn.clone());

            // El delay slot se ejecuta antes de la transferencia. Pertenece a
            // esta funcion y al mismo bloque que la instruccion que salta.
            let mut after = insn.end();
            if insn.delay_slot {
                let ds_addr = insn.end();
                if let Some(existing) = graph.insns.get(&ds_addr).cloned() {
                    graph.delay_slots.insert(ds_addr);
                    graph.max_end = graph.max_end.max(existing.end());
                    after = existing.end();
                    if existing.flow != Flow::Next {
                        warnings.push(format!(
                            "0x{ds_addr:x}: el delay slot transfiere el control; se ignora esa transferencia"
                        ));
                    }
                } else if *instructions >= opts.max_instructions as u64 {
                    *truncated = true;
                    warnings.push(format!(
                        "se alcanzo el limite de {} instrucciones; el analisis queda truncado",
                        opts.max_instructions
                    ));
                    return Ok(graph);
                } else if !image.is_executable(ds_addr) {
                    warnings.push(format!(
                        "0x{ds_addr:x}: el delay slot cae fuera de las regiones ejecutables"
                    ));
                } else if let Some(ds) = dis.decode(image, ds_addr)? {
                    *instructions += 1;
                    graph.delay_slots.insert(ds_addr);
                    graph.max_end = graph.max_end.max(ds.end());
                    after = ds.end();
                    if ds.flow != Flow::Next {
                        warnings.push(format!(
                            "0x{ds_addr:x}: el delay slot transfiere el control; se ignora esa transferencia"
                        ));
                    }
                    graph.insns.insert(ds_addr, ds);
                } else {
                    warnings.push(format!("0x{ds_addr:x}: no se pudo decodificar el delay slot"));
                }
            }

            match insn.flow {
                Flow::Next => pc = after,
                Flow::Call(Some(target)) => {
                    graph.leaders.insert(after);
                    pending.insert(after);
                    if image.is_executable(target) {
                        graph.call_targets.insert(target);
                    } else {
                        warnings.push(format!(
                            "0x{:x}: llamada a 0x{target:x}, que no es ejecutable",
                            insn.address
                        ));
                    }
                    break;
                }
                Flow::Call(None) => {
                    graph.leaders.insert(after);
                    pending.insert(after);
                    break;
                }
                Flow::Jump(Some(target)) => {
                    if !image.is_executable(target) {
                        warnings.push(format!(
                            "0x{:x}: salto a 0x{target:x}, que no es ejecutable",
                            insn.address
                        ));
                    } else if (target != start && known_starts.contains(&target))
                        || owner.get(&target).is_some_and(|&o| o != start)
                    {
                        // Salto final: el destino es otra funcion.
                    } else {
                        graph.leaders.insert(target);
                        pending.insert(target);
                    }
                    break;
                }
                Flow::Jump(None) => break,
                Flow::CondJump(target) => {
                    graph.leaders.insert(after);
                    pending.insert(after);
                    if !image.is_executable(target) {
                        warnings.push(format!(
                            "0x{:x}: rama a 0x{target:x}, que no es ejecutable",
                            insn.address
                        ));
                    } else if (target != start && known_starts.contains(&target))
                        || owner.get(&target).is_some_and(|&o| o != start)
                    {
                        // Rama hacia otra funcion: se registra la arista, no se sigue.
                    } else {
                        graph.leaders.insert(target);
                        pending.insert(target);
                    }
                    break;
                }
                Flow::Return | Flow::Stop => break,
            }
        }
    }

    Ok(graph)
}

/// Convierte las instrucciones de una funcion en bloques basicos y aristas.
fn build_cfg(
    graph: &FunctionGraph,
    image: &Image<'_>,
    warnings: &mut Warnings,
) -> (Vec<BasicBlock>, BTreeSet<CfgEdge>) {
    // Un destino de rama que cae en un delay slot no abre bloque: el hueco
    // siempre se ejecuta junto a su rama.
    let mut leaders: BTreeSet<u64> = graph
        .leaders
        .iter()
        .copied()
        .filter(|a| graph.insns.contains_key(a) && !graph.delay_slots.contains(a))
        .collect();
    for &ds in &graph.delay_slots {
        if graph.leaders.contains(&ds) {
            warnings.push(format!("0x{ds:x}: una rama apunta a un delay slot; se une a su bloque"));
        }
    }
    leaders.insert(graph.start);

    let mut blocks = Vec::new();
    for &leader in &leaders {
        let mut addr = leader;
        let mut count = 0u64;
        let mut end = leader;
        while let Some(insn) = graph.insns.get(&addr) {
            if addr != leader && leaders.contains(&addr) {
                break;
            }
            count += 1;
            end = insn.end();
            addr = insn.end();
        }
        blocks.push(BasicBlock { function: graph.start, start: leader, end, instructions: count });
    }

    // Direccion de instruccion -> inicio de su bloque, para normalizar destinos
    // que apuntan al interior de un bloque.
    let mut block_of: BTreeMap<u64, u64> = BTreeMap::new();
    for block in &blocks {
        let mut addr = block.start;
        while let Some(insn) = graph.insns.get(&addr) {
            block_of.insert(addr, block.start);
            addr = insn.end();
        }
    }
    let norm = |dst: u64| block_of.get(&dst).copied().unwrap_or(dst);

    let mut edges = BTreeSet::new();
    for block in &blocks {
        let (flow_insn, after) = terminator(graph, block);
        let mut push = |dst: u64, kind: EdgeKind| {
            edges.insert(CfgEdge { src: block.start, dst: norm(dst), kind });
        };
        match flow_insn.flow {
            Flow::Next => {
                if graph.insns.contains_key(&after) {
                    push(after, EdgeKind::Fallthrough);
                }
            }
            Flow::Call(Some(target)) => {
                if graph.insns.contains_key(&after) {
                    push(after, EdgeKind::Fallthrough);
                }
                if image.is_executable(target) {
                    push(target, EdgeKind::Call);
                }
            }
            Flow::Call(None) => {
                if graph.insns.contains_key(&after) {
                    push(after, EdgeKind::Fallthrough);
                }
            }
            Flow::Jump(Some(target)) => {
                if !image.is_executable(target) {
                    // ya se aviso durante la exploracion
                } else if graph.insns.contains_key(&target) {
                    push(target, EdgeKind::Jump);
                } else {
                    push(target, EdgeKind::TailCall);
                }
            }
            Flow::Jump(None) => {}
            Flow::CondJump(target) => {
                if graph.insns.contains_key(&after) {
                    push(after, EdgeKind::Fallthrough);
                }
                if image.is_executable(target) {
                    push(target, EdgeKind::Branch);
                }
            }
            Flow::Return | Flow::Stop => {}
        }
    }
    (blocks, edges)
}

/// Ultima instruccion con transferencia de control del bloque y direccion
/// siguiente a su delay slot (o a la propia instruccion si no lo tiene).
fn terminator<'a>(graph: &'a FunctionGraph, block: &BasicBlock) -> (&'a Instruction, u64) {
    let Some((&last_addr, last)) = graph.insns.range(block.start..block.end).next_back() else {
        // Un bloque siempre contiene al menos la instruccion de su lider.
        return (&graph.insns[&block.start], block.start);
    };
    if last_addr != block.start {
        if let Some((_, prev)) = graph.insns.range(block.start..last_addr).next_back() {
            if prev.delay_slot && prev.end() == last_addr {
                return (prev, last.end());
            }
        }
    }
    (last, last.end())
}
