//! CLI de DecompForge (seccion 11.3 del Documento Maestro).
//!
//! Fase 1: init, load, analyze, info y export. El resto de comandos
//! documentados se reconocen y explican en que fase llegaran.

use decompforge_core::analysis::AnalysisSummary;
use decompforge_core::nameforge::{NameForgeConfig, SuggestionBatch};
use decompforge_core::synthetic;
use decompforge_core::{Arch, Endian, Error, FlatSpec, LoadOptions, Project, SuggestOptions};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EXT: &str = "dfproj";

const USAGE: &str = "\
DecompForge {VERSION} - decompilar, verificar y portar videojuegos (asistido por IA)

USO:
  decompforge <comando> [opciones]

COMANDOS (Fase 1):
  init <nombre> [--platform P] [--dir D] [--sample]
        Crea un proyecto <nombre>.dfproj. Con --sample incluye un binario
        sintetico propio (sin contenido de terceros).
  load <binario> [--project F] [--arch A --endian E --base ADDR] [--no-analyze]
        Carga un binario PROPIO (ELF, DOL, PE, NSO) y detecta funciones y
        llamadas con Capstone. Para ROMs planas indica --arch, --endian y
        --base. Con --no-analyze solo importa secciones y simbolos.
  analyze <binario> [--project F]
        Vuelve a analizar el proyecto; el SHA-256 debe coincidir con el
        binario cargado. Conserva nombres y estados ya existentes.
  info [--project F] [--json]
        Muestra el estado del proyecto.
  export --format json|re-json [--project F] [--output F]
        Exporta al formato de intercambio JSON. `re-json` es el documento
        re-1.0 para herramientas de ingenieria inversa (Ghidra, IDA...).
  apply <updates.json> [--project F]
        Aplica nombres, firmas y comentarios de un documento re-1.0 de tipo
        `updates` (todo o nada).
  name <binario> [--project F] [--config F] [--batch] [--limit N] [--function ADDR]
        NameForge: propone hasta 3 nombres con confianza y justificacion.
        Sin --batch exige --function y pregunta cual aceptar (modo interactivo).
        Con --batch revisa todas las funciones sin nombre (o las indicadas).
  name list [--project F] [--state pending|accepted|rejected|all] [--function ADDR] [--json]
        Lista las propuestas guardadas (por defecto, pendientes).
  name accept <id> [--project F] [--force]
  name reject <id> [--project F]
        Acepta (aplica el nombre) o rechaza una propuesta pendiente.
  name config [--output F]
        Muestra o escribe la configuracion de estilo y proveedor por defecto.

COMANDOS PLANIFICADOS: match, recomp, lint, verify, report

Si no indicas --project se usa el unico *.dfproj del directorio actual.
DecompForge no descifra ni elude protecciones: ver docs/ACCEPTABLE_USE.md.
";

type CliResult<T> = Result<T, CliError>;

struct CliError {
    msg: String,
    code: u8,
}

impl From<Error> for CliError {
    fn from(e: Error) -> Self {
        let code = match e {
            Error::Protected { .. } => 3,
            Error::Unsupported { .. } => 4,
            _ => 1,
        };
        CliError { msg: e.to_string(), code }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError { msg: e.to_string(), code: 1 }
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError { msg: e.to_string(), code: 1 }
    }
}

fn fail<T>(msg: impl Into<String>) -> CliResult<T> {
    Err(CliError { msg: msg.into(), code: 1 })
}

/// Argumentos ya separados en posicionales y opciones.
struct Args {
    positional: Vec<String>,
    values: HashMap<String, String>,
    bools: Vec<String>,
}

impl Args {
    fn parse(raw: &[String], value_flags: &[&str], bool_flags: &[&str]) -> CliResult<Args> {
        let mut a = Args { positional: vec![], values: HashMap::new(), bools: vec![] };
        let mut it = raw.iter();
        while let Some(x) = it.next() {
            if let Some(name) = x.strip_prefix("--") {
                if bool_flags.contains(&name) {
                    a.bools.push(name.to_string());
                } else if value_flags.contains(&name) {
                    match it.next() {
                        Some(v) => {
                            a.values.insert(name.to_string(), v.clone());
                        }
                        None => return fail(format!("la opcion --{name} necesita un valor")),
                    }
                } else {
                    return fail(format!("opcion desconocida: --{name}"));
                }
            } else {
                a.positional.push(x.clone());
            }
        }
        Ok(a)
    }
    fn flag(&self, n: &str) -> bool {
        self.bools.iter().any(|b| b == n)
    }
    fn value(&self, n: &str) -> Option<&str> {
        self.values.get(n).map(String::as_str)
    }
}

fn parse_addr(s: &str) -> CliResult<u64> {
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    };
    r.or_else(|_| fail(format!("direccion invalida: '{s}'")))
}

fn project_path(args: &Args) -> CliResult<PathBuf> {
    if let Some(p) = args.value("project") {
        return Ok(PathBuf::from(p));
    }
    let mut found = Vec::new();
    for e in std::fs::read_dir(".")? {
        let p = e?.path();
        if p.extension().and_then(|x| x.to_str()) == Some(EXT) {
            found.push(p);
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => fail(format!("no hay ningun .{EXT} en el directorio actual; usa --project")),
        _ => fail(format!("hay varios .{EXT} en el directorio actual; usa --project")),
    }
}

fn print_binary(b: &decompforge_core::LoadedBinary) {
    println!("formato:        {}", b.format);
    println!("arquitectura:   {} ({} bits, {}-endian)", b.arch, b.bits, b.endian);
    match b.entry {
        Some(e) => println!("entrada:        0x{e:08x}"),
        None => println!("entrada:        (no definida)"),
    }
    println!("secciones:      {}", b.sections.len());
    for s in &b.sections {
        println!("  {:<10} 0x{:08x}  tam 0x{:<8x} {}", s.name, s.start, s.size, s.perms);
    }
    for n in &b.notes {
        println!("aviso: {n}");
    }
}

fn current_user() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "user".into())
}

fn print_analysis(s: &AnalysisSummary) {
    println!(
        "analisis:       {} funciones, {} instrucciones, {} llamadas, {} bloques, {} aristas CFG",
        s.functions, s.instructions, s.call_edges, s.basic_blocks, s.cfg_edges
    );
    if s.truncated {
        println!("aviso: el analisis quedo truncado por los limites de seguridad");
    }
    for w in &s.warnings {
        println!("aviso: {w}");
    }
}

fn cmd_init(raw: &[String]) -> CliResult<()> {
    let a = Args::parse(raw, &["platform", "dir"], &["sample"])?;
    let Some(name) = a.positional.first() else {
        return fail("uso: decompforge init <nombre> [--platform P] [--dir D] [--sample]");
    };
    let dir = PathBuf::from(a.value("dir").unwrap_or("."));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{name}.{EXT}"));
    let sample = a.flag("sample");
    let platform = a.value("platform").or(if sample { Some("ps2") } else { None });
    let mut p = Project::create(&path, name, platform)?;
    println!("proyecto creado: {}", path.display());
    if sample {
        let bin = synthetic::elf_mips_le32_program();
        let loaded = p.import_binary(&bin, &LoadOptions::default(), "sample")?;
        println!("binario sintetico cargado ({} bytes):", bin.len());
        print_binary(&loaded);
        let summary = p.analyze(&bin, "sample")?;
        print_analysis(&summary);
    }
    Ok(())
}

fn cmd_load(raw: &[String]) -> CliResult<()> {
    let a = Args::parse(raw, &["project", "arch", "endian", "base"], &["no-analyze"])?;
    let Some(bin_path) = a.positional.first() else {
        return fail(
            "uso: decompforge load <binario> [--project F] [--arch A --endian E --base ADDR] \
             [--no-analyze]",
        );
    };
    let flat = match (a.value("arch"), a.value("endian"), a.value("base")) {
        (None, None, None) => None,
        (Some(ar), Some(en), Some(ba)) => Some(FlatSpec {
            arch: ar.parse::<Arch>().or_else(fail)?,
            endian: en.parse::<Endian>().or_else(fail)?,
            base: parse_addr(ba)?,
        }),
        _ => return fail("para una ROM plana indica --arch, --endian y --base juntos"),
    };
    let data = std::fs::read(bin_path)?;
    let mut project = Project::open(&project_path(&a)?)?;
    let user = current_user();
    let loaded = project.import_binary(&data, &LoadOptions { flat }, &user)?;
    println!("cargado: {bin_path} ({} bytes)", data.len());
    print_binary(&loaded);
    if !a.flag("no-analyze") {
        let summary = project.analyze(&data, &user)?;
        print_analysis(&summary);
    }
    Ok(())
}

fn cmd_analyze(raw: &[String]) -> CliResult<()> {
    let a = Args::parse(raw, &["project"], &[])?;
    let Some(bin_path) = a.positional.first() else {
        return fail("uso: decompforge analyze <binario> [--project F]");
    };
    let data = std::fs::read(bin_path)?;
    let mut project = Project::open(&project_path(&a)?)?;
    let summary = project.analyze(&data, &current_user())?;
    println!("analizado: {bin_path} ({} bytes)", data.len());
    print_analysis(&summary);
    Ok(())
}

fn cmd_info(raw: &[String]) -> CliResult<()> {
    let a = Args::parse(raw, &["project"], &["json"])?;
    let p = Project::open(&project_path(&a)?)?;
    let i = p.info()?;
    if a.flag("json") {
        println!("{}", serde_json::to_string_pretty(&i)?);
        return Ok(());
    }
    println!("proyecto:       {}", i.name);
    println!("plataforma:     {}", i.platform.as_deref().unwrap_or("(sin indicar)"));
    if !i.loaded {
        println!("binario:        (ninguno cargado; usa `decompforge load`)");
        return Ok(());
    }
    println!(
        "binario:        {} bytes, sha256 {}",
        i.binary_size.unwrap_or(0),
        i.binary_sha256.as_deref().unwrap_or("?")
    );
    println!("formato:        {}", i.format.as_deref().unwrap_or("?"));
    println!(
        "arquitectura:   {} ({} bits, {}-endian)",
        i.architecture.as_deref().unwrap_or("?"),
        i.bits.unwrap_or(0),
        i.endian.as_deref().unwrap_or("?")
    );
    if let Some(e) = i.entry {
        println!("entrada:        0x{e:08x}");
    }
    println!("secciones:      {}", i.sections);
    println!("simbolos:       {}", i.symbols);
    println!("funciones:      {}", i.functions);
    println!("bloques:        {}", i.basic_blocks);
    println!("aristas CFG:    {}", i.cfg_edges);
    if i.name_suggestions > 0 {
        println!(
            "propuestas:     {} ({} pendientes)",
            i.name_suggestions, i.name_suggestions_pending
        );
    }
    for (state, n) in &i.functions_by_state {
        println!("  {state:<11} {n}");
    }
    Ok(())
}

fn cmd_export(raw: &[String]) -> CliResult<()> {
    let a = Args::parse(raw, &["project", "format", "output"], &[])?;
    let format = match a.value("format") {
        Some(f @ ("json" | "re-json")) => f,
        Some(other) => {
            return fail(format!(
                "formato de exportacion no soportado: '{other}' (usa json o re-json)"
            ))
        }
        None => {
            return fail("uso: decompforge export --format json|re-json [--project F] [--output F]")
        }
    };
    let p = Project::open(&project_path(&a)?)?;
    let doc = if format == "re-json" { p.export_re_json()? } else { p.export_json()? };
    let text = serde_json::to_string_pretty(&doc)? + "\n";
    match a.value("output") {
        Some(out) => {
            std::fs::write(Path::new(out), text)?;
            println!("exportado a {out}");
        }
        None => print!("{text}"),
    }
    Ok(())
}

fn cmd_apply(raw: &[String]) -> CliResult<()> {
    let a = Args::parse(raw, &["project"], &[])?;
    let Some(path) = a.positional.first() else {
        return fail("uso: decompforge apply <updates.json> [--project F]");
    };
    // Algunos editores de Windows guardan UTF-8 con BOM; JSON lo permite al
    // inicio del documento, pero `serde_json` no lo ignora por si solo.
    let bytes = std::fs::read(path)?;
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    let doc: serde_json::Value = serde_json::from_slice(bytes)?;
    let mut p = Project::open(&project_path(&a)?)?;
    let s = p.apply_updates(&doc, &current_user())?;
    println!(
        "aplicado: {} funciones, {} nombres, {} firmas, {} comentarios",
        s.functions, s.names, s.signatures, s.comments
    );
    Ok(())
}

fn cmd_name(raw: &[String]) -> CliResult<()> {
    let a = Args::parse(
        raw,
        &["project", "config", "function", "limit", "state", "output"],
        &["batch", "force", "json"],
    )?;
    let sub = a.positional.first().map(String::as_str);
    match sub {
        Some("list") => return cmd_name_list(&a),
        Some("accept") => return cmd_name_decide(&a, true),
        Some("reject") => return cmd_name_decide(&a, false),
        Some("config") => return cmd_name_config(&a),
        _ => {}
    }

    let Some(bin_path) = a.positional.first() else {
        return fail(
            "uso: decompforge name <binario> [--project F] [--config F] [--batch] \
             [--limit N] [--function ADDR]",
        );
    };
    let config = match a.value("config") {
        Some(p) => NameForgeConfig::load(Path::new(p))?,
        None => NameForgeConfig::default(),
    };
    let data = std::fs::read(bin_path)?;
    let mut project = Project::open(&project_path(&a)?)?;
    let user = current_user();

    let addresses = match a.value("function") {
        Some(s) => vec![parse_addr(s)?],
        None => Vec::new(),
    };
    let limit = match a.value("limit") {
        Some(s) => s.parse::<usize>().or_else(|_| fail(format!("limite invalido: '{s}'")))?,
        None => 0,
    };
    let options = SuggestOptions { addresses, limit };

    let interactive = !a.flag("batch");
    if interactive && options.addresses.len() != 1 {
        return fail(
            "el modo interactivo necesita --function ADDR; usa --batch para todas las funciones",
        );
    }

    let batch = project.suggest_names(&data, &config, &options, &user)?;
    if a.flag("json") {
        println!("{}", serde_json::to_string_pretty(&batch)?);
        return Ok(());
    }

    println!(
        "nameforge: {} funciones, {} propuestas, {} descartadas",
        batch.functions, batch.suggestions, batch.discarded
    );
    for w in &batch.warnings {
        println!("aviso: {w}");
    }
    for r in &batch.records {
        println!(
            "  {:>4}  0x{:08x}  {:<30} {:>5.2}  {}",
            r.id, r.function, r.name, r.confidence, r.reason
        );
    }

    if interactive && !batch.records.is_empty() {
        interactive_review(&mut project, &batch, a.flag("force"))?;
    }
    Ok(())
}

fn cmd_name_list(a: &Args) -> CliResult<()> {
    let p = Project::open(&project_path(a)?)?;
    let function = match a.value("function") {
        Some(s) => Some(parse_addr(s)?),
        None => None,
    };
    let rows = p.suggestions(function, a.value("state"))?;
    if a.flag("json") {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("sin propuestas");
        return Ok(());
    }
    println!(
        "{:<5} {:<10} {:<30} {:>5}  {:<8} motivo",
        "id", "funcion", "nombre", "conf", "estado"
    );
    for r in &rows {
        println!(
            "{:<5} 0x{:08x} {:<30} {:>5.2}  {:<8} {}",
            r.id, r.function, r.name, r.confidence, r.state, r.reason
        );
    }
    Ok(())
}

fn cmd_name_decide(a: &Args, accept: bool) -> CliResult<()> {
    let Some(id_text) = a.positional.get(1) else {
        return fail(if accept {
            "uso: decompforge name accept <id> [--project F] [--force]"
        } else {
            "uso: decompforge name reject <id> [--project F]"
        });
    };
    let id: i64 = id_text.parse().or_else(|_| fail(format!("id invalido: '{id_text}'")))?;
    let mut project = Project::open(&project_path(a)?)?;
    let user = current_user();
    let r = if accept {
        project.accept_suggestion(id, a.flag("force"), &user)?
    } else {
        project.reject_suggestion(id, &user)?
    };
    println!(
        "{} {}: 0x{:08x} -> {} (confianza {:.2})",
        if accept { "aceptada" } else { "rechazada" },
        r.id,
        r.function,
        r.name,
        r.confidence
    );
    Ok(())
}

fn cmd_name_config(a: &Args) -> CliResult<()> {
    let config = NameForgeConfig::default();
    let text = serde_json::to_string_pretty(&config)? + "\n";
    match a.value("output") {
        Some(out) => {
            std::fs::write(out, &text)?;
            println!("configuracion escrita en {out}");
        }
        None => print!("{text}"),
    }
    Ok(())
}

fn interactive_review(
    project: &mut Project,
    batch: &SuggestionBatch,
    force: bool,
) -> CliResult<()> {
    println!(
        "revision interactiva: enter = omitir, r = rechazar todas, numero = aceptar, f = aceptar con force"
    );
    for (i, r) in batch.records.iter().enumerate() {
        println!("  [{}] {:<30} {:>5.2}  {}", i + 1, r.name, r.confidence, r.reason);
    }
    print!("opcion: ");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Ok(());
    }
    let choice = line.trim();
    let user = current_user();
    if choice.eq_ignore_ascii_case("r") {
        for r in &batch.records {
            project.reject_suggestion(r.id, &user)?;
        }
        println!("rechazadas {} propuestas", batch.records.len());
    } else if let Ok(n) = choice.parse::<usize>() {
        if n >= 1 && n <= batch.records.len() {
            let r = project.accept_suggestion(batch.records[n - 1].id, force, &user)?;
            println!("aceptada {}: 0x{:08x} -> {}", r.id, r.function, r.name);
        } else {
            println!("opcion fuera de rango; no se acepto nada");
        }
    } else if choice.is_empty() {
        println!("omitido; las propuestas quedan pendientes");
    } else {
        println!("opcion no valida; no se acepto nada");
    }
    Ok(())
}

fn planned(cmd: &str) -> Option<&'static str> {
    Some(match cmd {
        "name" => "Fase 3 (NameForge)",
        "match" => "Fase 4 (MatchLoop)",
        "recomp" => "Fase 5/6 (StaticRecomp)",
        "lint" => "Fase 6 (portability linter)",
        "verify" => "Fase 7 (TwinRun)",
        "report" => "Fase 8 (informes y panel de progreso)",
        _ => return None,
    })
}

fn run(args: Vec<String>) -> CliResult<()> {
    let Some(cmd) = args.first().map(String::as_str) else {
        print!("{}", USAGE.replace("{VERSION}", VERSION));
        return Ok(());
    };
    let rest = &args[1..];
    match cmd {
        "-h" | "--help" | "help" => {
            print!("{}", USAGE.replace("{VERSION}", VERSION));
            Ok(())
        }
        "-V" | "--version" | "version" => {
            println!("decompforge {VERSION}");
            Ok(())
        }
        "init" => cmd_init(rest),
        "load" => cmd_load(rest),
        "analyze" => cmd_analyze(rest),
        "info" => cmd_info(rest),
        "export" => cmd_export(rest),
        "apply" => cmd_apply(rest),
        "name" => cmd_name(rest),
        other => match planned(other) {
            Some(phase) => Err(CliError {
                msg: format!("el comando '{other}' aun no esta implementado (llegara en {phase})"),
                code: 2,
            }),
            None => fail(format!("comando desconocido: '{other}' (prueba `decompforge help`)")),
        },
    }
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e.msg);
            ExitCode::from(e.code)
        }
    }
}
