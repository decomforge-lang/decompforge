//! Pruebas de extremo a extremo de la CLI (Fase 2: `export --format re-json`
//! y `apply`). Usan binarios sinteticos propios; nunca contenido de terceros.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "decompforge-cli-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_decompforge"))
        .args(args)
        .output()
        .expect("no se pudo ejecutar decompforge")
}

fn write_json(path: &Path, doc: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(doc).unwrap() + "\n").unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn apply_roundtrip_updates_names_signatures_and_comments() {
    let dir = TempDir::new();
    let project = dir.file("demo.dfproj");
    let out = run(&["init", "demo", "--sample", "--dir", dir.0.to_str().unwrap()]);
    // `init` crea <dir>/<nombre>.dfproj.
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let export = dir.file("export.json");
    let out = run(&[
        "export",
        "--format",
        "re-json",
        "--project",
        project.to_str().unwrap(),
        "--output",
        export.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let doc = read_json(&export);
    assert_eq!(doc["schema_version"], "re-1.0");
    let address = doc["functions"][0]["address"].as_str().unwrap().to_string();

    let updates = dir.file("updates.json");
    write_json(
        &updates,
        &json!({
            "schema_version": "re-1.0",
            "kind": "updates",
            "functions": [{
                "address": address,
                "name": "game_update_player",
                "signature": "void game_update_player(void)",
                "comments": [{"address": address, "text": "funcion renombrada por la CLI"}]
            }]
        }),
    );
    let out = run(&["apply", updates.to_str().unwrap(), "--project", project.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 nombres"), "{stdout}");

    let export2 = dir.file("export2.json");
    let out = run(&[
        "export",
        "--format",
        "re-json",
        "--project",
        project.to_str().unwrap(),
        "--output",
        export2.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let doc = read_json(&export2);
    let f = doc["functions"].as_array().unwrap().iter().find(|f| f["address"] == address).unwrap();
    assert_eq!(f["name"], "game_update_player");
    assert_eq!(f["signature"], "void game_update_player(void)");
    assert_eq!(f["comments"][0]["text"], "funcion renombrada por la CLI");
}

#[test]
fn apply_accepts_utf8_bom() {
    let dir = TempDir::new();
    let project = dir.file("demo.dfproj");
    assert!(run(&["init", "demo", "--sample", "--dir", dir.0.to_str().unwrap()]).status.success());

    let export = dir.file("export.json");
    assert!(run(&[
        "export",
        "--format",
        "re-json",
        "--project",
        project.to_str().unwrap(),
        "--output",
        export.to_str().unwrap(),
    ])
    .status
    .success());
    let doc = read_json(&export);
    let address = doc["functions"][0]["address"].as_str().unwrap().to_string();

    let updates = dir.file("updates-bom.json");
    let text = serde_json::to_string_pretty(&json!({
        "schema_version": "re-1.0",
        "kind": "updates",
        "functions": [{"address": address, "name": "con_bom"}]
    }))
    .unwrap();
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.as_bytes());
    std::fs::write(&updates, bytes).unwrap();

    let out = run(&["apply", updates.to_str().unwrap(), "--project", project.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let info = run(&["info", "--project", project.to_str().unwrap(), "--json"]);
    let info: Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info["functions_by_state"]["named"], 1);
}

#[test]
fn apply_rejects_invalid_documents_without_touching_the_project() {
    let dir = TempDir::new();
    let project = dir.file("demo.dfproj");
    assert!(run(&["init", "demo", "--sample", "--dir", dir.0.to_str().unwrap()]).status.success());

    let bad = dir.file("bad.json");
    write_json(&bad, &json!({"schema_version": "1.0", "kind": "updates", "functions": []}));
    let out = run(&["apply", bad.to_str().unwrap(), "--project", project.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("intercambio JSON"), "{stderr}");

    let info = run(&["info", "--project", project.to_str().unwrap(), "--json"]);
    let info: Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info["functions_by_state"]["detected"], 3);
}

#[test]
fn name_config_and_list_work_on_empty_project() {
    let dir = TempDir::new();
    let project = dir.file("demo.dfproj");
    assert!(run(&["init", "demo", "--dir", dir.0.to_str().unwrap()]).status.success());

    let out = run(&["name", "config"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"provider\""), "{stdout}");

    let out = run(&["name", "list", "--project", project.to_str().unwrap(), "--json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.as_array().unwrap().is_empty());

    let out = run(&["name", "accept", "999", "--project", project.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no existe"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn re_export_requires_a_loaded_binary() {
    let dir = TempDir::new();
    let project = dir.file("vacio.dfproj");
    assert!(run(&["init", "vacio", "--dir", dir.0.to_str().unwrap()]).status.success());
    let out = run(&["export", "--format", "re-json", "--project", project.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("binario"));
}
