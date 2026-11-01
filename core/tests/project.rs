use decompforge_core::synthetic as syn;
use decompforge_core::{Error, LoadOptions, Project};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "decompforge-test-{}-{}",
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

#[test]
fn create_import_reopen_roundtrip() {
    let dir = TempDir::new();
    let path = dir.file("demo.dfproj");
    let bin = syn::elf_mips_le32();
    {
        let mut p = Project::create(&path, "demo", Some("ps2")).unwrap();
        let before = p.info().unwrap();
        assert!(!before.loaded);
        p.import_binary(&bin, &LoadOptions::default(), "tester").unwrap();
    }
    let p = Project::open(&path).unwrap();
    let info = p.info().unwrap();
    assert_eq!(info.name, "demo");
    assert_eq!(info.platform.as_deref(), Some("ps2"));
    assert!(info.loaded);
    assert_eq!(info.architecture.as_deref(), Some("mips"));
    assert_eq!(info.endian.as_deref(), Some("little"));
    assert_eq!(info.format.as_deref(), Some("elf"));
    assert_eq!(info.bits, Some(32));
    assert_eq!(info.entry, Some(0x0010_0000));
    assert_eq!(info.binary_size, Some(bin.len() as u64));
    assert_eq!(info.binary_sha256.as_deref().map(str::len), Some(64));
    assert_eq!((info.sections, info.symbols, info.functions), (3, 1, 0));
}

#[test]
fn create_refuses_existing_file_and_empty_name() {
    let dir = TempDir::new();
    let path = dir.file("x.dfproj");
    Project::create(&path, "x", None).unwrap();
    assert!(matches!(Project::create(&path, "x", None), Err(Error::Project(_))));
    assert!(matches!(Project::in_memory("   ", None), Err(Error::Project(_))));
}

#[test]
fn second_binary_is_refused() {
    let mut p = Project::in_memory("demo", None).unwrap();
    p.import_binary(&syn::elf_x86_64(), &LoadOptions::default(), "t").unwrap();
    let e = p.import_binary(&syn::elf_aarch64(), &LoadOptions::default(), "t").unwrap_err();
    assert!(matches!(e, Error::Project(_)));
    assert_eq!(p.info().unwrap().architecture.as_deref(), Some("x86_64")); // intacto
}

#[test]
fn rejected_binary_leaves_project_untouched() {
    let mut p = Project::in_memory("demo", None).unwrap();
    let e = p.import_binary(&syn::fake_self_header(), &LoadOptions::default(), "t").unwrap_err();
    assert!(matches!(e, Error::Protected { .. }));
    let info = p.info().unwrap();
    assert!(!info.loaded);
    assert_eq!(info.sections, 0);
    let loads: i64 = p
        .conn()
        .query_row("SELECT COUNT(*) FROM audit_log WHERE action='load'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(loads, 0);
    // y todavia puede cargarse un binario valido despues
    p.import_binary(&syn::dol_ppc(), &LoadOptions::default(), "t").unwrap();
    assert!(p.info().unwrap().loaded);
}

#[test]
fn audit_log_is_immutable_and_records_actions() {
    let mut p = Project::in_memory("demo", None).unwrap();
    p.import_binary(&syn::pe_x86_64(), &LoadOptions::default(), "ana").unwrap();
    let actions: Vec<(String, String)> = p
        .conn()
        .prepare("SELECT actor, action FROM audit_log ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(actions, [("system".into(), "init".into()), ("ana".into(), "load".into())]);
    assert!(p.conn().execute("UPDATE audit_log SET actor='x'", []).is_err());
    assert!(p.conn().execute("DELETE FROM audit_log", []).is_err());
}

#[test]
fn schema_enforces_function_state_and_confidence() {
    let p = Project::in_memory("demo", None).unwrap();
    let c = p.conn();
    assert!(c
        .execute(
            "INSERT INTO function (address,size,state,updated_at) VALUES (1,4,'bogus','t')",
            []
        )
        .is_err());
    c.execute("INSERT INTO function (address,size,updated_at) VALUES (4096,16,'t')", []).unwrap();
    assert!(c
        .execute("INSERT INTO ai_suggestion (function_id,kind,proposal,confidence,created_at) VALUES (1,'name','x',1.5,'t')", [])
        .is_err());
    c.execute("INSERT INTO ai_suggestion (function_id,kind,proposal,confidence,created_at) VALUES (1,'name','game_update',0.9,'t')", [])
        .unwrap();
}

#[test]
fn open_rejects_foreign_or_missing_files() {
    let dir = TempDir::new();
    assert!(Project::open(&dir.file("nope.dfproj")).is_err());
    let other = dir.file("other.db");
    let c = rusqlite::Connection::open(&other).unwrap();
    c.execute("CREATE TABLE t (a)", []).unwrap();
    drop(c);
    assert!(Project::open(&other).is_err());
}

#[test]
fn newer_schema_is_refused() {
    let dir = TempDir::new();
    let path = dir.file("future.dfproj");
    drop(Project::create(&path, "f", None).unwrap());
    let c = rusqlite::Connection::open(&path).unwrap();
    c.pragma_update(None, "user_version", 999).unwrap();
    drop(c);
    assert!(matches!(Project::open(&path), Err(Error::Project(_))));
}

#[test]
fn export_json_matches_exchange_format_and_is_deterministic() {
    let make = || {
        let mut p = Project::in_memory("demo", Some("ps2")).unwrap();
        p.import_binary(&syn::elf_mips_le32(), &LoadOptions::default(), "t").unwrap();
        // una funcion con una llamada, como en el ejemplo 9.4 del documento
        let c = p.conn();
        c.execute(
            "INSERT INTO function (address,size,name,state,updated_at) VALUES (1048832,96,'game_update_player','named','t')",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO xref (src,dst,kind) VALUES (1048832,1049344,'call')", []).unwrap();
        p.export_json().unwrap()
    };
    let (a, b) = (make(), make());
    assert_eq!(a, b, "el export debe ser identico entre ejecuciones (RNF-02)");

    assert_eq!(a["schema_version"], "1.0");
    assert_eq!(a["project"]["arch"], "mips");
    assert_eq!(a["project"]["endian"], "little");
    assert_eq!(a["project"]["entry"], "0x00100000");
    assert_eq!(a["sections"][0]["name"], ".text");
    assert_eq!(a["sections"][0]["start"], "0x00100000");
    assert_eq!(a["symbols"][0]["name"], "_entry");
    let f = &a["functions"][0];
    assert_eq!(f["address"], "0x00100100");
    assert_eq!(f["name"], "game_update_player");
    assert_eq!(f["state"], "named");
    assert_eq!(f["calls"][0], "0x00100300");
}

#[test]
fn export_of_empty_project_is_valid() {
    let p = Project::in_memory("vacio", None).unwrap();
    let j = p.export_json().unwrap();
    assert_eq!(j["project"]["arch"], serde_json::Value::Null);
    assert_eq!(j["functions"], serde_json::json!([]));
}

fn analyzed_project() -> Project {
    let mut p = Project::in_memory("demo", Some("ps2")).unwrap();
    let bin = syn::elf_mips_le32();
    p.import_binary(&bin, &LoadOptions::default(), "t").unwrap();
    p.analyze(&bin, "t").unwrap();
    p
}

fn first_function(p: &Project) -> u64 {
    p.conn()
        .query_row("SELECT address FROM function ORDER BY address LIMIT 1", [], |r| {
            Ok(r.get::<_, i64>(0)? as u64)
        })
        .unwrap()
}

#[test]
fn apply_updates_roundtrip_and_state_transition() {
    let mut p = analyzed_project();
    let a = first_function(&p);
    let doc = serde_json::json!({
        "schema_version": "re-1.0",
        "kind": "updates",
        "source": {"tool": "prueba"},
        "functions": [{
            "address": format!("0x{a:08x}"),
            "name": "game_update_player",
            "signature": "void game_update_player(Player *p)",
            "comments": [
                {"address": format!("0x{a:08x}"), "text": "actualiza el jugador"},
                {"address": format!("0x{:08x}", a + 4), "text": "delay slot"}
            ]
        }]
    });
    let s = p.apply_updates(&doc, "tester").unwrap();
    assert_eq!((s.functions, s.names, s.signatures, s.comments), (1, 1, 1, 2));

    let (name, state, signature): (String, String, String) = p
        .conn()
        .query_row(
            "SELECT name, state, signature FROM function WHERE address = ?1",
            [a as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(name, "game_update_player");
    assert_eq!(state, "named");
    assert_eq!(signature, "void game_update_player(Player *p)");

    let re = p.export_re_json().unwrap();
    assert_eq!(re["schema_version"], "re-1.0");
    assert_eq!(re["kind"], "export");
    assert_eq!(re["project"]["arch"], "mips");
    let f = re["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["address"] == format!("0x{a:08x}"))
        .unwrap();
    assert_eq!(f["name"], "game_update_player");
    assert_eq!(f["signature"], "void game_update_player(Player *p)");

    // Verificamos que los comentarios estén en la base de datos (todo o nada).
    let all_comments: Vec<(i64, String)> = p
        .conn()
        .prepare("SELECT address, text FROM comment ORDER BY address")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    let comment_texts: Vec<&str> = all_comments.iter().map(|(_, t)| t.as_str()).collect();
    assert!(
        comment_texts.iter().any(|t| t.contains("actualiza")),
        "el comentario 'actualiza el jugador' debe estar en la BD; got {all_comments:?}"
    );
    assert!(
        comment_texts.iter().any(|t| t.contains("delay slot")),
        "el comentario 'delay slot' debe estar en la BD; got {all_comments:?}"
    );

    // La re-exportación incluye los comentarios cuya dirección cae dentro del range de la función.
    let cmts = f["comments"].as_array();
    assert!(cmts.is_some(), "debe haber comentarios en la re-exportación");
    if let Some(c) = cmts {
        let texts: Vec<&str> = c.iter().map(|v| v["text"].as_str().unwrap_or_default()).collect();
        // Al menos uno de los dos debe aparecer (el que cae dentro del rango de la función).
        assert!(
            texts.iter().any(|t| t.contains("actualiza") || t.contains("delay slot")),
            "al menos un comentario debe aparecer en la re-exportación; got {c:?}"
        );
    }
    // segunda aplicacion idempotente
    p.apply_updates(&doc, "tester").unwrap();
    let n: i64 = p.conn().query_row("SELECT COUNT(*) FROM comment", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 2);
}

#[test]
fn apply_updates_is_all_or_nothing_and_validates() {
    let mut p = analyzed_project();
    let a = first_function(&p);
    let missing = 0x00ff_ffffu64;
    let doc = serde_json::json!({
        "schema_version": "re-1.0",
        "kind": "updates",
        "functions": [
            {"address": format!("0x{a:08x}"), "name": "no_debe_aplicarse"},
            {"address": format!("0x{missing:08x}"), "name": "fantasma"}
        ]
    });
    assert!(matches!(p.apply_updates(&doc, "t"), Err(Error::Exchange(_))));
    let name: Option<String> = p
        .conn()
        .query_row("SELECT name FROM function WHERE address = ?1", [a as i64], |r| r.get(0))
        .unwrap();
    assert_eq!(name, None, "la primera actualizacion no debe aplicarse");

    let bad = [
        serde_json::json!({"schema_version": "1.0", "kind": "updates", "functions": []}),
        serde_json::json!({"schema_version": "re-1.0", "kind": "export", "functions": []}),
        serde_json::json!({"schema_version": "re-1.0", "kind": "updates"}),
        serde_json::json!({"schema_version": "re-1.0", "kind": "updates", "functions": [
            {"address": "0x01000000"}
        ]}),
        serde_json::json!({"schema_version": "re-1.0", "kind": "updates", "functions": [
            {"address": format!("0x{a:08x}"), "name": "  "}
        ]}),
        serde_json::json!({"schema_version": "re-1.0", "kind": "updates", "functions": [
            {"address": "0x01000000", "name": "a"},
            {"address": "0x01000000", "name": "b"}
        ]}),
        serde_json::json!({"schema_version": "re-1.0", "kind": "updates", "functions": [
            {"address": "0xx", "name": "a"}
        ]}),
    ];
    for d in bad {
        assert!(matches!(p.apply_updates(&d, "t"), Err(Error::Exchange(_))), "{d}");
    }
    let actions: i64 = p
        .conn()
        .query_row("SELECT COUNT(*) FROM audit_log WHERE action='apply'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(actions, 0);
}

#[test]
fn apply_updates_preserves_advanced_states_and_named_functions_get_fallback() {
    let mut p = analyzed_project();
    let a = first_function(&p);
    p.conn().execute("UPDATE function SET state='verified' WHERE address=?1", [a as i64]).unwrap();
    let doc = serde_json::json!({
        "schema_version": "re-1.0", "kind": "updates",
        "functions": [{"address": format!("0x{a:08x}"), "name": "keep_verified"}]
    });
    p.apply_updates(&doc, "t").unwrap();
    let state: String = p
        .conn()
        .query_row("SELECT state FROM function WHERE address=?1", [a as i64], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "verified");

    // Las funciones sin nombre se exportan con un nombre estable para Ghidra.
    let re = p.export_re_json().unwrap();
    for f in re["functions"].as_array().unwrap() {
        assert!(f["name"].as_str().is_some_and(|n| !n.is_empty()));
    }
}

#[test]
fn re_export_is_deterministic_and_normalizes_types_and_xrefs() {
    let make = || {
        let p = analyzed_project();
        p.conn()
            .execute(
                "INSERT INTO \"type\" (name, category, definition, size)
                 VALUES ('Player', 'Struct', 'struct Player { int hp; };', 4)",
                [],
            )
            .unwrap();
        p.conn()
            .execute("INSERT INTO xref (src,dst,kind) VALUES (1048576,1048832,'read')", [])
            .unwrap();
        p.export_re_json().unwrap()
    };
    let (a, b) = (make(), make());
    assert_eq!(a, b, "el documento re-1.0 debe ser determinista (RNF-02)");
    assert_eq!(a["types"][0]["name"], "Player");
    assert_eq!(a["types"][0]["kind"], "struct");
    assert_eq!(a["source"]["tool"], "decompforge");
    assert!(a["xrefs"].as_array().unwrap().iter().any(|x| x["kind"] == "read"));

    // Un proyecto sin binario no puede producir un documento re-1.0 valido.
    let empty = Project::in_memory("vacio", None).unwrap();
    assert!(matches!(empty.export_re_json(), Err(Error::Exchange(_))));
}
