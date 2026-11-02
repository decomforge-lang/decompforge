use decompforge_core::nameforge::NameForgeConfig;
use decompforge_core::synthetic as syn;
use decompforge_core::{LoadOptions, Project, SuggestOptions};

#[test]
fn nameforge_suggests_and_persists() {
    let bin = syn::elf_mips_le32_strings();
    let mut p = Project::in_memory("demo", Some("ps2")).unwrap();
    p.import_binary(&bin, &LoadOptions::default(), "tester").unwrap();
    p.analyze(&bin, "tester").unwrap();

    let config = NameForgeConfig::default();
    let batch = p.suggest_names(&bin, &config, &SuggestOptions::default(), "tester").unwrap();
    assert!(batch.functions >= 1);
    assert!(batch.suggestions >= 1);
    assert!(batch.records.iter().any(|r| r.name == "player_speed"));

    let pending = p.suggestions(None, Some("pending")).unwrap();
    assert!(!pending.is_empty());
    let info = p.info().unwrap();
    assert!(info.name_suggestions >= 1);
    assert!(info.name_suggestions_pending >= 1);
}

#[test]
fn nameforge_accept_and_reject() {
    let bin = syn::elf_mips_le32_strings();
    let mut p = Project::in_memory("demo", Some("ps2")).unwrap();
    p.import_binary(&bin, &LoadOptions::default(), "tester").unwrap();
    p.analyze(&bin, "tester").unwrap();

    let config = NameForgeConfig::default();
    let batch = p.suggest_names(&bin, &config, &SuggestOptions::default(), "tester").unwrap();
    assert!(!batch.records.is_empty());

    let id = batch.records[0].id;
    let accepted = p.accept_suggestion(id, false, "tester").unwrap();
    assert_eq!(accepted.state, "accepted");

    // Aceptar de nuevo falla.
    assert!(p.accept_suggestion(id, false, "tester").is_err());

    // Rechazar otra propuesta.
    if batch.records.len() > 1 {
        let id2 = batch.records[1].id;
        let rejected = p.reject_suggestion(id2, "tester").unwrap();
        assert_eq!(rejected.state, "rejected");
    }
}

#[test]
fn nameforge_force_required_for_named_function() {
    let bin = syn::elf_mips_le32_strings();
    let mut p = Project::in_memory("demo", Some("ps2")).unwrap();
    p.import_binary(&bin, &LoadOptions::default(), "tester").unwrap();
    p.analyze(&bin, "tester").unwrap();

    let config = NameForgeConfig::default();
    let batch = p.suggest_names(&bin, &config, &SuggestOptions::default(), "tester").unwrap();
    assert!(!batch.records.is_empty());
    let id = batch.records[0].id;
    p.accept_suggestion(id, false, "tester").unwrap();

    let addr = batch.records[0].function;
    let batch2 = p
        .suggest_names(&bin, &config, &SuggestOptions { addresses: vec![addr], limit: 0 }, "tester")
        .unwrap();
    if !batch2.records.is_empty() {
        let id2 = batch2.records[0].id;
        assert!(p.accept_suggestion(id2, false, "tester").is_err());
        assert!(p.accept_suggestion(id2, true, "tester").is_ok());
    }
}

#[test]
fn nameforge_migration_v4_columns_exist() {
    let p = Project::in_memory("demo", None).unwrap();
    let c = p.conn();
    // Las columnas de v4 deben existir.
    let mut st = c.prepare("PRAGMA table_info(ai_suggestion)").unwrap();
    let cols: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<std::result::Result<Vec<String>, _>>()
        .unwrap();
    for required in ["reason", "seq", "decided_at"] {
        assert!(cols.iter().any(|c| c == required), "falta columna {required}");
    }
}
