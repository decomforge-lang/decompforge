//! Pruebas de integracion del analisis recursivo: cargar un binario sintetico,
//! detectar funciones y llamadas, y comprobar que el estado se persiste y se
//! puede repetir sin perder trabajo del usuario.

use decompforge_core::synthetic as syn;
use decompforge_core::{Arch, Endian, Error, FlatSpec, LoadOptions, Project};

fn loaded(bin: &[u8], platform: &str) -> Project {
    let mut p = Project::in_memory("analisis", Some(platform)).unwrap();
    p.import_binary(bin, &LoadOptions::default(), "tester").unwrap();
    p
}

fn functions(p: &Project) -> Vec<(u64, u64)> {
    p.conn()
        .prepare("SELECT address, size FROM function ORDER BY address")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn calls(p: &Project) -> Vec<(u64, u64)> {
    p.conn()
        .prepare("SELECT src, dst FROM xref WHERE kind = 'call' ORDER BY src, dst")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn mips_recursive_detection() {
    let bin = syn::elf_mips_le32_program();
    let mut p = loaded(&bin, "ps2");
    let s = p.analyze(&bin, "tester").unwrap();
    assert_eq!((s.functions, s.call_edges, s.truncated), (3, 2, false));
    assert_eq!(s.instructions, 10);
    assert_eq!(functions(&p), [(0x0010_0000, 0x18), (0x0010_0020, 0x08), (0x0010_0030, 0x08)]);
    assert_eq!(calls(&p), [(0x0010_0000, 0x0010_0020), (0x0010_0000, 0x0010_0030)]);
    let info = p.info().unwrap();
    assert_eq!(info.functions, 3);
    assert_eq!(info.functions_by_state.get("detected"), Some(&3));
}

#[test]
fn ppc_recursive_detection() {
    let bin = syn::elf_ppc_be32_program();
    let mut p = loaded(&bin, "gamecube");
    let s = p.analyze(&bin, "tester").unwrap();
    assert_eq!((s.functions, s.call_edges, s.instructions), (3, 2, 10));
    assert_eq!(functions(&p), [(0x0001_0000, 0x18), (0x0001_0020, 0x08), (0x0001_0030, 0x08)]);
    assert_eq!(calls(&p), [(0x0001_0000, 0x0001_0020), (0x0001_0000, 0x0001_0030)]);
}

#[test]
fn aarch64_recursive_detection() {
    let bin = syn::elf_aarch64_program();
    let mut p = loaded(&bin, "switch");
    let s = p.analyze(&bin, "tester").unwrap();
    assert_eq!((s.functions, s.call_edges, s.instructions), (3, 2, 9));
    assert_eq!(functions(&p), [(0x0040_0000, 0x14), (0x0040_0020, 0x08), (0x0040_0030, 0x08)]);
    assert_eq!(calls(&p), [(0x0040_0000, 0x0040_0020), (0x0040_0000, 0x0040_0030)]);
}

#[test]
fn x86_64_recursive_detection() {
    let bin = syn::elf_x86_64_program();
    let mut p = loaded(&bin, "pc");
    let s = p.analyze(&bin, "tester").unwrap();
    assert_eq!((s.functions, s.call_edges, s.instructions), (3, 2, 9));
    assert_eq!(functions(&p), [(0x0040_1000, 0x0D), (0x0040_1010, 0x06), (0x0040_1020, 0x06)]);
    assert_eq!(calls(&p), [(0x0040_1000, 0x0040_1010), (0x0040_1000, 0x0040_1020)]);
}

#[test]
fn nso_lz4_is_analyzed_over_the_materialized_image() {
    let bin = syn::nso_arm64_lz4();
    let mut p = loaded(&bin, "switch");
    let s = p.analyze(&bin, "tester").unwrap();
    // La imagen descomprimida empieza con `ret`: una funcion de 4 bytes. Sin
    // descompresion, esos bytes serian la cabecera del bloque LZ4.
    assert_eq!((s.functions, s.instructions), (1, 1));
    assert_eq!(functions(&p), [(0x0, 4)]);
}

#[test]
fn reanalysis_is_idempotent_and_preserves_user_work() {
    let bin = syn::elf_mips_le32_program();
    let mut p = loaded(&bin, "ps2");
    p.analyze(&bin, "tester").unwrap();

    p.conn()
        .execute(
            "UPDATE function SET name = 'game_helper', state = 'named' WHERE address = ?1",
            [0x0010_0020i64],
        )
        .unwrap();
    let before = p.export_json().unwrap();

    let again = p.analyze(&bin, "tester").unwrap();
    assert_eq!((again.functions, again.call_edges), (3, 2));
    assert_eq!(p.export_json().unwrap(), before);

    let row: (Option<String>, String) = p
        .conn()
        .query_row("SELECT name, state FROM function WHERE address = ?1", [0x0010_0020i64], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(row, (Some("game_helper".into()), "named".into()));

    let analyses: i64 = p
        .conn()
        .query_row("SELECT COUNT(*) FROM audit_log WHERE action = 'analyze'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(analyses, 2);
}

#[test]
fn binary_must_match_the_loaded_sha256() {
    let bin = syn::elf_mips_le32_program();
    let mut p = loaded(&bin, "ps2");
    let mut other = bin.clone();
    let middle = other.len() / 2;
    other[middle] ^= 0xFF;

    let err = p.analyze(&other, "tester").unwrap_err();
    assert!(matches!(err, Error::Analysis(_)));
    assert_eq!(p.info().unwrap().functions, 0);
    let analyses: i64 = p
        .conn()
        .query_row("SELECT COUNT(*) FROM audit_log WHERE action = 'analyze'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(analyses, 0);
}

#[test]
fn analysis_requires_a_loaded_binary() {
    let mut p = Project::in_memory("vacio", None).unwrap();
    assert!(matches!(p.analyze(b"nada", "t"), Err(Error::Project(_))));
}

#[test]
fn spu_is_loaded_but_not_analyzable() {
    let bin = syn::elf_spu();
    let mut p = loaded(&bin, "ps3");
    assert_eq!(p.info().unwrap().architecture.as_deref(), Some("spu"));
    let err = p.analyze(&bin, "tester").unwrap_err();
    assert!(matches!(err, Error::Unsupported { format: "SPU", .. }));
    assert_eq!(p.info().unwrap().functions, 0);
}

#[test]
fn unknown_architecture_is_unsupported() {
    let bin = syn::elf_mips_le32_program();
    let mut p = loaded(&bin, "desconocida");
    p.conn().execute("UPDATE project SET architecture = 'unknown' WHERE id = 1", []).unwrap();
    let err = p.analyze(&bin, "tester").unwrap_err();
    assert!(matches!(err, Error::Unsupported { format: "desconocido", .. }));
}

/// Fuzzing ligero y determinista del analisis. Entradas aleatorias no pueden
/// provocar panics ni agotar los limites (RNF-03).
#[test]
fn mutated_code_never_panics() {
    let mut state = 0xD1CE_BA5E_F00D_1234u64;
    let mut rnd = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let base = 0x1000u64;
    for _ in 0..64 {
        let len = 32 + (rnd() % 256) as usize;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(rnd() as u8);
        }
        let mut p = Project::in_memory("fuzz", None).unwrap();
        let opts = LoadOptions {
            flat: Some(FlatSpec { arch: Arch::X86_64, endian: Endian::Little, base }),
        };
        p.import_binary(&data, &opts, "fuzz").unwrap();
        p.conn()
            .execute(
                "INSERT INTO symbol (address, name, kind, origin) VALUES (?1, 'seed', 'function', 'test')",
                [base as i64],
            )
            .unwrap();
        let _ = p.analyze(&data, "fuzz");
    }
}
