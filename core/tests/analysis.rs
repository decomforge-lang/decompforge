//! Pruebas de integracion del analisis recursivo: cargar un binario sintetico,
//! detectar funciones y llamadas, y comprobar que el estado se persiste y se
//! puede repetir sin perder trabajo del usuario.

use decompforge_core::analysis::{analyze, AnalysisOptions, EdgeKind, Image};
use decompforge_core::loader::Section;
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

fn blocks(p: &Project) -> Vec<(u64, u64, u64)> {
    p.conn()
        .prepare("SELECT address, size, instructions FROM basic_block ORDER BY address")
        .unwrap()
        .query_map([], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn cfg(p: &Project) -> Vec<(u64, u64, String)> {
    p.conn()
        .prepare("SELECT src, dst, kind FROM cfg_edge ORDER BY src, dst, kind")
        .unwrap()
        .query_map([], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64, r.get::<_, String>(2)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn mips_recursive_detection_with_delay_slots_and_cfg() {
    let bin = syn::elf_mips_le32_program();
    let mut p = loaded(&bin, "ps2");
    let s = p.analyze(&bin, "tester").unwrap();
    assert_eq!((s.functions, s.call_edges, s.truncated), (3, 2, false));
    // Los `nop` de delay slot de `jal` y del `jr $ra` final ya cuentan.
    assert_eq!(s.instructions, 13);
    assert_eq!((s.basic_blocks, s.cfg_edges), (5, 4));
    assert_eq!(functions(&p), [(0x0010_0000, 0x1c), (0x0010_0020, 0x0C), (0x0010_0030, 0x0C)]);
    assert_eq!(calls(&p), [(0x0010_0000, 0x0010_0020), (0x0010_0000, 0x0010_0030)]);
    assert_eq!(
        blocks(&p),
        [
            (0x0010_0000, 0x0C, 3),
            (0x0010_000C, 0x08, 2),
            (0x0010_0014, 0x08, 2),
            (0x0010_0020, 0x0C, 3),
            (0x0010_0030, 0x0C, 3),
        ]
    );
    assert_eq!(
        cfg(&p),
        [
            (0x0010_0000, 0x0010_000C, "fallthrough".into()),
            (0x0010_0000, 0x0010_0020, "call".into()),
            (0x0010_000C, 0x0010_0014, "fallthrough".into()),
            (0x0010_000C, 0x0010_0030, "call".into()),
        ]
    );
    // El delay slot de `jr $ra` pertenece a `main`; el relleno no es de nadie.
    assert_eq!(p.instruction_owner(0x0010_0018).unwrap(), Some(0x0010_0000));
    assert_eq!(p.instruction_owner(0x0010_001C).unwrap(), None);
    assert_eq!(p.instruction_owner(0x0010_0024).unwrap(), Some(0x0010_0020));

    let info = p.info().unwrap();
    assert_eq!(info.functions, 3);
    assert_eq!((info.basic_blocks, info.cfg_edges), (5, 4));
    assert_eq!(info.functions_by_state.get("detected"), Some(&3));
}

fn flat_image(code: &[u8], start: u64) -> Image<'_> {
    let sections = [Section {
        name: ".text".into(),
        start,
        size: code.len() as u64,
        perms: "r-x".into(),
        file_offset: Some(0),
    }];
    Image::from_sections(code, &sections)
}

#[test]
fn mips_conditional_branch_keeps_its_delay_slot_in_the_block() {
    // beq t0,t1,0x2010 ; addiu t0,t0,1 (delay) ; jr ra ; nop ; jr ra ; nop
    let code = [
        0x03, 0x00, 0x09, 0x11, // beq t0,t1,0x2010
        0x01, 0x00, 0x08, 0x25, // addiu t0,t0,1 (delay slot)
        0x08, 0x00, 0xE0, 0x03, // jr ra
        0x00, 0x00, 0x00, 0x00, // nop (delay slot)
        0x08, 0x00, 0xE0, 0x03, // jr ra (destino de la rama)
        0x00, 0x00, 0x00, 0x00, // nop (delay slot)
    ];
    let img = flat_image(&code, 0x2000);
    let a = analyze(&img, Arch::Mips, Endian::Little, 32, &[0x2000], &AnalysisOptions::default())
        .unwrap();
    assert_eq!(a.instructions, 6);
    assert_eq!(a.functions.len(), 1);
    assert_eq!((a.functions[0].address, a.functions[0].size), (0x2000, 0x18));
    assert_eq!(a.blocks.len(), 3);
    assert_eq!((a.blocks[0].start, a.blocks[0].end), (0x2000, 0x2008));
    assert_eq!(a.blocks[0].instructions, 2); // rama + delay slot
    assert_eq!(a.owner(0x2004), Some(0x2000)); // el delay slot es de la funcion
    assert_eq!(
        a.cfg_edges,
        [
            decompforge_core::analysis::CfgEdge {
                src: 0x2000,
                dst: 0x2008,
                kind: EdgeKind::Fallthrough,
            },
            decompforge_core::analysis::CfgEdge {
                src: 0x2000,
                dst: 0x2010,
                kind: EdgeKind::Branch,
            },
        ]
    );
}

#[test]
fn a_jump_to_another_known_function_is_a_tail_call_not_an_inline_body() {
    // j 0x3010 ; nop (delay) ; relleno ; jr ra ; nop
    let code = [
        0x04, 0x0C, 0x00, 0x08, // j 0x3010
        0x00, 0x00, 0x00, 0x00, // nop (delay slot)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0xE0, 0x03, // jr ra
        0x00, 0x00, 0x00, 0x00, // nop (delay slot)
    ];
    let img = flat_image(&code, 0x3000);
    let a = analyze(
        &img,
        Arch::Mips,
        Endian::Little,
        32,
        &[0x3000, 0x3010],
        &AnalysisOptions::default(),
    )
    .unwrap();
    assert_eq!(a.functions.len(), 2);
    assert_eq!((a.functions[0].address, a.functions[0].size), (0x3000, 0x08));
    assert_eq!((a.functions[1].address, a.functions[1].size), (0x3010, 0x08));
    assert_eq!(a.owner(0x3000), Some(0x3000));
    assert_eq!(a.owner(0x3004), Some(0x3000)); // delay slot del salto
    assert_eq!(a.owner(0x3010), Some(0x3010));
    assert!(a
        .cfg_edges
        .iter()
        .any(|e| e.src == 0x3000 && e.dst == 0x3010 && e.kind == EdgeKind::TailCall));
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
