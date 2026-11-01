use decompforge_core::loader::{detect, load};
use decompforge_core::synthetic as syn;
use decompforge_core::{Arch, Endian, Error, FlatSpec, Format, LoadOptions};

fn opts() -> LoadOptions {
    LoadOptions::default()
}

fn sec<'a>(b: &'a decompforge_core::LoadedBinary, name: &str) -> &'a decompforge_core::Section {
    b.sections.iter().find(|s| s.name == name).unwrap_or_else(|| panic!("falta seccion {name}"))
}

#[test]
fn elf_mips_le32_ps2_like() {
    let b = load(&syn::elf_mips_le32(), &opts()).unwrap();
    assert_eq!((b.format, b.arch, b.endian, b.bits), (Format::Elf, Arch::Mips, Endian::Little, 32));
    assert_eq!(b.entry, Some(0x0010_0000));
    assert_eq!(b.sections.len(), 3);
    let text = sec(&b, ".text");
    assert_eq!((text.start, text.size, text.perms.as_str()), (0x0010_0000, 8, "r-x"));
    assert_eq!(sec(&b, ".data").perms, "rw-");
    let bss = sec(&b, ".bss");
    assert_eq!((bss.size, bss.file_offset), (0x40, None));
    assert!(b.notes.iter().any(|n| n.contains("PS2")));
}

#[test]
fn elf_ppc_be32() {
    let b = load(&syn::elf_ppc_be32(), &opts()).unwrap();
    assert_eq!((b.arch, b.endian, b.bits), (Arch::PowerPc, Endian::Big, 32));
    assert_eq!(b.entry, Some(0x0001_0000));
    assert_eq!(sec(&b, ".text").start, 0x0001_0000);
}

#[test]
fn elf_aarch64_and_x86_64() {
    let a = load(&syn::elf_aarch64(), &opts()).unwrap();
    assert_eq!((a.arch, a.endian, a.bits), (Arch::Arm64, Endian::Little, 64));
    let x = load(&syn::elf_x86_64(), &opts()).unwrap();
    assert_eq!((x.arch, x.endian, x.bits), (Arch::X86_64, Endian::Little, 64));
    assert_eq!(x.entry, Some(0x40_1000));
}

#[test]
fn dol_is_detected_without_magic_and_loaded() {
    let d = syn::dol_ppc();
    assert_eq!(detect(&d).unwrap(), Format::Dol);
    let b = load(&d, &opts()).unwrap();
    assert_eq!((b.arch, b.endian, b.bits), (Arch::PowerPc, Endian::Big, 32));
    assert_eq!(b.entry, Some(0x8000_3100));
    let names: Vec<_> = b.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, [".text0", ".data0", ".bss"]);
    assert_eq!(sec(&b, ".bss").file_offset, None);
}

#[test]
fn dol_validation_rejects_incoherent_header() {
    let mut d = syn::dol_ppc();
    d[0xE0..0xE4].copy_from_slice(&0x9000_0000u32.to_be_bytes()); // entrada fuera del texto
    assert!(matches!(detect(&d), Err(Error::UnknownFormat)));
    // Datos aleatorios no deben parecer un DOL.
    assert!(matches!(detect(&[0x41u8; 0x400]), Err(Error::UnknownFormat)));
}

#[test]
fn pe_x86_64() {
    let b = load(&syn::pe_x86_64(), &opts()).unwrap();
    assert_eq!((b.format, b.arch, b.bits), (Format::Pe, Arch::X86_64, 64));
    assert_eq!(b.entry, Some(0x1_4000_1000));
    let t = sec(&b, ".text");
    assert_eq!((t.start, t.perms.as_str(), t.file_offset), (0x1_4000_1000, "r-x", Some(0x200)));
    assert_eq!(sec(&b, ".data").perms, "rw-");
}

#[test]
fn nso_header_plain_and_compressed() {
    let b = load(&syn::nso_arm64(false), &opts()).unwrap();
    assert_eq!(
        (b.format, b.arch, b.endian, b.bits),
        (Format::Nso, Arch::Arm64, Endian::Little, 64)
    );
    let names: Vec<_> = b.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, [".text", ".rodata", ".data", ".bss"]);
    assert_eq!(sec(&b, ".rodata").start, 0x1000);
    assert_eq!(sec(&b, ".bss").start, 0x2010);
    assert!(b.notes.is_empty());

    let c = load(&syn::nso_arm64(true), &opts()).unwrap();
    assert_eq!(c.notes.len(), 3);
    assert!(c.notes[0].contains("LZ4"));
}

#[test]
fn self_container_is_rejected_as_protected() {
    let err = load(&syn::fake_self_header(), &opts()).unwrap_err();
    assert!(matches!(err, Error::Protected { .. }));
    assert!(err.to_string().contains("no descifra ni elude"));
    // PS4 SELF.
    let mut ps4 = vec![0x4f, 0x15, 0x3d, 0x1d];
    ps4.resize(64, 0);
    assert!(matches!(load(&ps4, &opts()), Err(Error::Protected { .. })));
}

#[test]
fn recognized_but_unsupported_containers() {
    assert!(matches!(
        load(b"XEX2\0\0\0\0", &opts()),
        Err(Error::Unsupported { format: "XEX", .. })
    ));
    let mut iso = vec![0u8; 0x8100];
    iso[0x8001..0x8006].copy_from_slice(b"CD001");
    assert!(matches!(load(&iso, &opts()), Err(Error::Unsupported { format: "ISO 9660", .. })));
    assert!(matches!(load(b"PFS0\0\0\0\0", &opts()), Err(Error::Unsupported { .. })));
}

#[test]
fn unknown_needs_flat_spec() {
    let rom = vec![0x13u8; 256];
    assert!(matches!(load(&rom, &opts()), Err(Error::UnknownFormat)));
    let spec = FlatSpec { arch: Arch::Arm, endian: Endian::Little, base: 0x0800_0000 };
    let b = load(&rom, &LoadOptions { flat: Some(spec) }).unwrap();
    assert_eq!((b.format, b.arch, b.bits), (Format::Flat, Arch::Arm, 32));
    assert_eq!((b.sections[0].start, b.sections[0].size), (0x0800_0000, 256));
    // Una ROM plana vacia es un error, no un panic.
    assert!(load(&[], &LoadOptions { flat: Some(spec) }).is_err());
}

#[test]
fn truncated_files_are_errors() {
    for bin in [syn::elf_mips_le32(), syn::elf_aarch64(), syn::pe_x86_64(), syn::nso_arm64(false)] {
        let cut = &bin[..bin.len() / 2];
        assert!(load(cut, &opts()).is_err(), "un archivo truncado debe rechazarse");
    }
}

/// Fuzzing ligero y determinista: ninguna entrada malformada puede provocar
/// un panic (RNF-03). El fuzzing real con cargo-fuzz queda para el CI.
#[test]
fn mutated_inputs_never_panic() {
    let seeds = [
        syn::elf_mips_le32(),
        syn::elf_ppc_be32(),
        syn::elf_aarch64(),
        syn::dol_ppc(),
        syn::pe_x86_64(),
        syn::nso_arm64(true),
    ];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let flat =
        LoadOptions { flat: Some(FlatSpec { arch: Arch::Mips, endian: Endian::Little, base: 0 }) };
    for seed in &seeds {
        for _ in 0..3000 {
            let mut d = seed.clone();
            for _ in 0..(1 + rnd() % 6) {
                let i = (rnd() % d.len() as u64) as usize;
                d[i] = match rnd() % 3 {
                    0 => 0xFF,
                    1 => 0x00,
                    _ => rnd() as u8,
                };
            }
            if rnd() % 4 == 0 {
                d.truncate((rnd() % d.len() as u64) as usize);
            }
            let _ = load(&d, &opts());
            let _ = load(&d, &flat);
        }
    }
}

#[test]
fn stripped_elf_falls_back_to_pt_load_segments() {
    // Partimos de un ELF32 LE valido, quitamos la tabla de secciones y
    // anadimos una tabla de segmentos con un PT_LOAD ejecutable.
    let mut d = syn::elf_mips_le32();
    let phoff = d.len() as u32;
    d[0x30..0x32].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0
    d[0x1C..0x20].copy_from_slice(&phoff.to_le_bytes()); // e_phoff
    d[0x2C..0x2E].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    let ph: [u32; 8] = [1, 0x34, 0x0010_0000, 0x0010_0000, 8, 0x20, 5, 4]; // PT_LOAD r-x
    for v in ph {
        d.extend_from_slice(&v.to_le_bytes());
    }
    let b = load(&d, &opts()).unwrap();
    assert_eq!(b.sections.len(), 1);
    let s = &b.sections[0];
    assert_eq!(
        (s.name.as_str(), s.start, s.size, s.perms.as_str()),
        ("LOAD0", 0x0010_0000, 0x20, "r-x")
    );
    assert_eq!(s.file_offset, Some(0x34));
    assert!(b.notes.iter().any(|n| n.contains("PT_LOAD")));

    // Segmento que se sale del archivo -> error, no panic.
    let n = d.len();
    d[n - 16..n - 12].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes()); // p_filesz enorme
    assert!(load(&d, &opts()).is_err());
}

#[test]
fn elf_without_any_tables_loads_with_a_note() {
    let mut d = syn::elf_mips_le32();
    d[0x30..0x32].copy_from_slice(&0u16.to_le_bytes()); // e_shnum = 0, sin phdrs
    let b = load(&d, &opts()).unwrap();
    assert!(b.sections.is_empty());
    assert!(b.notes.iter().any(|n| n.contains("ni de segmentos")));
}
