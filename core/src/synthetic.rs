//! Generadores de binarios SINTETICOS.
//!
//! Todo lo que produce este modulo lo escribe el propio proyecto: cabeceras
//! minimas validas y unas pocas instrucciones triviales (`jr $ra`, `blr`,
//! `ret`...). No contiene ni deriva de ningun juego ni SDK (ver
//! docs/ACCEPTABLE_USE.md y seccion 12.2 del Documento Maestro).

struct W {
    buf: Vec<u8>,
    big: bool,
}

impl W {
    fn new(big: bool) -> Self {
        W { buf: Vec::new(), big }
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&if self.big { v.to_be_bytes() } else { v.to_le_bytes() });
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    fn pad_to(&mut self, len: usize) {
        assert!(self.buf.len() <= len, "pad_to hacia atras");
        self.buf.resize(len, 0);
    }
    fn set_u32(&mut self, off: usize, v: u32) {
        let b = if self.big { v.to_be_bytes() } else { v.to_le_bytes() };
        self.buf[off..off + 4].copy_from_slice(&b);
    }
}

fn align(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

// ---------------------------------------------------------------- ELF

/// Seccion de un ELF sintetico.
pub struct ElfSection {
    /// Nombre que se escribe en `.shstrtab`.
    pub name: &'static str,
    /// Direccion virtual.
    pub addr: u64,
    /// Flags SHF_* (1 = escritura, 2 = alloc, 4 = ejecutable).
    pub flags: u64,
    /// Contenido de la seccion.
    pub data: Vec<u8>,
    /// `Some(n)`: seccion NOBITS (tipo bss) de `n` bytes sin datos en el archivo.
    pub nobits_size: Option<u64>,
}

/// Descripcion completa de un ELF sintetico de 32 o 64 bits.
pub struct ElfSpec {
    /// Genera ELF64 en lugar de ELF32.
    pub is64: bool,
    /// Usa big endian.
    pub big: bool,
    /// Campo `e_machine` (EM_MIPS, EM_PPC, EM_AARCH64, EM_X86_64, ...).
    pub machine: u16,
    /// Campo `e_flags` (p. ej. ABI de MIPS).
    pub e_flags: u32,
    /// Punto de entrada.
    pub entry: u64,
    /// Secciones en orden.
    pub sections: Vec<ElfSection>,
}

/// Construye un ELF ejecutable con cabecera, secciones y `.shstrtab`.
pub fn build_elf(spec: &ElfSpec) -> Vec<u8> {
    let hdr = if spec.is64 { 0x40 } else { 0x34 };
    let mut offs = Vec::new();
    let mut cur = hdr;
    for s in &spec.sections {
        cur = align(cur, 4);
        offs.push(cur);
        cur += s.data.len();
    }
    let mut strtab = vec![0u8];
    let mut name_offs = Vec::new();
    for s in &spec.sections {
        name_offs.push(strtab.len() as u32);
        strtab.extend_from_slice(s.name.as_bytes());
        strtab.push(0);
    }
    let shstr_name = strtab.len() as u32;
    strtab.extend_from_slice(b".shstrtab\0");
    let strtab_off = align(cur, 4);
    cur = strtab_off + strtab.len();
    let shoff = align(cur, 8);
    let shnum = spec.sections.len() + 2;
    let shentsize: u16 = if spec.is64 { 0x40 } else { 0x28 };

    let mut w = W::new(spec.big);
    w.bytes(b"\x7fELF");
    w.u8(if spec.is64 { 2 } else { 1 });
    w.u8(if spec.big { 2 } else { 1 });
    w.u8(1); // EI_VERSION
    w.pad_to(16);
    w.u16(2); // ET_EXEC
    w.u16(spec.machine);
    w.u32(1);
    if spec.is64 {
        w.u64(spec.entry);
        w.u64(0); // phoff
        w.u64(shoff as u64);
    } else {
        w.u32(spec.entry as u32);
        w.u32(0);
        w.u32(shoff as u32);
    }
    w.u32(spec.e_flags);
    w.u16(hdr as u16); // ehsize
    w.u16(if spec.is64 { 0x38 } else { 0x20 }); // phentsize
    w.u16(0); // phnum
    w.u16(shentsize);
    w.u16(shnum as u16);
    w.u16((shnum - 1) as u16); // shstrndx = ultima seccion
    assert_eq!(w.buf.len(), hdr);

    for (s, &o) in spec.sections.iter().zip(&offs) {
        w.pad_to(o);
        w.bytes(&s.data);
    }
    w.pad_to(strtab_off);
    w.bytes(&strtab);
    w.pad_to(shoff);

    let is64 = spec.is64;
    let sh = |w: &mut W, name: u32, kind: u32, flags: u64, addr: u64, off: u64, size: u64| {
        w.u32(name);
        w.u32(kind);
        if is64 {
            w.u64(flags);
            w.u64(addr);
            w.u64(off);
            w.u64(size);
        } else {
            w.u32(flags as u32);
            w.u32(addr as u32);
            w.u32(off as u32);
            w.u32(size as u32);
        }
        w.u32(0); // link
        w.u32(0); // info
        if is64 {
            w.u64(4);
            w.u64(0);
        } else {
            w.u32(4);
            w.u32(0);
        }
    };
    sh(&mut w, 0, 0, 0, 0, 0, 0); // SHT_NULL
    for ((s, &o), &n) in spec.sections.iter().zip(&offs).zip(&name_offs) {
        match s.nobits_size {
            Some(sz) => sh(&mut w, n, 8, s.flags, s.addr, o as u64, sz),
            None => sh(&mut w, n, 1, s.flags, s.addr, o as u64, s.data.len() as u64),
        }
    }
    sh(&mut w, shstr_name, 3, 0, 0, strtab_off as u64, strtab.len() as u64);
    w.buf
}

fn sample_sections(code: &[u8], text: u64, data: u64) -> Vec<ElfSection> {
    vec![
        ElfSection { name: ".text", addr: text, flags: 6, data: code.to_vec(), nobits_size: None },
        ElfSection { name: ".data", addr: data, flags: 3, data: vec![0xAA; 16], nobits_size: None },
        ElfSection {
            name: ".bss",
            addr: data + 0x100,
            flags: 3,
            data: vec![],
            nobits_size: Some(0x40),
        },
    ]
}

fn words(big: bool, words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for &w in words {
        out.extend_from_slice(&if big { w.to_be_bytes() } else { w.to_le_bytes() });
    }
    out
}

/// ELF MIPS LE32 con tres funciones y dos llamadas directas. Sirve para
/// comprobar el desensamblado recursivo sin usar codigo de terceros.
///
/// `main` (0x00100000) llama a `f1` (0x00100020) y a `f2` (0x00100030);
/// las tres terminan en `jr $ra`.
pub fn elf_mips_le32_program() -> Vec<u8> {
    let code = words(
        false,
        &[
            0x27BD_FFF8, // addiu sp,sp,-8
            0x0C04_0008, // jal 0x00100020
            0x0000_0000, // nop (delay slot)
            0x0C04_000C, // jal 0x00100030
            0x0000_0000, // nop (delay slot)
            0x03E0_0008, // jr ra
            0x0000_0000, // nop (delay slot)
            0x0000_0000, // relleno hasta 0x00100020
            0x2508_0001, // addiu t0,t0,1
            0x03E0_0008, // jr ra
            0x0000_0000, // nop (delay slot)
            0x0000_0000, // relleno hasta 0x00100030
            0x2529_0002, // addiu t1,t1,2
            0x03E0_0008, // jr ra
            0x0000_0000, // nop (delay slot)
        ],
    );
    build_elf(&ElfSpec {
        is64: false,
        big: false,
        machine: 8,
        e_flags: 0x20,
        entry: 0x0010_0000,
        sections: sample_sections(&code, 0x0010_0000, 0x0020_0000),
    })
}

/// ELF PowerPC BE32 con tres funciones y dos `bl` directos.
pub fn elf_ppc_be32_program() -> Vec<u8> {
    let code = words(
        true,
        &[
            0x9421_FFF0, // stwu r1,-16(r1)
            0x4800_001D, // bl 0x00010020
            0x6000_0000, // nop
            0x4800_0025, // bl 0x00010030
            0x6000_0000, // nop
            0x4E80_0020, // blr
            0x6000_0000, // relleno hasta 0x00010020
            0x6000_0000,
            0x3860_0007, // li r3,7
            0x4E80_0020, // blr
            0x6000_0000, // relleno hasta 0x00010030
            0x6000_0000,
            0x3860_0009, // li r3,9
            0x4E80_0020, // blr
        ],
    );
    build_elf(&ElfSpec {
        is64: false,
        big: true,
        machine: 20,
        e_flags: 0,
        entry: 0x0001_0000,
        sections: sample_sections(&code, 0x0001_0000, 0x0002_0000),
    })
}

/// ELF AArch64 con tres funciones y dos `bl` directos.
pub fn elf_aarch64_program() -> Vec<u8> {
    let code = words(
        false,
        &[
            0xA9BF_7BFD, // stp x29,x30,[sp,#-16]!
            0x9400_0007, // bl 0x00400020
            0x9400_000A, // bl 0x00400030
            0xA8C1_7BFD, // ldp x29,x30,[sp],#16
            0xD65F_03C0, // ret
            0xD503_201F, // nop (relleno)
            0xD503_201F,
            0xD503_201F,
            0x5280_00E0, // mov w0,#7
            0xD65F_03C0, // ret
            0xD503_201F, // relleno hasta 0x00400030
            0xD503_201F,
            0x5280_0120, // mov w0,#9
            0xD65F_03C0, // ret
        ],
    );
    build_elf(&ElfSpec {
        is64: true,
        big: false,
        machine: 183,
        e_flags: 0,
        entry: 0x0040_0000,
        sections: sample_sections(&code, 0x0040_0000, 0x0050_0000),
    })
}

/// ELF x86-64 con tres funciones y dos `call` directos.
pub fn elf_x86_64_program() -> Vec<u8> {
    let code = vec![
        0x55, // push rbp
        0xE8, 0x0A, 0x00, 0x00, 0x00, // call 0x00401010
        0xE8, 0x15, 0x00, 0x00, 0x00, // call 0x00401020
        0x5D, // pop rbp
        0xC3, // ret
        0x90, 0x90, 0x90, // relleno hasta 0x00401010
        0xB8, 0x07, 0x00, 0x00, 0x00, // mov eax,7
        0xC3, // ret
        0x90, 0x90, 0x90, 0x90, 0x90, // relleno hasta 0x00401020
        0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax,9
        0xC3, // ret
    ];
    build_elf(&ElfSpec {
        is64: true,
        big: false,
        machine: 62,
        e_flags: 0,
        entry: 0x0040_1000,
        sections: sample_sections(&code, 0x0040_1000, 0x0060_0000),
    })
}

/// ELF de Cell SPU (big-endian, 32 bits). Capstone no desensambla SPU: el
/// cargador lo acepta, pero el analisis debe rechazarlo con `Unsupported`.
pub fn elf_spu() -> Vec<u8> {
    build_elf(&ElfSpec {
        is64: false,
        big: true,
        machine: 23,
        e_flags: 0,
        entry: 0x0000_0000,
        sections: sample_sections(&[0, 0, 0, 0], 0x0000_0000, 0x0001_0000),
    })
}

/// ELF MIPS little-endian de 32 bits (tipo PS2/R5900). Codigo: `jr $ra; nop`.
pub fn elf_mips_le32() -> Vec<u8> {
    build_elf(&ElfSpec {
        is64: false,
        big: false,
        machine: 8,
        e_flags: 0x20,
        entry: 0x0010_0000,
        sections: sample_sections(&[0x08, 0x00, 0xE0, 0x03, 0, 0, 0, 0], 0x0010_0000, 0x0020_0000),
    })
}

/// ELF PowerPC big-endian de 32 bits (tipo PS3 PPU en modo 32 bits). Codigo: `blr`.
pub fn elf_ppc_be32() -> Vec<u8> {
    build_elf(&ElfSpec {
        is64: false,
        big: true,
        machine: 20,
        e_flags: 0,
        entry: 0x0001_0000,
        sections: sample_sections(&[0x4E, 0x80, 0x00, 0x20], 0x0001_0000, 0x0002_0000),
    })
}

/// ELF AArch64 little-endian. Codigo: `ret`.
pub fn elf_aarch64() -> Vec<u8> {
    build_elf(&ElfSpec {
        is64: true,
        big: false,
        machine: 183,
        e_flags: 0,
        entry: 0x40_0000,
        sections: sample_sections(&[0xC0, 0x03, 0x5F, 0xD6], 0x40_0000, 0x50_0000),
    })
}

/// ELF x86-64 little-endian. Codigo: `ret`.
pub fn elf_x86_64() -> Vec<u8> {
    build_elf(&ElfSpec {
        is64: true,
        big: false,
        machine: 62,
        e_flags: 0,
        entry: 0x40_1000,
        sections: sample_sections(&[0xC3], 0x40_1000, 0x60_0000),
    })
}

// ---------------------------------------------------------------- DOL

/// DOL sintetico (GameCube/Wii): una seccion de texto, una de datos y bss.
pub fn dol_ppc() -> Vec<u8> {
    let mut w = W::new(true);
    w.pad_to(0x100);
    let put = |w: &mut W, off: usize, v: u32| w.set_u32(off, v);
    put(&mut w, 0x00, 0x100); // text0 offset
    put(&mut w, 0x48, 0x8000_3100); // text0 addr
    put(&mut w, 0x90, 0x20); // text0 size
    put(&mut w, 0x1C, 0x120); // data0 offset
    put(&mut w, 0x64, 0x8000_4000); // data0 addr
    put(&mut w, 0xAC, 0x10); // data0 size
    put(&mut w, 0xD8, 0x8000_5000); // bss addr
    put(&mut w, 0xDC, 0x100); // bss size
    put(&mut w, 0xE0, 0x8000_3100); // entry
    w.bytes(&[0x4E, 0x80, 0x00, 0x20]); // blr
    w.pad_to(0x120);
    w.bytes(&[0x55; 0x10]);
    w.buf
}

// ---------------------------------------------------------------- PE

/// PE32+ x86-64 sintetico con `.text` y `.data`.
pub fn pe_x86_64() -> Vec<u8> {
    let mut w = W::new(false);
    w.bytes(b"MZ");
    w.pad_to(0x3C);
    w.u32(0x40);
    w.pad_to(0x40);
    w.bytes(b"PE\0\0");
    w.u16(0x8664); // machine
    w.u16(2); // numero de secciones
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u16(0xF0); // tamano de cabecera opcional
    w.u16(0x22);
    let opt = w.buf.len();
    w.pad_to(opt + 0xF0);
    // Cabecera opcional (PE32+).
    let mut o = W::new(false);
    o.u16(0x20B);
    o.pad_to(16);
    o.u32(0x1000); // entry rva
    o.pad_to(24);
    o.u64(0x1_4000_0000); // image base
    let ob = o.buf;
    w.buf[opt..opt + ob.len()].copy_from_slice(&ob);

    let section = |w: &mut W, name: &[u8], vsize: u32, rva: u32, rsize: u32, rptr: u32, ch: u32| {
        let mut n = [0u8; 8];
        n[..name.len()].copy_from_slice(name);
        w.bytes(&n);
        w.u32(vsize);
        w.u32(rva);
        w.u32(rsize);
        w.u32(rptr);
        w.u32(0);
        w.u32(0);
        w.u32(0); // reloc/linenum counts (16 bits cada uno)
        w.u32(ch);
    };
    section(&mut w, b".text", 0x10, 0x1000, 0x200, 0x200, 0x6000_0020);
    section(&mut w, b".data", 0x20, 0x2000, 0x200, 0x400, 0xC000_0040);
    w.pad_to(0x200);
    w.u8(0xC3); // ret
    w.pad_to(0x600);
    w.buf
}

// ---------------------------------------------------------------- NSO

/// NSO0 sintetico (Switch, ARM64). Con `compressed = true` marca los tres
/// segmentos como comprimidos, pero guarda los datos tal cual (`compressed_size
/// == size`): sirve para comprobar que el cargador los trata como almacenados.
/// Para probar LZ4 de verdad usa [`nso_arm64_lz4`].
pub fn nso_arm64(compressed: bool) -> Vec<u8> {
    let mut w = W::new(false);
    w.bytes(b"NSO0");
    w.u32(0); // version
    w.u32(0); // reservado
    w.u32(if compressed { 0b111 } else { 0 }); // flags
    w.pad_to(0x100);
    let put = |w: &mut W, off: usize, v: u32| w.set_u32(off, v);
    // text
    put(&mut w, 0x10, 0x100);
    put(&mut w, 0x14, 0x0);
    put(&mut w, 0x18, 8);
    // rodata
    put(&mut w, 0x20, 0x108);
    put(&mut w, 0x24, 0x1000);
    put(&mut w, 0x28, 0x10);
    // data
    put(&mut w, 0x30, 0x118);
    put(&mut w, 0x34, 0x2000);
    put(&mut w, 0x38, 0x10);
    put(&mut w, 0x3C, 0x100); // bss
    put(&mut w, 0x60, 8);
    put(&mut w, 0x64, 0x10);
    put(&mut w, 0x68, 0x10);
    w.bytes(&[0xC0, 0x03, 0x5F, 0xD6, 0, 0, 0, 0]); // ret
    w.bytes(&[0x11; 0x10]);
    w.bytes(&[0x22; 0x10]);
    w.buf
}

/// NSO0 sintetico con los tres segmentos realmente comprimidos con LZ4.
///
/// `.text` ocupa 0x80 bytes (dos bloques de 0x40 para ejercitar el bucle),
/// `.rodata` y `.data` 0x40 bytes cada uno. La cabecera de 0x100 bytes se
/// conserva y los bloques se encadenan detras.
pub fn nso_arm64_lz4() -> Vec<u8> {
    let mut text = Vec::with_capacity(0x80);
    // `ret` repetido en el primer bloque; un patron distinto en el segundo.
    for _ in 0..16 {
        text.extend_from_slice(&[0xC0, 0x03, 0x5F, 0xD6]);
    }
    for i in 0..0x40 {
        text.push((i as u8).wrapping_mul(7));
    }
    let rodata: Vec<u8> = (0..0x40).map(|i| (i as u8 % 8).wrapping_add(0x40)).collect();
    let data = vec![0x22u8; 0x40];

    fn push_block(out: &mut Vec<u8>, raw: &[u8]) {
        let compressed = lz4_flex::block::compress(raw);
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        out.extend_from_slice(&compressed);
    }

    let mut text_blocks = Vec::new();
    for chunk in text.chunks(0x40) {
        push_block(&mut text_blocks, chunk);
    }
    let mut rodata_blocks = Vec::new();
    push_block(&mut rodata_blocks, &rodata);
    let mut data_blocks = Vec::new();
    push_block(&mut data_blocks, &data);

    let text_off = 0x100usize;
    let rodata_off = text_off + text_blocks.len();
    let data_off = rodata_off + rodata_blocks.len();

    let mut w = W::new(false);
    w.bytes(b"NSO0");
    w.u32(0); // version
    w.u32(0); // reservado
    w.u32(0b111); // los tres segmentos comprimidos
    w.pad_to(0x100);
    let put = |w: &mut W, off: usize, v: u32| w.set_u32(off, v);
    put(&mut w, 0x10, text_off as u32);
    put(&mut w, 0x14, 0x0);
    put(&mut w, 0x18, text.len() as u32);
    put(&mut w, 0x20, rodata_off as u32);
    put(&mut w, 0x24, 0x1000);
    put(&mut w, 0x28, rodata.len() as u32);
    put(&mut w, 0x30, data_off as u32);
    put(&mut w, 0x34, 0x2000);
    put(&mut w, 0x38, data.len() as u32);
    put(&mut w, 0x3C, 0x100); // bss
    put(&mut w, 0x60, text_blocks.len() as u32);
    put(&mut w, 0x64, rodata_blocks.len() as u32);
    put(&mut w, 0x68, data_blocks.len() as u32);
    w.bytes(&text_blocks);
    w.bytes(&rodata_blocks);
    w.bytes(&data_blocks);
    w.buf
}

// ---------------------------------------------------------------- otros

/// Cabecera falsa de contenedor SELF (solo el magic): sirve para comprobar que
/// se rechaza con el mensaje de proteccion.
pub fn fake_self_header() -> Vec<u8> {
    let mut v = b"SCE\0".to_vec();
    v.resize(0x100, 0);
    v
}
