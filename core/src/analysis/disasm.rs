//! Desensamblador basado en Capstone y clasificacion del flujo de control.
//!
//! Solo se habilitan las arquitecturas que usa el proyecto (MIPS, PowerPC,
//! ARM, ARM64 y x86). SPU no esta soportado por Capstone; el analisis lo
//! rechaza con un error explicito en vez de adivinar.

use super::image::Image;
use crate::arch::{Arch, Endian};
use crate::error::{Error, Result};
use capstone::arch;
use capstone::prelude::*;
use capstone::{Capstone, InsnDetail, InsnGroupId, InsnGroupType};

/// Flujo de control de una instruccion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Continua en la instruccion siguiente.
    Next,
    /// Llamada; si el destino es directo se conoce la direccion.
    Call(Option<u64>),
    /// Salto. `Some(dst)` si es directo y `None` si es indirecto.
    Jump(Option<u64>),
    /// Salto condicional con destino directo: siguen el destino y el fallthrough.
    CondJump(u64),
    /// Retorno.
    Return,
    /// Interrupcion o instruccion que detiene el flujo.
    Stop,
}

/// Instruccion ya decodificada (sin punteros a Capstone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Direccion virtual de la instruccion.
    pub address: u64,
    /// Longitud en bytes (2 o 4 en MIPS/PPC/ARM, 1-15 en x86).
    pub size: u8,
    /// Mnemonico en minusculas segun Capstone (p. ej. `jal`).
    pub mnemonic: String,
    /// Operandos tal como los muestra Capstone.
    pub op_str: String,
    /// Clasificacion del flujo de control.
    pub flow: Flow,
    /// La instruccion siguiente se ejecuta siempre antes de aplicar el salto,
    /// la llamada o el retorno (*delay slot* de MIPS). Un salto condicional
    /// solo ejecuta el hueco cuando la condicion se cumple; se modela como si
    /// siempre se ejecutara para no perder codigo alcanzable.
    pub delay_slot: bool,
}

impl Instruction {
    /// Direccion inmediatamente posterior a la instruccion.
    pub fn end(&self) -> u64 {
        self.address + u64::from(self.size)
    }
}

/// Envoltorio de Capstone configurado para una arquitectura concreta.
pub struct Disassembler {
    cs: Capstone,
    arch: Arch,
}

impl Disassembler {
    /// Crea un desensamblador para `arch`, `endian` y ancho de palabra `bits`.
    ///
    /// SPU y arquitecturas desconocidas devuelven [`Error::Unsupported`].
    pub fn new(arch: Arch, endian: Endian, bits: u8) -> Result<Self> {
        let cs_endian = match endian {
            Endian::Little => capstone::Endian::Little,
            Endian::Big => capstone::Endian::Big,
        };
        let built = match arch {
            Arch::Mips => {
                let mode = if bits == 64 {
                    arch::mips::ArchMode::Mips64
                } else {
                    arch::mips::ArchMode::Mips32
                };
                Capstone::new().mips().mode(mode).endian(cs_endian).detail(true).build()
            }
            Arch::PowerPc => {
                let mode = if bits == 64 {
                    arch::ppc::ArchMode::Mode64
                } else {
                    arch::ppc::ArchMode::Mode32
                };
                Capstone::new().ppc().mode(mode).endian(cs_endian).detail(true).build()
            }
            Arch::Arm => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .endian(cs_endian)
                .detail(true)
                .build(),
            Arch::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .endian(cs_endian)
                .detail(true)
                .build(),
            Arch::X86 => Capstone::new()
                .x86()
                .mode(if bits == 64 {
                    arch::x86::ArchMode::Mode64
                } else {
                    arch::x86::ArchMode::Mode32
                })
                .detail(true)
                .build(),
            Arch::X86_64 => {
                Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build()
            }
            Arch::Spu => {
                return Err(Error::Unsupported {
                    format: "SPU",
                    hint: "Capstone no desensambla SPU; el modulo Cell se analizara en la Fase 10"
                        .into(),
                })
            }
            Arch::Unknown => {
                return Err(Error::Unsupported {
                    format: "desconocido",
                    hint: "no se puede desensamblar sin una arquitectura reconocida".into(),
                })
            }
        };
        let cs = built.map_err(|e| Error::Analysis(format!("no se pudo iniciar Capstone: {e}")))?;
        Ok(Disassembler { cs, arch })
    }

    /// Decodifica una instruccion en `address`. Devuelve `None` si no hay bytes
    /// suficientes o si Capstone no reconoce la codificacion (fin de bloque).
    pub fn decode(&self, image: &Image, address: u64) -> Result<Option<Instruction>> {
        // 16 bytes es el maximo de x86; las demas arquitecturas usan 4. Pedimos
        // solo lo disponible para poder decodificar la ultima instruccion de
        // una seccion aunque queden menos de 16 bytes.
        let Some(code) = image.read_up_to(address, 16) else {
            return Ok(None);
        };
        let insns = self
            .cs
            .disasm_count(code, address, 1)
            .map_err(|e| Error::Analysis(format!("Capstone en 0x{address:x}: {e}")))?;
        let Some(insn) = insns.iter().next() else {
            return Ok(None);
        };
        let size = insn.bytes().len();
        if size == 0 || size > 16 {
            return Ok(None);
        }
        let mnemonic = insn.mnemonic().unwrap_or("").to_string();
        let op_str = insn.op_str().unwrap_or("").to_string();
        let detail = self
            .cs
            .insn_detail(insn)
            .map_err(|e| Error::Analysis(format!("Capstone (detalle) en 0x{address:x}: {e}")))?;
        let groups = detail.groups();
        let is_call = has_group(groups, InsnGroupType::CS_GRP_CALL);
        let is_jump = has_group(groups, InsnGroupType::CS_GRP_JUMP);
        let is_ret = has_group(groups, InsnGroupType::CS_GRP_RET);
        let is_int = has_group(groups, InsnGroupType::CS_GRP_INT);
        let is_iret = has_group(groups, InsnGroupType::CS_GRP_IRET);
        let target = immediate_target(&detail, self.arch);

        // Capstone 5 no asigna los grupos genericos de llamada/retorno en MIPS
        // ni en PowerPC; se reconocen por el mnemonico.
        let special = match (self.arch, mnemonic.as_str()) {
            (Arch::Mips, m) if m.starts_with("jal") => Some(Flow::Call(target)),
            (Arch::Mips, "jr" | "jr.hb") => {
                Some(if first_operand_is_ra(&op_str) { Flow::Return } else { Flow::Jump(None) })
            }
            (Arch::PowerPc, "bl" | "bla") => Some(Flow::Call(target)),
            (Arch::PowerPc, "bctrl" | "blrl") => Some(Flow::Call(None)),
            (Arch::PowerPc, "blr") => Some(Flow::Return),
            _ => None,
        };

        let flow = if let Some(f) = special {
            f
        } else if is_ret || is_iret {
            Flow::Return
        } else if is_call {
            Flow::Call(target)
        } else if is_jump {
            match target {
                Some(t) if is_unconditional(self.arch, &mnemonic) => Flow::Jump(Some(t)),
                Some(t) => Flow::CondJump(t),
                None => Flow::Jump(None),
            }
        } else if is_int {
            Flow::Stop
        } else {
            Flow::Next
        };

        let delay_slot = has_delay_slot(self.arch, &mnemonic, flow);
        Ok(Some(Instruction { address, size: size as u8, mnemonic, op_str, flow, delay_slot }))
    }
}

/// Las ramas, saltos, llamadas y retornos de MIPS ejecutan la instruccion
/// siguiente antes de transferir el control. `syscall`/`break`/`eret` no.
///
/// Las variantes *branch-likely* (`beql`, `bnel`, ...) solo ejecutan el hueco
/// cuando la rama se toma; el analisis las trata como las normales y prefiere
/// conservar codigo de mas a perder codigo alcanzable.
fn has_delay_slot(arch: Arch, mnemonic: &str, flow: Flow) -> bool {
    if arch != Arch::Mips {
        return false;
    }
    let transfers =
        matches!(flow, Flow::Call(_) | Flow::Jump(_) | Flow::CondJump(_) | Flow::Return);
    transfers && !matches!(mnemonic, "syscall" | "break" | "eret" | "deret")
}

fn has_group(groups: &[InsnGroupId], group: u32) -> bool {
    groups.iter().any(|g| u32::from(g.0) == group)
}

fn first_operand_is_ra(op_str: &str) -> bool {
    op_str.split(',').next().map(str::trim) == Some("$ra")
}

/// Salto incondicional segun la arquitectura. El resto de saltos con destino
/// directo se tratan como condicionales (siguen destino y fallthrough).
fn is_unconditional(arch: Arch, mnemonic: &str) -> bool {
    match arch {
        Arch::Mips => matches!(mnemonic, "b" | "j"),
        Arch::PowerPc => matches!(mnemonic, "b" | "ba"),
        Arch::Arm | Arch::Arm64 => mnemonic == "b",
        Arch::X86 | Arch::X86_64 => matches!(mnemonic, "jmp" | "ljmp"),
        Arch::Spu | Arch::Unknown => false,
    }
}

/// Primer operando inmediato, que en estas arquitecturas es la direccion
/// absoluta de destino de llamadas y saltos directos.
fn immediate_target(detail: &InsnDetail<'_>, arch: Arch) -> Option<u64> {
    let detail = detail.arch_detail();
    let value = match arch {
        Arch::Mips => detail.mips()?.operands().find_map(|op| match op {
            arch::mips::MipsOperand::Imm(v) => Some(v),
            _ => None,
        }),
        Arch::PowerPc => detail.ppc()?.operands().find_map(|op| match op {
            arch::ppc::PpcOperand::Imm(v) => Some(v),
            _ => None,
        }),
        Arch::Arm => detail.arm()?.operands().find_map(|op| match op.op_type {
            arch::arm::ArmOperandType::Imm(v) => Some(i64::from(v)),
            _ => None,
        }),
        Arch::Arm64 => detail.arm64()?.operands().find_map(|op| match op.op_type {
            arch::arm64::Arm64OperandType::Imm(v) => Some(v),
            _ => None,
        }),
        Arch::X86 | Arch::X86_64 => detail.x86()?.operands().find_map(|op| match op.op_type {
            arch::x86::X86OperandType::Imm(v) => Some(v),
            _ => None,
        }),
        Arch::Spu | Arch::Unknown => None,
    };
    value.and_then(|v| u64::try_from(v).ok())
}

/// Utilidad de diagnostico: desensambla como maximo `count` instrucciones
/// desde `address` (la usara la interfaz en la Fase 2/5).
pub fn disassemble(
    image: &Image,
    arch: Arch,
    endian: Endian,
    bits: u8,
    address: u64,
    count: usize,
) -> Result<Vec<Instruction>> {
    let dis = Disassembler::new(arch, endian, bits)?;
    let mut out = Vec::new();
    let mut pc = address;
    while out.len() < count {
        let Some(insn) = dis.decode(image, pc)? else {
            break;
        };
        pc = insn.end();
        out.push(insn);
        if matches!(out.last().map(|i| i.flow), Some(Flow::Return) | Some(Flow::Stop)) {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::Section;

    fn image(data: &[u8], start: u64) -> Image<'_> {
        let sections = [Section {
            name: ".text".into(),
            start,
            size: data.len() as u64,
            perms: "r-x".into(),
            file_offset: Some(0),
        }];
        Image::from_sections(data, &sections)
    }

    #[test]
    fn mips_call_branch_and_return() {
        // jal 0x100010 ; nop ; bne $t0,$t1,0 ; jr $ra
        let code = [
            0x04, 0x00, 0x04, 0x0C, // jal 0x00100010
            0x00, 0x00, 0x00, 0x00, // nop
            0x00, 0x00, 0x09, 0x15, // bne t0,t1,0 -> 0x0010000C
            0x08, 0x00, 0xE0, 0x03, // jr ra
        ];
        let img = image(&code, 0x0010_0000);
        let dis = Disassembler::new(Arch::Mips, Endian::Little, 32).unwrap();
        let call = dis.decode(&img, 0x0010_0000).unwrap().unwrap();
        assert_eq!(call.flow, Flow::Call(Some(0x0010_0010)));
        assert!(call.delay_slot);
        let nop = dis.decode(&img, 0x0010_0004).unwrap().unwrap();
        assert_eq!(nop.flow, Flow::Next);
        assert!(!nop.delay_slot);
        let branch = dis.decode(&img, 0x0010_0008).unwrap().unwrap();
        assert_eq!(branch.flow, Flow::CondJump(0x0010_000C));
        assert!(branch.delay_slot);
        let ret = dis.decode(&img, 0x0010_000C).unwrap().unwrap();
        assert_eq!(ret.flow, Flow::Return);
        assert!(ret.delay_slot);
    }

    #[test]
    fn only_mips_flow_instructions_have_delay_slots() {
        // `bl 0x10010` en PowerPC; `ret` en AArch64; `call` en x86-64.
        for (arch, endian, bits, code, addr) in [
            (Arch::PowerPc, Endian::Big, 32, vec![0x48, 0x00, 0x00, 0x11], 0x1_0000u64),
            (Arch::Arm64, Endian::Little, 64, vec![0x04, 0x00, 0x00, 0x94], 0x40_0000),
            (Arch::X86_64, Endian::Little, 64, vec![0xE8, 0x00, 0x00, 0x00, 0x00], 0x40_1000),
        ] {
            let img = image(&code, addr);
            let dis = Disassembler::new(arch, endian, bits).unwrap();
            let insn = dis.decode(&img, addr).unwrap().unwrap();
            assert!(!insn.delay_slot, "{arch:?} no usa delay slot");
        }
    }

    #[test]
    fn ppc_call_and_return() {
        // bl 0x10010 ; blr ; nop
        let code = [0x48, 0x00, 0x00, 0x11, 0x4E, 0x80, 0x00, 0x20, 0x60, 0x00, 0x00, 0x00];
        let img = image(&code, 0x1_0000);
        let dis = Disassembler::new(Arch::PowerPc, Endian::Big, 32).unwrap();
        let call = dis.decode(&img, 0x1_0000).unwrap().unwrap();
        assert_eq!(call.flow, Flow::Call(Some(0x1_0010)));
        let ret = dis.decode(&img, 0x1_0004).unwrap().unwrap();
        assert_eq!(ret.flow, Flow::Return);
        let nop = dis.decode(&img, 0x1_0008).unwrap().unwrap();
        assert_eq!(nop.flow, Flow::Next);
    }

    #[test]
    fn aarch64_call_and_return() {
        // bl 0x400010 ; ret
        let code = [0x04, 0x00, 0x00, 0x94, 0xC0, 0x03, 0x5F, 0xD6];
        let img = image(&code, 0x40_0000);
        let dis = Disassembler::new(Arch::Arm64, Endian::Little, 64).unwrap();
        let call = dis.decode(&img, 0x40_0000).unwrap().unwrap();
        assert_eq!(call.flow, Flow::Call(Some(0x40_0010)));
        let ret = dis.decode(&img, 0x40_0004).unwrap().unwrap();
        assert_eq!(ret.flow, Flow::Return);
    }

    #[test]
    fn x86_call_is_absolute() {
        // call 0x401010 ; ret
        let code = [0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3];
        let img = image(&code, 0x40_1000);
        let dis = Disassembler::new(Arch::X86_64, Endian::Little, 64).unwrap();
        let call = dis.decode(&img, 0x40_1000).unwrap().unwrap();
        assert_eq!(call.flow, Flow::Call(Some(0x40_1010)));
        assert_eq!(call.size, 5);
        let ret = dis.decode(&img, 0x40_1005).unwrap().unwrap();
        assert_eq!(ret.flow, Flow::Return);
    }

    #[test]
    fn spu_is_rejected() {
        let err = match Disassembler::new(Arch::Spu, Endian::Big, 32) {
            Ok(_) => panic!("SPU no debe ser aceptado"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::Unsupported { format: "SPU", .. }));
    }
}
