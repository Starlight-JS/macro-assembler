use std::{
    mem::swap,
    ops::{BitAnd, BitOr, Deref, DerefMut},
    ptr::write_unaligned,
};

use crate::assembler_buffer::{AssemblerBuffer, AssemblerLabel, Put};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum RegisterID {
    #[cfg(target_arch = "x86")]
    EAX,
    #[cfg(target_arch = "x86")]
    ECX,
    #[cfg(target_arch = "x86")]
    EDX,
    #[cfg(target_arch = "x86")]
    EBX,
    #[cfg(target_arch = "x86")]
    ESP,
    #[cfg(target_arch = "x86")]
    EBP,
    #[cfg(target_arch = "x86")]
    ESI,
    #[cfg(target_arch = "x86")]
    EDI,

    #[cfg(target_arch = "x86_64")]
    EAX,
    #[cfg(target_arch = "x86_64")]
    ECX,
    #[cfg(target_arch = "x86_64")]
    EDX,
    #[cfg(target_arch = "x86_64")]
    EBX,
    #[cfg(target_arch = "x86_64")]
    ESP,
    #[cfg(target_arch = "x86_64")]
    EBP,
    #[cfg(target_arch = "x86_64")]
    ESI,
    #[cfg(target_arch = "x86_64")]
    EDI,
    #[cfg(target_arch = "x86_64")]
    R8,
    #[cfg(target_arch = "x86_64")]
    R9,
    #[cfg(target_arch = "x86_64")]
    R10,
    #[cfg(target_arch = "x86_64")]
    R11,
    #[cfg(target_arch = "x86_64")]
    R12,
    #[cfg(target_arch = "x86_64")]
    R13,
    #[cfg(target_arch = "x86_64")]
    R14,
    #[cfg(target_arch = "x86_64")]
    R15,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum FPRegisterID {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    XMM1,
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    XMM2,
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    XMM3,
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    XMM4,
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    XMM5,
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    XMM6,
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    XMM7,
    #[cfg(target_arch = "x86_64")]
    XMM8,
    #[cfg(target_arch = "x86_64")]
    XMM9,
    #[cfg(target_arch = "x86_64")]
    XMM10,
    #[cfg(target_arch = "x86_64")]
    XMM11,
    #[cfg(target_arch = "x86_64")]
    XMM12,
    #[cfg(target_arch = "x86_64")]
    XMM13,
    #[cfg(target_arch = "x86_64")]
    XMM14,
    #[cfg(target_arch = "x86_64")]
    XMM15,
}

#[cfg(target_arch = "x86_64")]
fn reg_requires_rex(reg: u8) -> bool {
    reg >= RegisterID::R8 as u8
}
#[cfg(target_arch = "x86_64")]
pub fn byte_reg_requires_rex(reg: u8) -> bool {
    reg >= RegisterID::ESP as u8
}

#[cfg(target_arch = "x86")]
fn byte_reg_requires_rex(_reg: u8) -> bool {
    false
}
#[cfg(target_arch = "x86")]
fn reg_requires_rex(_reg: u8) -> bool {
    false
}

macro_rules! c {
    ($($id: ident = $val: expr),*) => {

        $(#[allow(non_upper_case_globals)]pub const $id: u8 = $val;)*
    };
}
// OneByteOpcodeID defines the bytecode for 1 byte instruction. It also contains the prefixes
// for two bytes instructions.
// TwoByteOpcodeID, ThreeByteOpcodeID define the opcodes for the multibytes instructions.
//
// The encoding for each instruction can be found in the Intel Architecture Manual in the appendix
// "Opcode Map."
//
// Each opcode can have a suffix describing the type of argument. The full list of suffixes is
// in the "Key to Abbreviations" section of the "Opcode Map".
// The most common argument types are:
//     -E: The argument is either a GPR or a memory address.
//     -G: The argument is a GPR.
//     -I: The argument is an immediate.
// The most common sizes are:
//     -v: 32 or 64bit depending on the operand-size attribute.
//     -z: 32bit in both 32bit and 64bit mode. Common for immediate values.
c! {
        OP_ADD_EbGb                     = 0x00,
        OP_ADD_EvGv                     = 0x01,
        OP_ADD_GvEv                     = 0x03,
        OP_ADD_EAXIv                    = 0x05,
        OP_OR_EvGb                      = 0x08,
        OP_OR_EvGv                      = 0x09,
        OP_OR_GvEv                      = 0x0B,
        OP_OR_EAXIv                     = 0x0D,
        OP_2BYTE_ESCAPE                 = 0x0F,
        OP_AND_EvGb                     = 0x20,
        OP_AND_EvGv                     = 0x21,
        OP_AND_GvEv                     = 0x23,
        OP_SUB_EvGb                     = 0x28,
        OP_SUB_EvGv                     = 0x29,
        OP_SUB_GvEv                     = 0x2B,
        OP_SUB_EAXIv                    = 0x2D,
        PRE_PREDICT_BRANCH_NOT_TAKEN    = 0x2E,
        OP_XOR_EvGb                     = 0x30,
        OP_XOR_EvGv                     = 0x31,
        OP_XOR_GvEv                     = 0x33,
        OP_XOR_EAXIv                    = 0x35,
        OP_CMP_EvGv                     = 0x39,
        OP_CMP_GvEv                     = 0x3B,
        OP_CMP_EAXIv                    = 0x3D,
        PRE_REX                         = 0x40,
        OP_PUSH_EAX                     = 0x50,
        OP_POP_EAX                      = 0x58,
        OP_MOVSXD_GvEv                  = 0x63,
        PRE_GS                          = 0x65,
        PRE_OPERAND_SIZE                = 0x66,
        PRE_SSE_66                      = 0x66,
        OP_PUSH_Iz                      = 0x68,
        OP_IMUL_GvEvIz                  = 0x69,
        OP_GROUP1_EbIb                  = 0x80,
        OP_GROUP1_EvIz                  = 0x81,
        OP_GROUP1_EvIb                  = 0x83,
        OP_TEST_EbGb                    = 0x84,
        OP_TEST_EvGv                    = 0x85,
        OP_XCHG_EvGb                    = 0x86,
        OP_XCHG_EvGv                    = 0x87,
        OP_MOV_EbGb                     = 0x88,
        OP_MOV_EvGv                     = 0x89,
        OP_MOV_GvEv                     = 0x8B,
        OP_LEA                          = 0x8D,
        OP_GROUP1A_Ev                   = 0x8F,
        OP_NOP                          = 0x90,
        OP_XCHG_EAX                     = 0x90,
        OP_PAUSE                        = 0x90,
        OP_CDQ                          = 0x99,
        OP_MOV_EAXOv                    = 0xA1,
        OP_MOV_OvEAX                    = 0xA3,
        OP_TEST_ALIb                    = 0xA8,
        OP_TEST_EAXIv                   = 0xA9,
        OP_MOV_EAXIv                    = 0xB8,
        OP_GROUP2_EvIb                  = 0xC1,
        OP_RET                          = 0xC3,
        OP_GROUP11_EvIb                 = 0xC6,
        OP_GROUP11_EvIz                 = 0xC7,
        OP_INT3                         = 0xCC,
        OP_GROUP2_Ev1                   = 0xD1,
        OP_GROUP2_EvCL                  = 0xD3,
        OP_ESCAPE_D9                    = 0xD9,
        OP_ESCAPE_DD                    = 0xDD,
        OP_CALL_rel32                   = 0xE8,
        OP_JMP_rel32                    = 0xE9,
        PRE_LOCK                        = 0xF0,
        PRE_SSE_F2                      = 0xF2,
        PRE_SSE_F3                      = 0xF3,
        OP_HLT                          = 0xF4,
        OP_GROUP3_Eb                    = 0xF6,
        OP_GROUP3_EbIb                  = 0xF6,
        OP_GROUP3_Ev                    = 0xF7,
        OP_GROUP3_EvIz                  = 0xF7, // OP_GROUP3_Ev has an immediate, when instruction is a test.
        OP_GROUP5_Ev                    = 0xFF
}
c! {
    OP2_UD2             = 0xB,
        OP2_MOVSD_VsdWsd    = 0x10,
        OP2_MOVSD_WsdVsd    = 0x11,
        OP2_MOVSS_VsdWsd    = 0x10,
        OP2_MOVSS_WsdVsd    = 0x11,
        OP2_MOVAPD_VpdWpd   = 0x28,
        OP2_MOVAPS_VpdWpd   = 0x28,
        OP2_CVTSI2SD_VsdEd  = 0x2A,
        OP2_CVTTSD2SI_GdWsd = 0x2C,
        OP2_CVTTSS2SI_GdWsd = 0x2C,
        OP2_UCOMISD_VsdWsd  = 0x2E,
        OP2_RDTSC           = 0x31,
        OP2_3BYTE_ESCAPE_3A = 0x3A,
        OP2_CMOVCC          = 0x40,
        OP2_ADDSD_VsdWsd    = 0x58,
        OP2_MULSD_VsdWsd    = 0x59,
        OP2_CVTSD2SS_VsdWsd = 0x5A,
        OP2_CVTSS2SD_VsdWsd = 0x5A,
        OP2_SUBSD_VsdWsd    = 0x5C,
        OP2_DIVSD_VsdWsd    = 0x5E,
        OP2_MOVMSKPD_VdEd   = 0x50,
        OP2_SQRTSD_VsdWsd   = 0x51,
        OP2_ANDPS_VpdWpd    = 0x54,
        OP2_ANDNPD_VpdWpd   = 0x55,
        OP2_ORPS_VpdWpd     = 0x56,
        OP2_XORPD_VpdWpd    = 0x57,
        OP2_MOVD_VdEd       = 0x6E,
        OP2_MOVD_EdVd       = 0x7E,
        OP2_JCC_rel32       = 0x80,
        OP_SETCC            = 0x90,
        OP2_CPUID           = 0xA2,
        OP2_3BYTE_ESCAPE_AE = 0xAE,
        OP2_IMUL_GvEv       = 0xAF,
        OP2_CMPXCHGb        = 0xB0,
        OP2_CMPXCHG         = 0xB1,
        OP2_BTR             = 0xB3,
        OP2_MOVZX_GvEb      = 0xB6,
        OP2_POPCNT          = 0xB8,
        OP2_GROUP_BT_EvIb   = 0xBA,
        OP2_BT_EvEv         = 0xA3,
        OP2_BSF             = 0xBC,
        OP2_TZCNT           = 0xBC,
        OP2_BSR             = 0xBD,
        OP2_LZCNT           = 0xBD,
        OP2_MOVSX_GvEb      = 0xBE,
        OP2_MOVZX_GvEw      = 0xB7,
        OP2_MOVSX_GvEw      = 0xBF,
        OP2_XADDb           = 0xC0,
        OP2_XADD            = 0xC1,
        OP2_PEXTRW_GdUdIb   = 0xC5,
        OP2_BSWAP           = 0xC8,
        OP2_PSLLQ_UdqIb     = 0x73,
        OP2_PSRLQ_UdqIb     = 0x73,
        OP2_POR_VdqWdq      = 0xEB
}

c! {
    OP3_ROUNDSS_VssWssIb = 0x0A,
        OP3_ROUNDSD_VsdWsdIb = 0x0B,
        OP3_LFENCE           = 0xE8,
        OP3_MFENCE           = 0xF0,
        OP3_SFENCE           = 0xF8
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(C)]
pub enum VexPrefix {
    TwoBytes = 0xC5,
    ThreeBytes = 0xC4,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(C)]
pub enum VexImpliedBytes {
    TwoBytesOp = 1,
    TwoBytesOp38 = 2,
    TwoBytesOp3A = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub enum ModRmMode {
    NoDisp = 0,
    Disp8 = 1 << 6,
    Disp32 = 2 << 6,
    Register = 3 << 6,
}
pub struct X86Condition(pub u8);

impl X86Condition {
    pub const O: Self = Self(0);
    pub const NO: Self = Self(1);
    pub const B: Self = Self(2);
    pub const AE: Self = Self(3);
    pub const E: Self = Self(4);
    pub const NE: Self = Self(5);
    pub const BE: Self = Self(6);
    pub const A: Self = Self(7);
    pub const S: Self = Self(8);
    pub const NS: Self = Self(9);
    pub const P: Self = Self(10);
    pub const NP: Self = Self(11);
    pub const L: Self = Self(12);
    pub const GE: Self = Self(13);
    pub const LE: Self = Self(14);
    pub const G: Self = Self(15);
    pub const C: Self = Self::B;
    pub const NC: Self = Self::AE;
}

impl BitOr for X86Condition {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for X86Condition {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

fn cmovcc(cond: X86Condition) -> usize {
    OP2_CMOVCC as usize + cond.0 as usize
}

fn jcc_rel32(cond: X86Condition) -> usize {
    OP2_JCC_rel32 as usize + cond.0 as usize
}

fn setcc_opcode(cond: X86Condition) -> usize {
    OP_SETCC as usize + cond.0 as usize
}

c! {
    GROUP1_OP_ADD = 0,
        GROUP1_OP_OR  = 1,
        GROUP1_OP_ADC = 2,
        GROUP1_OP_AND = 4,
        GROUP1_OP_SUB = 5,
        GROUP1_OP_XOR = 6,
        GROUP1_OP_CMP = 7,

        GROUP1A_OP_POP = 0,

        GROUP2_OP_ROL = 0,
        GROUP2_OP_ROR = 1,
        GROUP2_OP_RCL = 2,
        GROUP2_OP_RCR = 3,

        GROUP2_OP_SHL = 4,
        GROUP2_OP_SHR = 5,
        GROUP2_OP_SAR = 7,

        GROUP3_OP_TEST = 0,
        GROUP3_OP_NOT  = 2,
        GROUP3_OP_NEG  = 3,
        GROUP3_OP_DIV = 6,
        GROUP3_OP_IDIV = 7,

        GROUP5_OP_CALLN = 2,
        GROUP5_OP_JMPN  = 4,
        GROUP5_OP_PUSH  = 6,

        GROUP11_MOV = 0,

        GROUP14_OP_PSLLQ = 6,
        GROUP14_OP_PSRLQ = 2,

        ESCAPE_D9_FSTP_singleReal = 3,
        ESCAPE_DD_FSTP_doubleReal = 3,

        GROUP_BT_OP_BT = 4
}

pub struct X86AssemblerFormatter {
    pub buffer: AssemblerBuffer,
}

impl X86AssemblerFormatter {
    pub const HAS_SIB: RegisterID = RegisterID::ESP;
    pub const NO_BASE: RegisterID = RegisterID::EBP;
    pub const NO_INDEX: RegisterID = RegisterID::ESP;

    #[cfg(target_arch = "x86_64")]
    pub const NO_BASE2: RegisterID = RegisterID::R13;
    #[cfg(target_arch = "x86_64")]
    pub const HAS_SIB2: RegisterID = RegisterID::R12;
    #[cfg(target_arch = "x86_64")]
    pub fn emit_rex(&mut self, w: bool, r: u8, x: u8, b: u8) {
        self.put_byte_unchecked(
            PRE_REX as u8 | ((w as u8) << 3) | ((r >> 3) << 2) | ((x >> 3) << 1) | (b >> 3),
        );
    }
    #[cfg(target_arch = "x86_64")]
    pub fn emit_rexw(&mut self, r: u8, x: u8, b: u8) {
        self.emit_rex(true, r, x, b);
    }
    #[cfg(target_arch = "x86_64")]
    pub fn emit_rex_if(&mut self, condition: bool, r: u8, x: u8, b: u8) {
        if condition {
            self.emit_rex(false, r, x, b);
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub fn emit_rex_if_needed(&mut self, r: u8, x: u8, b: u8) {
        self.emit_rex_if(reg_requires_rex(r | x | b), r, x, b);
    }

    #[cfg(target_arch = "x86")]
    pub fn emit_rex_if(&mut self, _: bool, _: u8, _: u8, _: u8) {}
    #[cfg(target_arch = "x86")]
    pub fn emit_rex_if_needed(&mut self, _: u8, _: u8, _: u8) {}

    pub fn debug_offset(&self) -> usize {
        self.buffer.debug_offset()
    }

    pub fn data(&self) -> *mut u8 {
        self.buffer.data()
    }

    pub fn is_aligned(&self, a: usize) {
        self.buffer.is_aligned(a);
    }

    pub fn label(&self) -> AssemblerLabel {
        self.buffer.label()
    }

    pub fn code_size(&self) -> usize {
        self.buffer.code_size()
    }

    pub fn put_modrm(&mut self, mode: ModRmMode, reg: u8, rm: RegisterID) {
        self.put_byte_unchecked(mode as u8 | ((reg & 7) << 3) | (rm as u8 & 7));
    }

    pub fn put_modrm_sib(
        &mut self,
        mode: ModRmMode,
        reg: u8,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
    ) {
        self.put_modrm(mode, reg, Self::HAS_SIB);
        self.put_byte_unchecked((scale << 6) | ((index as u8 & 7) << 3) | (base as u8 & 7));
    }

    pub fn register_modrm(&mut self, reg: u8, rm: RegisterID) {
        self.put_modrm(ModRmMode::Register, reg, rm);
    }

    pub fn memory_modrm(&mut self, reg: u8, base: RegisterID, offset: i32) {
        #[cfg(target_arch = "x86_64")]
        let cond = base == Self::HAS_SIB || base == Self::HAS_SIB2;
        #[cfg(target_arch = "x86")]
        let cond = base == Self::HAS_SIB;
        if cond {
            if offset == 0 {
                self.put_modrm_sib(ModRmMode::NoDisp, reg, base, Self::NO_INDEX as _, 0);
            } else if offset as i8 as i32 == offset {
                self.put_modrm_sib(ModRmMode::Disp8, reg, base, Self::NO_INDEX as _, 0);
                self.put_byte_unchecked(offset as i8);
            } else {
                self.put_modrm_sib(ModRmMode::Disp32, reg, base, Self::NO_INDEX as _, 0);
                self.put_int_unchecked(offset);
            }
        } else {
            #[cfg(target_arch = "x86_64")]
            let cond = offset == 0 && (base != Self::NO_BASE) && (base != Self::NO_BASE2);
            #[cfg(target_arch = "x86")]
            let cond = offset == 0 && base != Self::NO_BASE;
            if cond {
                self.put_modrm(ModRmMode::NoDisp, reg, base);
            } else if offset as i8 as i32 == offset {
                self.put_modrm(ModRmMode::Disp8, reg, base);
                self.put_byte_unchecked(offset as i8);
            } else {
                self.put_modrm(ModRmMode::Disp32, reg, base);
                self.put_int_unchecked(offset);
            }
        }
    }

    pub fn memory_modrm_disp8(&mut self, reg: u8, base: RegisterID, offset: i32) {
        assert_eq!(offset as i8 as i32, offset);
        #[cfg(target_arch = "x86_64")]
        let cond = base == Self::HAS_SIB || base == Self::HAS_SIB2;
        #[cfg(target_arch = "x86")]
        let cond = base == Self::HAS_SIB;

        if cond {
            self.put_modrm_sib(ModRmMode::Disp8, reg, base, Self::NO_INDEX, 0);
            self.put_byte_unchecked(offset as i8);
        } else {
            self.put_modrm(ModRmMode::Disp8, reg, base);
            self.put_byte_unchecked(offset as i8);
        }
    }
    pub fn memory_modrm_disp32(&mut self, reg: u8, base: RegisterID, offset: i32) {
        #[cfg(target_arch = "x86_64")]
        let cond = base == Self::HAS_SIB || base == Self::HAS_SIB2;
        #[cfg(target_arch = "x86")]
        let cond = base == Self::HAS_SIB;

        if cond {
            self.put_modrm_sib(ModRmMode::Disp32, reg, base, Self::NO_INDEX, 0);
            self.put_int_unchecked(offset);
        } else {
            self.put_modrm(ModRmMode::Disp32, reg, base);
            self.put_int_unchecked(offset);
        }
    }

    pub fn memory_modrm_scale(
        &mut self,
        reg: u8,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
        offset: i32,
    ) {
        #[cfg(target_arch = "x86_64")]
        let cond = offset == 0 && (base != Self::NO_BASE) && (base != Self::NO_BASE2);
        #[cfg(target_arch = "x86")]
        let cond = offset == 0 && base != Self::NO_BASE;
        if cond {
            self.put_modrm_sib(ModRmMode::NoDisp, reg, base, index, scale)
        } else if offset as i8 as i32 == offset {
            self.put_modrm_sib(ModRmMode::Disp8, reg, base, index, scale);
            self.put_byte_unchecked(offset as i8);
        } else {
            self.put_modrm_sib(ModRmMode::Disp32, reg, base, index, scale);
            self.put_int_unchecked(offset);
        }
    }

    pub fn memory_modrm_addr(&mut self, reg: u8, address: u32) {
        #[cfg(target_arch = "x86_64")]
        self.put_modrm_sib(ModRmMode::NoDisp, reg, Self::NO_BASE, Self::NO_INDEX, 0);
        #[cfg(target_arch = "x86")]
        self.put_modrm(ModRmMode::NoDisp, reg, Self::NO_BASE);

        self.put_int_unchecked(address);
    }

    pub fn two_bytes_vex(&mut self, simd_prefix: usize, in_op_reg: RegisterID, r: RegisterID) {
        self.put_byte_unchecked(VexPrefix::TwoBytes as u8);
        let mut second_byte = vex_encode_simd_prefix(simd_prefix);
        second_byte |= (!(in_op_reg as u8) & 0xf) << 3;
        second_byte |= !(reg_requires_rex(r as _) as u8) << 7;
        self.put_byte_unchecked(second_byte);
    }

    pub fn three_bytes_vex_nds(
        &mut self,
        simd_prefix: usize,
        implied_bytes: VexImpliedBytes,
        r: RegisterID,
        in_op_reg: RegisterID,
        x: RegisterID,
        b: RegisterID,
    ) {
        self.put_byte_unchecked(VexPrefix::ThreeBytes as u8);
        let mut second_byte = implied_bytes as u8;
        second_byte |= !(reg_requires_rex(r as _) as u8) << 7;
        second_byte |= !(reg_requires_rex(x as _) as u8) << 6;
        second_byte |= !(reg_requires_rex(b as _) as u8) << 5;
        self.put_byte_unchecked(second_byte);
        let mut third_byte = vex_encode_simd_prefix(simd_prefix);
        third_byte |= (!(in_op_reg as u8) & 0xf) << 3;
        self.put_byte_unchecked(third_byte);
    }

    pub fn three_bytes_vex_nds2(
        &mut self,
        simd_prefix: usize,
        implied_bytes: VexImpliedBytes,
        r: RegisterID,
        in_op_reg: RegisterID,
        b: RegisterID,
    ) {
        self.put_byte_unchecked(VexPrefix::ThreeBytes as u8);
        let mut second_byte = implied_bytes as u8;
        second_byte |= !(reg_requires_rex(r as _) as u8) << 7;
        second_byte |= 1 << 6; // REX.X
        second_byte |= !(reg_requires_rex(b as _) as u8) << 5;
        self.put_byte_unchecked(second_byte);
        let mut third_byte = vex_encode_simd_prefix(simd_prefix);
        third_byte |= (!(in_op_reg as u8) & 0xf) << 3;
        self.put_byte_unchecked(third_byte);
    }
    pub fn prefix(&mut self, pre: u8) {
        self.buffer.put_byte(pre);
    }
    // Word-sized operands / no operand instruction formatters.
    //
    // In addition to the opcode, the following operand permutations are supported:
    //   * None - instruction takes no operands.
    //   * One register - the low three bits of the RegisterID are added into the opcode.
    //   * Two registers - encode a register form ModRm (for all ModRm formats, the reg field is passed first, and a GroupOpcodeID may be passed in its place).
    //   * Three argument ModRM - a register, and a register and an offset describing a memory operand.
    //   * Five argument ModRM - a register, and a base register, an index, scale, and offset describing a memory operand.
    //
    // For 32-bit x86 targets, the address operand may also be provided as a void*.
    // On 64-bit targets REX prefixes will be planted as necessary, where high numbered registers are used.
    //
    // The twoByteOp methods plant two-byte Intel instructions sequences (first opcode byte 0x0F).
    pub fn one_byte_op(&mut self, op: u8) {
        self.ensure_space(16);
        self.put_byte_unchecked(op);
    }

    pub fn one_byte_op_r(&mut self, op: u8, reg: RegisterID) {
        self.ensure_space(16);
        self.emit_rex_if_needed(0, 0, reg as _);
        self.put_byte_unchecked(op + (reg as u8 & 7));
    }

    pub fn one_byte_op_rr(&mut self, op: u8, reg: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg as _, 0, rm as _);
        self.put_byte_unchecked(op);
        self.register_modrm(reg, rm);
    }

    pub fn one_byte_op_mem(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg, 0, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm(reg, base, offset);
    }
    pub fn one_byte_op_mem32(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg, 0, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm_disp32(reg, base, offset);
    }

    pub fn one_byte_op_mem8(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg, 0, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm_disp8(reg, base, offset);
    }

    pub fn one_byte_op_mem_scale(
        &mut self,
        op: u8,
        reg: u8,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
        offset: i32,
    ) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg as _, index as _, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm_scale(reg, base, index, scale, offset)
    }

    pub fn one_byte_op_addr(&mut self, op: u8, reg: u8, address: u32) {
        self.ensure_space(16);
        self.put_byte_unchecked(op);
        self.memory_modrm_addr(reg, address)
    }
    pub fn two_byte_op(&mut self, op: u8) {
        self.ensure_space(16);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
    }

    pub fn two_byte_op_r(&mut self, op: u8, reg: u8) {
        self.ensure_space(16);
        self.emit_rex_if_needed(0, 0, reg);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
    }
    pub fn two_byte_op_rr(&mut self, op: u8, reg: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg, 0, rm as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.register_modrm(reg, rm)
    }
    pub fn two_byte_op_mem(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg, 0, base as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.memory_modrm(reg, base, offset)
    }
    pub fn two_byte_op_mem_scale(
        &mut self,
        op: u8,
        reg: u8,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
        offset: i32,
    ) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg, index as _, base as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.memory_modrm_scale(reg, base, index, scale, offset)
    }
    pub fn two_byte_op_addr(&mut self, op: u8, reg: u8, address: u32) {
        self.ensure_space(16);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.memory_modrm_addr(reg, address)
    }
    pub fn vex_nds_lig_wig_two_byte_op(
        &mut self,
        simd_prefix: usize,
        op: u8,
        dest: RegisterID,
        a: RegisterID,
        b: RegisterID,
    ) {
        self.ensure_space(16);
        if reg_requires_rex(b as _) {
            self.three_bytes_vex_nds2(simd_prefix, VexImpliedBytes::TwoBytesOp, dest, a, b);
        } else {
            self.two_bytes_vex(simd_prefix, a, dest);
        }

        self.put_byte_unchecked(op);
        self.register_modrm(dest as _, b);
    }

    pub fn vex_nds_lig_wig_commutative_two_byte_op(
        &mut self,
        simd_prefix: usize,
        op: u8,
        dest: RegisterID,
        mut a: RegisterID,
        mut b: RegisterID,
    ) {
        if reg_requires_rex(b as _) {
            swap(&mut a, &mut b);
        }
        self.vex_nds_lig_wig_two_byte_op(simd_prefix, op, dest, a, b)
    }

    pub fn vex_nds_lig_wig_two_byte_op_mem(
        &mut self,
        simd_prefix: usize,
        op: u8,
        dest: RegisterID,
        a: RegisterID,
        base: RegisterID,
        offset: i32,
    ) {
        self.ensure_space(16);
        if reg_requires_rex(base as _) {
            self.three_bytes_vex_nds2(simd_prefix, VexImpliedBytes::TwoBytesOp, dest, a, base);
        } else {
            self.two_bytes_vex(simd_prefix, a, dest);
        }
        self.put_byte_unchecked(op);
        self.memory_modrm(dest as _, base, offset)
    }

    pub fn vex_nds_lig_wig_two_byte_op_mem_scale(
        &mut self,
        simd_prefix: usize,
        op: u8,
        dest: RegisterID,
        a: RegisterID,

        offset: i32,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
    ) {
        self.ensure_space(16);
        if reg_requires_rex(base as u8 | index as u8) {
            self.three_bytes_vex_nds(
                simd_prefix,
                VexImpliedBytes::TwoBytesOp,
                dest,
                a,
                index,
                base,
            );
        } else {
            self.two_bytes_vex(simd_prefix, a, dest);
        }
        self.put_byte_unchecked(op);
        self.memory_modrm_scale(dest as _, base, index, scale, offset)
    }

    pub fn three_byte_op(&mut self, prefix: u8, op: u8) {
        self.ensure_space(16);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(prefix);
        self.put_byte_unchecked(op);
    }

    pub fn three_byte_op_rr(&mut self, prefix: u8, op: u8, reg: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rex_if_needed(reg, 0, rm as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(prefix);
        self.put_byte_unchecked(op);
        self.register_modrm(reg, rm)
    }

    pub fn three_byte_op_disp(
        &mut self,
        prefix: u8,
        op: u8,
        reg: u8,
        base: RegisterID,
        displacement: i32,
    ) {
        self.emit_rex_if_needed(reg, 0, base as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(prefix);
        self.put_byte_unchecked(op);
        self.memory_modrm(reg, base, displacement);
    }
    // Quad-word-sized operands:
    //
    // Used to format 64-bit operantions, planting a REX.w prefix.
    // When planting d64 or f64 instructions, not requiring a REX.w prefix,
    // the normal (non-'64'-postfixed) formatters should be used.

    #[cfg(target_arch = "x86_64")]
    pub fn one_byte_op64(&mut self, op: u8) {
        self.ensure_space(16);
        self.emit_rexw(0, 0, 0);
        self.put_byte_unchecked(op);
    }
    #[cfg(target_arch = "x86_64")]
    pub fn one_byte_op64_r(&mut self, op: u8, r: RegisterID) {
        self.ensure_space(16);
        self.emit_rexw(0, 0, r as _);
        self.put_byte_unchecked(op);
    }

    #[cfg(target_arch = "x86_64")]
    pub fn one_byte_op64_rr(&mut self, op: u8, reg: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rexw(reg, 0, rm as _);
        self.put_byte_unchecked(op);
        self.register_modrm(reg, rm)
    }
    #[cfg(target_arch = "x86_64")]
    pub fn one_byte_op64_mem(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rexw(reg, 0, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm(reg, base, offset)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn one_byte_op64_mem_disp32(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rexw(reg, 0, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm_disp32(reg, base, offset)
    }
    #[cfg(target_arch = "x86_64")]
    pub fn one_byte_op64_mem_disp8(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rexw(reg, 0, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm_disp8(reg, base, offset)
    }
    #[cfg(target_arch = "x86_64")]
    pub fn one_byte_op64_mem_scale(
        &mut self,
        op: u8,
        reg: u8,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
        offset: i32,
    ) {
        self.ensure_space(16);
        self.emit_rexw(reg, index as _, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm_scale(reg, base, index, scale, offset)
    }
    #[cfg(target_arch = "x86_64")]
    pub fn one_byte_op64_addr(&mut self, op: u8, reg: u8, address: u32) {
        self.ensure_space(16);
        self.emit_rexw(reg, 0, 0);
        self.put_byte_unchecked(op);
        self.memory_modrm_addr(reg, address)
    }
    #[cfg(target_arch = "x86_64")]
    pub fn two_byte_op64_r(&mut self, op: u8, reg: u8) {
        self.ensure_space(16);
        self.emit_rexw(0, 0, reg);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op + (reg & 7))
    }

    #[cfg(target_arch = "x86_64")]
    pub fn two_byte_op64_rr(&mut self, op: u8, reg: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rexw(reg, 0, rm as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.register_modrm(reg, rm)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn two_byte_op64_mem(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rexw(reg, 0, base as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.memory_modrm(reg, base, offset)
    }
    #[cfg(target_arch = "x86_64")]
    pub fn two_byte_op64_mem_scale(
        &mut self,
        op: u8,
        reg: u8,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
        offset: i32,
    ) {
        self.ensure_space(16);
        self.emit_rexw(reg, index as _, base as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.memory_modrm_scale(reg, base, index, scale, offset)
    }

    // Byte-operands:
    //
    // These methods format byte operations.  Byte operations differ from the normal
    // formatters in the circumstances under which they will decide to emit REX prefixes.
    // These should be used where any register operand signifies a byte register.
    //
    // The disctinction is due to the handling of register numbers in the range 4..7 on
    // x86-64.  These register numbers may either represent the second byte of the first
    // four registers (ah..bh) or the first byte of the second four registers (spl..dil).
    //
    // Since ah..bh cannot be used in all permutations of operands (specifically cannot
    // be accessed where a REX prefix is present), these are likely best treated as
    // deprecated.  In order to ensure the correct registers spl..dil are selected a
    // REX prefix will be emitted for any byte register operand in the range 4..15.
    //
    // These formatters may be used in instructions where a mix of operand sizes, in which
    // case an unnecessary REX will be emitted, for example:
    //     movzbl %al, %edi
    // In this case a REX will be planted since edi is 7 (and were this a byte operand
    // a REX would be required to specify dil instead of bh).  Unneeded REX prefixes will
    // be silently ignored by the processor.
    //
    // Address operands should still be checked using regRequiresRex(), while byteRegRequiresRex()
    // is provided to check byte register operands.
    pub fn one_byte_op8_r(&mut self, op: u8, group: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rex_if(byte_reg_requires_rex(rm as _), 0, 0, rm as _);
        self.put_byte_unchecked(op);
        self.register_modrm(group, rm);
    }

    pub fn one_byte_op8_rr(&mut self, op: u8, reg: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rex_if(byte_reg_requires_rex(reg | rm as u8), reg, 0, rm as _);
        self.put_byte_unchecked(op);
        self.register_modrm(reg, rm);
    }

    pub fn one_byte_op8_mem(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rex_if(byte_reg_requires_rex(reg | base as u8), reg, 0, base as _);
        self.put_byte_unchecked(op);
        self.memory_modrm(reg, base, offset)
    }

    pub fn one_byte_op8_mem_scale(
        &mut self,
        op: u8,
        reg: u8,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
        offset: i32,
    ) {
        self.ensure_space(16);
        self.emit_rex_if(
            byte_reg_requires_rex(reg) || reg_requires_rex(index as u8 | base as u8),
            reg,
            index as _,
            base as _,
        );
        self.put_byte_unchecked(op);
        self.memory_modrm_scale(reg, base, index, scale, offset)
    }
    pub fn two_byte_op8_r(&mut self, op: u8, group: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rex_if(byte_reg_requires_rex(rm as _), 0, 0, rm as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.register_modrm(group, rm);
    }

    pub fn two_byte_op8_rr(&mut self, op: u8, reg: u8, rm: RegisterID) {
        self.ensure_space(16);
        self.emit_rex_if(byte_reg_requires_rex(reg | rm as u8), reg, 0, rm as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.register_modrm(reg, rm);
    }

    pub fn two_byte_op8_mem(&mut self, op: u8, reg: u8, base: RegisterID, offset: i32) {
        self.ensure_space(16);
        self.emit_rex_if(byte_reg_requires_rex(reg | base as u8), reg, 0, base as _);
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.memory_modrm(reg, base, offset)
    }

    pub fn two_byte_op8_mem_scale(
        &mut self,
        op: u8,
        reg: u8,
        base: RegisterID,
        index: RegisterID,
        scale: u8,
        offset: i32,
    ) {
        self.ensure_space(16);
        self.emit_rex_if(
            byte_reg_requires_rex(reg) || reg_requires_rex(index as u8 | base as u8),
            reg,
            index as _,
            base as _,
        );
        self.put_byte_unchecked(OP_2BYTE_ESCAPE as u8);
        self.put_byte_unchecked(op);
        self.memory_modrm_scale(reg, base, index, scale, offset)
    }

    // Immediates:
    //
    // An immediate should be appended where appropriate after an op has been emitted.
    // The writes are unchecked since the opcode formatters above will have ensured space.
    pub fn immediate_rel32(&mut self) -> AssemblerLabel {
        self.buffer.put_int_unchecked(0);
        self.label()
    }

    pub fn immediate64(&mut self, i: impl Put<i64>) {
        self.buffer.put_int64_unchecked(i);
    }

    pub fn immediate32(&mut self, i: impl Put<i32>) {
        self.buffer.put_int_unchecked(i);
    }

    pub fn immediate16(&mut self, i: impl Put<i16>) {
        self.buffer.put_short_unchecked(i);
    }

    pub fn immediate8(&mut self, i: impl Put<i8>) {
        self.buffer.put_byte_unchecked(i);
    }
    pub const MAX_INSTRUCTION_SIZE: usize = 16;
}

impl Deref for X86AssemblerFormatter {
    type Target = AssemblerBuffer;
    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for X86AssemblerFormatter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

fn vex_encode_simd_prefix(simd_prefix: usize) -> u8 {
    match simd_prefix {
        0x66 => 1,
        0xf3 => 2,
        0xf2 => 3,
        _ => unreachable!(),
    }
}
pub struct X86Assembler {
    formatter: X86AssemblerFormatter,
    index_of_last_watchpoint: i32,
    index_of_tail_last_watchpoint: i32,
}

impl X86Assembler {
    pub(crate) fn set_pointer(at: *mut u8, value: *mut u8) {
        unsafe {
            write_unaligned(at.cast::<*mut u8>().sub(1), value);
        }
    }
    pub(crate) fn set_int32(at: *mut u8, value: i32) {
        unsafe {
            write_unaligned(at.cast::<i32>().sub(1), value);
        }
    }

    pub(crate) fn set_int8(at: *mut u8, value: i8) {
        unsafe {
            write_unaligned(at.cast::<i8>().sub(1), value);
        }
    }
    pub(crate) fn set_rel32(from: *mut u8, to: *mut u8) {
        let offset = from as isize - to as isize;
        assert!(offset as i32 as isize == offset);
        Self::set_int32(from, offset as _);
    }

    pub fn fill_nops(base: *mut u8, mut size: usize) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            static NOPS: [&'static [u8]; 10] = [
                // nop
                &[0x90],
                // xchg %ax,%ax
                &[0x66, 0x90],
                // nopl (%[re]ax)
                &[0x0f, 0x1f, 0x00],
                // nopl 8(%[re]ax)
                &[0x0f, 0x1f, 0x40, 0x08],
                // nopl 8(%[re]ax,%[re]ax,1)
                &[0x0f, 0x1f, 0x44, 0x00, 0x08],
                // nopw 8(%[re]ax,%[re]ax,1)
                &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x08],
                // nopl 512(%[re]ax)
                &[0x0f, 0x1f, 0x80, 0x00, 0x02, 0x00, 0x00],
                // nopl 512(%[re]ax,%[re]ax,1)
                &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x02, 0x00, 0x00],
                // nopw 512(%[re]ax,%[re]ax,1)
                &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x02, 0x00, 0x00],
                // nopw %cs:512(%[re]ax,%[re]ax,1)
                &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x02, 0x00, 0x00],
            ];

            let mut at = base;
            while size != 0 {
                let nop_size = size.min(15);
                let num_prefixes = if nop_size <= 10 { 0 } else { nop_size - 10 };
                for _ in 0..=num_prefixes {
                    at.write(0x66);
                    at = at.add(1);
                }
                let nop_rest = nop_size - num_prefixes;
                for i in 0..=nop_rest {
                    at.write(NOPS[nop_rest - 1][i]);
                    at = at.add(1);
                }
                size -= nop_size;
            }
        }
        #[cfg(target_arch = "x86")]
        unsafe {
            core::ptr::write_bytes(base, OP_NOP as u8, size);
        }
    }

    pub fn nop(&mut self) {
        self.formatter.one_byte_op(OP_NOP);
    }

    pub fn debug_offset(&self) -> usize {
        self.formatter.debug_offset()
    }

    pub fn get_difference_between_labels(a: AssemblerLabel, b: AssemblerLabel) -> i32 {
        b.offset() as i32 - a.offset() as i32
    }

    pub fn get_relocate_address(code: *mut u8, label: AssemblerLabel) -> *mut u8 {
        unsafe { code.add(label.offset() as _) }
    }

    pub fn get_call_return_offset(call: AssemblerLabel) -> u32 {
        call.offset()
    }

    pub fn replace_with_address_computation(instruction_start: *mut u8) {
        let mut ptr = instruction_start;
        unsafe {
            #[cfg(target_arch = "x86_64")]
            if (ptr.read() & !15) == PRE_REX {
                ptr = ptr.add(1);
            }
            match ptr.read() {
                OP_MOV_GvEv => ptr.write(OP_LEA),
                OP_LEA => {}
                _ => unreachable!(),
            }
        }
    }
    pub fn replace_with_load(instruction_start: *mut u8) {
        let mut ptr = instruction_start;
        unsafe {
            #[cfg(target_arch = "x86_64")]
            if (ptr.read() & !15) == PRE_REX {
                ptr = ptr.add(1);
            }
            match ptr.read() {
                OP_MOV_GvEv => {}
                OP_LEA => ptr.write(OP_MOV_GvEv),
                _ => unreachable!(),
            }
        }
    }

    pub fn max_jump_replacement_size() -> usize {
        5
    }

    pub fn patchable_jump_size() -> usize {
        5
    }

    pub fn revert_jump_to_cmpl_im_force32(
        instruction_start: *mut u8,
        imm: i32,
        _offset: i32,
        dst: RegisterID,
    ) {
        let opcode_bytes = 1;
        let mod_rm_bytes = 1;
        unsafe {
            let ptr = instruction_start;
            ptr.write(OP_GROUP11_EvIz);
            ptr.add(1)
                .write(((ModRmMode::NoDisp as u8) << 6) | (GROUP1_OP_CMP << 3) | dst as u8);

            let as_bytes = imm.to_ne_bytes();
            for i in opcode_bytes + mod_rm_bytes..Self::max_jump_replacement_size() {
                ptr.add(i).write(as_bytes[i - opcode_bytes - mod_rm_bytes]);
            }
        }
    }
    pub fn revert_jump_to_cmpl_ir_force32(
        instruction_start: *mut u8,
        imm: i32,
        _offset: i32,
        dst: RegisterID,
    ) {
        let opcode_bytes = 1;
        let mod_rm_bytes = 1;
        unsafe {
            let ptr = instruction_start;
            ptr.write(OP_GROUP11_EvIz);
            ptr.add(1)
                .write(((ModRmMode::Register as u8) << 6) | (GROUP1_OP_CMP << 3) | dst as u8);

            let as_bytes = imm.to_ne_bytes();
            for i in opcode_bytes + mod_rm_bytes..Self::max_jump_replacement_size() {
                ptr.add(i).write(as_bytes[i - opcode_bytes - mod_rm_bytes]);
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub fn revert_jump_to_movq_i64r(instruction_start: *mut u8, imm: i64, dst: RegisterID) {
        let instruction_size = 10;
        let rex_bytes = 1;
        let opcode_bytes = 1;
        unsafe {
            let ptr = instruction_start;
            ptr.write(PRE_REX | (1 << 3) | (dst as u8 >> 3));
            ptr.add(1).write(OP_MOV_EAXIv | (dst as u8 & 7));
            let bytes = imm.to_ne_bytes();
            for i in rex_bytes + opcode_bytes..instruction_size {
                ptr.add(i).write(bytes[i - rex_bytes - opcode_bytes]);
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    pub fn revert_jump_to_movl_i32r(instruction_start: *mut u8, imm: i32, dst: RegisterID) {
        let instruction_size = 6;
        let rex_bytes = 1;
        let opcode_bytes = 1;
        unsafe {
            let ptr = instruction_start;
            ptr.write(PRE_REX | (dst as u8 >> 3));
            ptr.add(1).write(OP_MOV_EAXIv | (dst as u8 & 7));

            let bytes = imm.to_ne_bytes();
            for i in rex_bytes + opcode_bytes..instruction_size {
                ptr.add(i).write(bytes[i - rex_bytes - opcode_bytes]);
            }
        }
    }
}
