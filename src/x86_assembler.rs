use std::ops::{BitAnd, BitOr, Deref, DerefMut};

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

        $(#[allow(non_upper_case_globals)]pub const $id: usize = $val;)*
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
    OP2_CMOVCC + cond.0 as usize
}

fn jcc_rel32(cond: X86Condition) -> usize {
    OP2_JCC_rel32 + cond.0 as usize
}

fn setcc_opcode(cond: X86Condition) -> usize {
    OP_SETCC + cond.0 as usize
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
