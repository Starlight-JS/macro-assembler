#![feature(core_intrinsics)]

use std::mem::size_of;

pub enum RegisterID {
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,

    FP,
    LR,
    SP,
}

pub enum FPRegisterID {
    Q0,
    Q1,
    Q2,
    Q3,
    Q4,
    Q5,
    Q6,
    Q7,
    Q8,
    Q9,
    Q10,
    Q11,
    Q12,
    Q13,
    Q14,
    Q15,
    Q16,
    Q17,
    Q18,
    Q19,
    Q20,
    Q21,
    Q22,
    Q23,
    Q24,
    Q25,
    Q26,
    Q27,
    Q28,
    Q29,
    Q30,
    Q31,
}

pub struct ARMCondition(pub u8);

impl ARMCondition {
    pub const EQ: Self = Self(0);
    pub const NE: Self = Self(1);
    pub const HS: Self = Self(2);
    pub const CS: Self = Self::HS;

    pub const LO: Self = Self(3);
    pub const CC: Self = Self::LO;

    pub const MI: Self = Self(4);
    pub const PL: Self = Self(5);
    pub const VS: Self = Self(6);
    pub const VC: Self = Self(7);
    pub const HI: Self = Self(8);
    pub const LS: Self = Self(9);
    pub const GE: Self = Self(10);
    pub const LT: Self = Self(11);
    pub const GT: Self = Self(12);
    pub const LE: Self = Self(13);
    pub const AL: Self = Self(14);
    pub const Invalid: Self = Self(15);
}

pub enum ShiftType {
    LSL,
    LSR,
    ASR,
    ROR,
}

pub enum ExtendType {
    UXTB,
    UXTH,
    UXTW,
    UXTX,
    SXTB,
    SXTH,
    SXTW,
    SXTX,
}

pub enum SetFlags {
    DontSetFlags,
    S,
}

macro_rules! jump_enum_with_size {
    ($index:expr, $value: expr) => {
        ((($value as isize) << 4) | ($index))
    };
}

macro_rules! jump_enum_size {
    ($jump:expr) => {
        (($jump) >> 4)
    };
}

pub enum JumpType {
    JumpFixed = jump_enum_with_size!(0, 0),
    JumpNoCondition = jump_enum_with_size!(1, size_of::<u32>()),
    JumpCondition = jump_enum_with_size!(2, 2 * size_of::<u32>()),
    JumpCompareAndBranch = jump_enum_with_size!(3, 2 * size_of::<u32>()),
    JumpTestBit = jump_enum_with_size!(4, 2 * size_of::<u32>()),
    JumpNoConditionFixedSize = jump_enum_with_size!(5, 1 * size_of::<u32>()),
    JumpConditionFixedSize = jump_enum_with_size!(6, 2 * size_of::<u32>()),
    JumpCompareAndBranchFixedSize = jump_enum_with_size!(7, 2 * size_of::<u32>()),
    JumpTestBitFixedSize = jump_enum_with_size!(8, 2 * size_of::<u32>()),
}

pub enum JumpLinkType {
    LinkInvalid = jump_enum_with_size!(0, 0),
    LinkJumpNoCondition = jump_enum_with_size!(1, 1 * size_of::<u32>()),
    LinkJumpConditionDirect = jump_enum_with_size!(2, 1 * size_of::<u32>()),
    LinkJumpCondition = jump_enum_with_size!(3, 2 * size_of::<u32>()),
    LinkJumpCompareAndBranch = jump_enum_with_size!(4, 2 * size_of::<u32>()),
    LinkJumpCompareAndBranchDirect = jump_enum_with_size!(5, 1 * size_of::<u32>()),
    LinkJumpTestBit = jump_enum_with_size!(6, 2 * size_of::<u32>()),
    LinkJumpTestBitDirect = jump_enum_with_size!(7, 1 * size_of::<u32>()),
}
enum Datasize {
    Datasize32,
    Datasize64,
    Datasize64Top,
    Datasize16,
}

enum MemOpSize {
    MemOpSize8Or128,
    MemOpSize16,
    MemOpSize32,
    MemOpSize64,
}

enum BranchType {
    BranchTypeJmp,
    BranchTypeCall,
    BranchTypeRet,
}

enum AddOp {
    AddOpAdd,
    AddOpSub,
}

enum BitfieldOp {
    BitfieldOpSbfm,
    BitfieldOpBfm,
    BitfieldOpUbfm,
}

enum DataOp1Source {
    DataOpRbit,
    DataOpRev16,
    DataOpRev32,
    DataOpRev64,
    DataOpClz,
    DataOpCls,
}

enum DataOp2Source {
    DataOpUdiv = 2,
    DataOpSdiv = 3,
    DataOpLslv = 8,
    DataOpLsrv = 9,
    DataOpASRV = 10,
    DataOpRORV = 11,
}

enum DataOp3Source {
    DataOpMadd = 0,
    DataOpMsub = 1,
    DataOpSmaddl = 2,
    DataOpSmsubl = 3,
    DataOpSmulh = 4,
    DataOpUmaddl = 10,
    DataOpUmsubl = 11,
    DataOpUmulh = 12,
}

enum ExcepnOp {
    ExcepnOpException = 0,
    ExcepnOpBreakpoint = 1,
    ExcepnOpHalt = 2,
    ExcepnOpDcps = 5,
}

enum FPCmpOp {
    FpcmpOpFcmp = 0x00,
    FpcmpOpFcmp0 = 0x08,
    FpcmpOpFcmpe = 0x10,
    FpcmpOpFcmpe0 = 0x18,
}

enum FPCondCmpOp {
    FpcpndCmpOpFcmp,
    FpcondCmpOpFcmpe,
}

enum FPDataOp1Source {
    FpdataOpFmov = 0,
    FpdataOpFabs = 1,
    FpdataOpFneg = 2,
    FpdataOpFsqrt = 3,
    FpdataOpFcvtToSingle = 4,
    FpdataOpFcvtToDouble = 5,
    FpdataOpFcvtToHalf = 7,
    FpdataOpFrintn = 8,
    FpdataOpFrintp = 9,
    FpdataOpFrintm = 10,
    FpdataOpFrintz = 11,
    FpdataOpFrinta = 12,
    FpdataOpFrintx = 14,
    FpdataOpFrinti = 15,
}

enum FPDataOp2Source {
    FpdataOpFmul,
    FpdataOpFdiv,
    FpdataOpFadd,
    FpdataOpFsub,
    FpdataOpFmax,
    FpdataOpFmin,
    FpdataOpFmaxnm,
    FpdataOpFminnm,
    FpdataOpFnmul,
}

enum SIMD3Same {
    SimdLogicalOp = 0x03,
}

enum SIMD3SameLogical {
    SimdLogicalOpAnd = 0x00,
    SimdLogicalOpBic = 0x01,
    SimdLogicalOpOrr = 0x02,
    SimdLogicalOpOrn = 0x03,
    SimdLogacalOpEor = 0x80,
    SimdLogicalOpBsl = 0x81,
    SimdLogicalOpBit = 0x82,
    SimdLogicalOpBif = 0x83,
}

enum FPIntConvOp {
    FpintConvOpFcvtns = 0x00,
    FpintConvOpFcvtnu = 0x01,
    FpintConvOpScvtf = 0x02,
    FpintConvOpUcvtf = 0x03,
    FpintConvOpFcvtas = 0x04,
    FpintConvOpFcvtau = 0x05,
    FpintConvOpFmovQtoX = 0x06,
    FpintConvOpFmovXtoQ = 0x07,
    FpintConvOpFcvtps = 0x08,
    FpintConvOpFcvtpu = 0x09,
    FpintConvOpFmovQtoXTop = 0x0e,
    FpintConvOpFmovXtoQTop = 0x0f,
    FpintConvOpFcvtms = 0x10,
    FpintConvOpFcvtmu = 0x11,
    FpintConvOpFcvtzs = 0x18,
    FpintConvOpFcvtzu = 0x19,
}

enum LogicalOp {
    LogicalOpAnd,
    LogicalOpOrr,
    LogicalOpEor,
    LogicalOpAnds
}

pub struct  MemOp(u8);

impl MemOp {
    pub const MemOpStore:Self = Self(0);
    pub const MemOpLoad: Self = Self(1);
    pub const MemOpStoreV128: Self = Self(2);
    pub const MemOpLoadV128: Self = Self(3);
    pub const MemOpPrefetch: Self = Self(2);
    pub const MemOpLoadSigned64: Self = Self(2);
    pub const MemOpLoadSigned32: Self = Self(3);
}

pub struct MemPairOpSize(u8);

impl MemPairOpSize {
    pub const MemPairOp32: Self = Self(0);
    pub const MemPairOpLoadSigned32: Self = Self(1);
    pub const MemPairOp64: Self = Self(2);
    pub const MemPairOpV32: Self = Self::MemPairOp32;
    pub const MemPairOpV64:Self = Self(1);
    pub const MemPairOpV128: Self = Self(2);
}

enum MoveWideOp {
    MoveWideOpN = 0,
    MoveWideOpZ = 2,
    MoveWideOpK = 3 
}


pub struct LdrLiteralOp(u8);

impl LdrLiteralOp {
    pub const LdrLiteralOp32bit: Self = Self(0);
    pub const LdrLiteralOp64bit: Self = Self(1);
    pub const LdrLiteralOpLdrsw: Self = Self(2);
    pub const LdrLiteralOp128bit: Self = Self(2);
}

enum ExoticLoadFence {
    ExoticLoadFenceNone,
    ExoticLoadFenceAcquire
}

enum ExoticLoadAtomic {
    ExoticLoadAtomicLink,
    ExoticLoadAtomicNone
}

enum ExoticStoreFence {
    ExoticStoreFenceNone,
    ExoticStoreFenceRelease,
}

pub struct ARMAssembler {}
