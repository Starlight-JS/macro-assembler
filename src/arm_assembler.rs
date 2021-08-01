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
    SP
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
    Q31
}

pub struct ArmCondition(pub u8);


impl ArmCondition {
    pub const EQ:Self = Self(0);
    pub const NE:Self = Self(1);
    pub const HS:Self = Self(2);
    pub const CS:Self = Self::HS;

    pub const LO :Self = Self(3);
    pub const CC:Self = Self::LO;

    pub const MI:Self = Self(4);
    pub const PL:Self = Self(5);
    pub const VS:Self = Self(6);
    pub const VC:Self = Self(7);
    pub const HI:Self = Self(8);
    pub const LS:Self = Self(9);
    pub const GE:Self = Self(10);
    pub const LT:Self = Self(11);
    pub const GT:Self = Self(12);
    pub const LE:Self = Self(13);
    pub const AL:Self = Self(14);
    pub const Invalid: Self = Self(15);
}
