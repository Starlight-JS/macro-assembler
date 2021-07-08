use crate::assembler_buffer::AssemblerBuffer;
use crate::link_buffer::LinkBuffer;

pub trait MacroAssembler {
    fn code_size(&self) -> usize;
    fn emit_nops(&mut self, count: usize);
    fn breakpoint(&mut self);
    fn label(&mut self);
    fn take_link_tasks(&mut self) -> Vec<Box<dyn FnOnce(&mut LinkBuffer)>>;
    fn take_late_link_tasks(&mut self) -> Vec<Box<dyn FnOnce(&mut LinkBuffer)>>;
    fn buffer(&self) -> &AssemblerBuffer;
    fn buffer_mut(&mut self) -> &mut AssemblerBuffer;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]

pub enum DoubleCondition {
    EqualAndOrdered,
    NotEqualAndOrdered,
    GreaterThanAndOrdered,
    GreaterThanOrEqualAndOrdered,
    LessThanAndOrdered,
    LessThanOrEqualAndOrdered,
    EqualOrUnordered,
    NotEqualOrUnordered,
    GreaterThanOrUnordered,
    GreaterThanOrEqualOrUnordered,
    LessThanOrUnordered,
    LessThanOrEqualOrUnordered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub enum ResultCondition {
    Overflow,
    Signed,
    PositiveOrZero,
    Zero,
    NonZero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub enum RelationalCondition {
    Equal,
    NotEqual,
    Above,
    AboveOrEqual,
    Below,
    BelowOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}
