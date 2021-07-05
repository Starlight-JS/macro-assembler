use assembler_data::AssemblerBuffer;
use link_buffer::LinkBuffer;

pub mod assembler_data;
pub mod link_buffer;
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
