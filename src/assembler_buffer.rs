use std::mem::{replace, size_of};

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct AssemblerLabel {
    offset: u32,
}

impl AssemblerLabel {
    pub(crate) fn set_offset(&mut self, offset: u32) {
        self.offset = offset;
    }

    pub const fn offset(&self) -> u32 {
        self.offset
    }

    pub const fn label_at_offset(&self, offset: i32) -> Self {
        Self::new((self.offset as i32).wrapping_add(offset) as _)
    }

    pub const fn new(offset: u32) -> Self {
        Self { offset }
    }

    pub const fn is_set(&self) -> bool {
        self.offset != u32::MAX
    }
}

impl Default for AssemblerLabel {
    fn default() -> Self {
        Self::new(u32::MAX)
    }
}
pub struct AssemblerData {
    buffer: *mut u8,

    capacity: usize,
}

impl AssemblerData {
    pub fn buffer(&self) -> *mut u8 {
        self.buffer
    }
    pub fn new(initial_capacity: Option<usize>) -> Self {
        let cap = initial_capacity.unwrap_or_else(|| 128);
        unsafe {
            let mem = libc::malloc(cap);
            Self {
                buffer: mem.cast(),
                capacity: cap,
            }
        }
    }
    pub fn clear(&mut self) {
        if !self.buffer.is_null() {
            unsafe {
                libc::free(self.buffer.cast());
                self.capacity = 0;
            }
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn grow(&mut self, extra: Option<usize>) {
        let cap = self.capacity + self.capacity / 2 + extra.unwrap_or(0);
        unsafe {
            self.buffer = libc::realloc(self.buffer.cast(), cap).cast();
            self.capacity = cap;
        }
    }
}

impl Drop for AssemblerData {
    fn drop(&mut self) {
        self.clear();
    }
}

pub struct AssemblerBuffer {
    storage: AssemblerData,
    index: usize,
}

impl AssemblerBuffer {
    pub fn out_of_line_grow(&mut self) {
        self.storage.grow(None);
    }

    pub fn grow(&mut self, cap: Option<usize>) {
        self.storage.grow(cap);
    }

    pub(crate) fn put_integral_unchecked<T>(&mut self, value: T) {
        #[cfg(target_arch = "arm64")]
        {
            assert_eq!(size_of::<T>(), 4);
        }

        unsafe {
            core::ptr::write_unaligned(self.storage.buffer().add(self.index).cast::<T>(), value);
            self.index += size_of::<T>();
        }
    }

    pub(crate) fn put_integral<T>(&mut self, value: T) {
        let next_index = self.index + size_of::<T>();
        if next_index > self.storage.capacity() {
            self.out_of_line_grow();
        }
        self.put_integral_unchecked(value);
    }

    pub fn data(&self) -> *mut u8 {
        self.storage.buffer()
    }

    pub fn code_size(&self) -> usize {
        self.index
    }

    pub fn set_code_size(&mut self, size: usize) {
        self.index = size;
        assert!(self.index <= self.storage.capacity());
    }

    pub fn put_int_unchecked(&mut self, i: impl Put<i32>) {
        self.put_integral_unchecked(i.put());
    }

    pub fn put_int(&mut self, i: impl Put<i32>) {
        self.put_integral(i.put());
    }

    pub fn put_int64_unchecked(&mut self, i: impl Put<i64>) {
        self.put_integral_unchecked(i.put());
    }

    pub fn put_int64(&mut self, i: impl Put<i64>) {
        self.put_integral(i.put());
    }

    pub fn put_short(&mut self, i: impl Put<i16>) {
        self.put_integral(i.put());
    }

    pub fn put_short_unchecked(&mut self, i: impl Put<i16>) {
        self.put_integral_unchecked(i.put());
    }

    pub fn put_byte(&mut self, i: impl Put<i8>) {
        self.put_integral(i.put());
    }

    pub fn put_byte_unchecked(&mut self, i: impl Put<i8>) {
        self.put_integral(i.put());
    }

    pub fn is_aligned(&self, alignment: usize) -> bool {
        (self.index & (alignment - 1)) == 0
    }

    pub fn ensure_space(&mut self, space: usize) {
        while !self.is_available(space) {
            self.out_of_line_grow();
        }
    }

    pub fn is_available(&self, space: usize) -> bool {
        self.index + space <= self.storage.capacity()
    }

    pub fn new() -> Self {
        Self {
            storage: AssemblerData::new(None),
            index: 0,
        }
    }

    pub fn label(&self) -> AssemblerLabel {
        AssemblerLabel::new(self.index as _)
    }

    pub fn debug_offset(&self) -> usize {
        self.index
    }

    pub fn release_assembler_data(&mut self) -> AssemblerData {
        replace(&mut self.storage, AssemblerData::new(None))
    }
}

pub trait Put<T> {
    fn put(self) -> T;
}

impl Put<i8> for u8 {
    fn put(self) -> i8 {
        self as _
    }
}

impl Put<i8> for i8 {
    fn put(self) -> i8 {
        self
    }
}

impl Put<i16> for i16 {
    fn put(self) -> i16 {
        self
    }
}
impl Put<i16> for u16 {
    fn put(self) -> i16 {
        self as _
    }
}
impl Put<i32> for i32 {
    fn put(self) -> i32 {
        self
    }
}
impl Put<i32> for u32 {
    fn put(self) -> i32 {
        self as _
    }
}

impl Put<i64> for u64 {
    fn put(self) -> i64 {
        self as _
    }
}
impl Put<i64> for i64 {
    fn put(self) -> i64 {
        self
    }
}
