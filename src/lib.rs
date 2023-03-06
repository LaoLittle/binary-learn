use std::ptr::NonNull;

pub mod sys;

struct JitMemory {
    ptr: NonNull<()>,
}

impl JitMemory {
    pub fn new(capacity: usize) {}
}
