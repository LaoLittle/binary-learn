use crate::sys;
use std::io::Result;

pub struct AllocatedMemory(sys::AllocatedMemory);

impl AllocatedMemory {
    pub unsafe fn new(capacity: usize) -> Result<Self> {
        sys::AllocatedMemory::new(capacity).map(Self)
    }

    #[inline]
    pub unsafe fn write(&mut self, buf: &[u8], offset: isize) -> Result<()> {
        self.0.write(buf, offset)
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut () {
        self.0.as_ptr()
    }
}
