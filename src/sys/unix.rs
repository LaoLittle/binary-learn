use super::definitions::*;
use std::io::{Error as IOError, Result as IOResult};
use std::ptr::{null_mut, NonNull};

extern "C" {
    fn mmap(addr: PVoid, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> PVoid;

    fn munmap(addr: PVoid, len: usize) -> c_int;

    fn mprotect(addr: PVoid, len: usize, prot: c_int) -> c_int;
}

fn success_or_err<F: FnOnce() -> c_int>(f: F) -> IOResult<()> {
    if f() == -1 {
        Err(IOError::last_os_error())
    } else {
        Ok(())
    }
}

pub struct AllocatedMemory {
    ptr: NonNull<()>,
    capacity: usize,
}

impl AllocatedMemory {
    pub unsafe fn new(capacity: usize) -> IOResult<Self> {
        let mut flags = MAP_ANONYMOUS | MAP_PRIVATE;
        #[cfg(apple)]
        {
            flags |= MAP_JIT;
        }

        let ptr = mmap(null_mut(), capacity, PROT_READ, flags, -1, 0);

        NonNull::new(ptr)
            .map(|ptr| Self { ptr, capacity })
            .ok_or_else(IOError::last_os_error)
    }

    pub unsafe fn write(&mut self, buf: &[u8], offset: isize) -> IOResult<()> {
        self.protect(PROT_READ | PROT_WRITE)?;

        let ptr = self.ptr.as_ptr() as *mut u8;
        std::ptr::copy(buf.as_ptr(), ptr.offset(offset), buf.len());

        self.protect(PROT_READ | PROT_EXEC)?;

        Ok(())
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut () {
        self.ptr.as_ptr()
    }

    fn protect(&mut self, prot: c_int) -> IOResult<()> {
        unsafe {
            success_or_err(|| mprotect(self.ptr.as_ptr(), self.capacity, prot))?;
        }

        Ok(())
    }
}

#[cfg(apple)]
extern "C" {
    fn pthread_jit_write_protect_np(enabled: c_int);
}

#[inline]
unsafe fn enter_jit_write() {
    #[cfg(apple)]
    pthread_jit_write_protect_np(0);
}

#[inline]
unsafe fn exit_jit_write() {
    #[cfg(apple)]
    pthread_jit_write_protect_np(1);
}
