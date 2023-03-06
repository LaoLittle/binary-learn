use std::ptr::{null_mut, NonNull};

pub type DWORD = u32;
pub type PDWORD = *mut DWORD;

pub type LPVOID = *mut ();
pub type BOOL = std::ffi::c_int;

pub const MEM_COMMIT: DWORD = 0x00001000;
pub const MEM_RESERVE: DWORD = 0x00002000;

pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;

pub const PAGE_EXECUTE_READWRITE: DWORD = 0x04;

extern "stdcall" {
    pub fn VirtualAlloc(addr: LPVOID, size: usize, fl_al_type: DWORD, fl_protect: DWORD) -> LPVOID;

    pub fn VirtualProtect(
        addr: LPVOID,
        size: usize,
        fl_protect: DWORD,
        fl_protect_old: PDWORD,
    ) -> BOOL;
}

pub struct AllocatedMemory {
    ptr: NonNull<()>,
    capacity: usize,
}

type IOResult<T> = std::io::Result<T>;
type IOError = std::io::Error;

#[inline]
fn success_or_err<F: FnOnce() -> BOOL>(f: F) -> IOResult<()> {
    if f() == 0 {
        Err(IOError::last_os_error())
    } else {
        Ok(())
    }
}

impl AllocatedMemory {
    pub unsafe fn new(capacity: usize) -> IOResult<Self> {
        let ptr =
            unsafe { VirtualAlloc(null_mut(), capacity, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE) };

        NonNull::new(ptr)
            .map(|nn| Self { ptr: nn, capacity })
            .ok_or_else(std::io::Error::last_os_error)
    }

    pub unsafe fn write(&mut self, buf: &[u8], offset: isize) -> IOResult<()> {
        let origin = self.protect(PAGE_READWRITE)?;

        let ptr = self.ptr.as_ptr() as *mut u8;
        std::ptr::copy(buf.as_ptr(), ptr.offset(offset), buf.len());

        self.protect(origin)?;

        Ok(())
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut () {
        self.ptr.as_ptr()
    }

    fn protect(&mut self, fl_protect: u32) -> IOResult<u32> {
        let mut origin = 0;
        unsafe {
            success_or_err(|| {
                VirtualProtect(self.ptr.as_ptr(), self.capacity, fl_protect, &mut origin)
            })?;
        }

        Ok(origin)
    }
}
