use super::definitions::*;
use std::io::{Error as IOError, Result as IOResult};
use std::mem::ManuallyDrop;
use std::ptr::{null_mut, NonNull};

extern "stdcall" {
    fn VirtualAlloc(addr: LPVOID, size: usize, fl_al_type: DWORD, fl_protect: DWORD) -> LPVOID;

    fn VirtualProtect(
        addr: LPVOID,
        size: usize,
        fl_protect: DWORD,
        fl_protect_old: PDWORD,
    ) -> BOOL;

    fn VirtualFree(addr: LPVOID, size: usize, free_type: DWORD) -> BOOL;
}

pub struct AllocatedMemory {
    ptr: NonNull<()>,
    capacity: usize,
}

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
            .map(|ptr| Self { ptr, capacity })
            .ok_or_else(std::io::Error::last_os_error)
    }

    pub unsafe fn write(&mut self, buf: &[u8], offset: isize) -> IOResult<()> {
        self.protect(PAGE_READWRITE)?;

        let ptr = self.ptr.as_ptr() as *mut u8;
        std::ptr::copy(buf.as_ptr(), ptr.offset(offset), buf.len());

        self.protect(PAGE_EXECUTE)?;

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

    pub fn try_free(self) -> IOResult<()> {
        let mut m = ManuallyDrop::new(self);
        unsafe {
            m.try_release()
        }
    }

    unsafe fn try_release(&mut self) -> IOResult<()> {
        success_or_err(|| VirtualFree(self.ptr.as_ptr(), 0, MEM_DECOMMIT))
    }
}

impl Drop for AllocatedMemory {
    fn drop(&mut self) {
        unsafe {
            self.try_release().unwrap_or_else(|e| panic!("release mem({:p}) failed: {e}", self.ptr))
        }
    }
}