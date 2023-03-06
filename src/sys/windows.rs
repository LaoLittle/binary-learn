pub type DWORD = u32;
pub type PDWORD = *mut DWORD;

pub type LPVOID = *mut ();
pub type BOOL = std::ffi::c_int;

pub const MEM_COMMIT: DWORD =                      0x00001000;
pub const MEM_RESERVE: DWORD =                     0x00002000;

pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;

pub const PAGE_EXECUTE_READWRITE: DWORD = 0x04;

extern "stdcall" {
    pub fn VirtualAlloc(addr: LPVOID, size: usize, fl_al_type: DWORD, fl_protect: DWORD) -> LPVOID;

    pub fn VirtualProtect(addr: LPVOID, size: usize, fl_protect: DWORD, fl_protect_old: PDWORD) -> BOOL;
}