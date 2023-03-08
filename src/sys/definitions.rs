use cfg_if::cfg_if;

pub type PVoid = *mut ();

#[allow(non_camel_case_types)]
pub type c_int = std::ffi::c_int;

cfg_if! {
    if #[cfg(windows)] {
        pub type DWORD = u32;
        pub type PDWORD = *mut DWORD;

        pub type LPVOID = PVoid;
        pub type BOOL = c_int;

        pub const MEM_COMMIT: DWORD = 0x00001000;
        pub const MEM_RESERVE: DWORD = 0x00002000;

        pub const MEM_DECOMMIT: DWORD = 0x00008000;

        pub const PAGE_READWRITE: DWORD = 0x04;
        pub const PAGE_EXECUTE: DWORD = 0x10;

        //pub const PAGE_EXECUTE_READWRITE: DWORD = 0x04;
    } else if #[cfg(apple)] {
        #[allow(non_camel_case_types)]
        pub type off_t = i64;

        pub const PROT_READ: c_int = 0x01;
        pub const PROT_WRITE: c_int = 0x02;
        pub const PROT_EXEC: c_int = 0x04;

        pub const MAP_ANON: c_int = 0x1000;
        pub const MAP_ANONYMOUS: c_int = MAP_ANON;
        pub const MAP_PRIVATE: c_int = 0x0002;
        pub const MAP_JIT: c_int = 0x0800;
    } else if #[cfg(unix)] {
        pub type off_t = i64;

        pub const PROT_READ: c_int = 0x01;
        pub const PROT_WRITE: c_int = 0x02;
        pub const PROT_EXEC: c_int = 0x04;

        pub const MAP_ANON: c_int = 0x1000;
        pub const MAP_ANONYMOUS: c_int = MAP_ANON;
        pub const MAP_PRIVATE: c_int = 0x0002;
    }
}
