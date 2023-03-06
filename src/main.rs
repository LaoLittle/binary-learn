use std::ptr::null_mut;

use ffi::sys::windows::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};

fn main() {
    let my = [0xe8, 0x2f, 0x00, 0xf9];
    let my = u32::from_ne_bytes(my);

    println!("{:b}", my);

    unsafe {
        fn extract<F: Fn()>(f: &F) -> u64 {
            extern "C" fn invoke<F: Fn()>(addr: *const F) {
                unsafe {
                    (*addr)();
                }
            }

            invoke::<F> as u64
        }

        union Imm {
            addr: u64,
            imms: [u16; 4],
        }

        let var = 1234;
        let closure = move || {
            println!("var={}", var);
        };

        let invk = Imm {
            addr: extract(&closure),
        };
        let [a, b, c, d] = invk.imms;

        let arg = Imm {
            addr: &closure as *const _ as u64,
        };
        let [o, p, q, r] = arg.imms;

        let code = [
            movk(true, 0, o, 0),
            movk(true, 1, p, 0),
            movk(true, 2, q, 0),
            movk(true, 3, r, 0),
            movk(true, 0, a, 8),
            movk(true, 1, b, 8),
            movk(true, 2, c, 8),
            movk(true, 3, d, 8),
            br(8),
        ]
        .concat();

        #[repr(C)]
        struct MyStruct {
            fa: i64,
            fb: i64,
            fc: [u8; 4],
        }
        extern "C" fn stru() {}

        let size = code.len();
        let mem = VirtualAlloc(null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if mem.is_null() {
            panic!(
                "virtual alloc returns null, err: {}",
                std::io::Error::last_os_error()
            );
        }

        let mem_w = mem as *mut u8;
        std::ptr::copy(code.as_ptr(), mem_w, size);

        let mut flag = 0;
        if VirtualProtect(mem, size, PAGE_EXECUTE, &mut flag) == 0 {
            panic!(
                "failed to protect, err: {}",
                std::io::Error::last_os_error()
            );
        }

        let fp: extern "C" fn() = std::mem::transmute(mem);
        fp();

        drop(closure)
    }
}

const BR: u8 = 0b00;
const BLR: u8 = 0b01;
const RET: u8 = 0b10;

// BLR Rn
#[inline]
const fn blr(rn: u8) -> [u8; 4] {
    branch_with_reg(BLR, rn)
}

// BR Rn
#[inline]
const fn br(rn: u8) -> [u8; 4] {
    branch_with_reg(BR, rn)
}

// RET
#[inline]
const fn ret(rn: Option<u8>) -> [u8; 4] {
    branch_with_reg(
        RET,
        match rn {
            Some(rn) => rn,
            None => 30,
        },
    )
}

const fn branch_with_reg(op: u8, rn: u8) -> [u8; 4] {
    debug_assert!(op <= 0b10 && is_valid_reg(rn));
    // 1101011 | 0(Z) | 0 | 00 (BR) | 11111 | 0000 | 0(A) | 0(M) | 00000(Rn) | 00000(Rm)
    const BR0: u32 = 0b11010110000111110000000000000000;
    let mut br = BR0;
    br |= (rn as u32) << 5;
    br |= (op as u32) << 21;

    br.to_ne_bytes()
}

const SF: u32 = 1 << 31;

// MOVK Rd, #<imm>
const fn movk(sf: bool, hw: u8, imm: u16, rd: u8) -> [u8; 4] {
    debug_assert!(hw <= 0b11 && is_valid_reg(rd));
    const BASE_MOVK: u32 = 0b01110010100000000000000000000000;
    let mut base = BASE_MOVK;

    if sf {
        base |= SF;
    }

    base |= (hw as u32) << 21;
    base |= (imm as u32) << 5;
    base |= rd as u32;

    base.to_ne_bytes()
}

// STR Rt [Rn], offset
const fn str_immpost(is_64_bit: bool, offset: i16, rn: u8, rt: u8) -> [u8; 4] {
    debug_assert!(offset >= -256 && offset < 255);

    const I9_BITS: u32 = 0b111111111;
    const FLAG: u32 = 0b01 << 10;

    let mut base = str_imm_base(is_64_bit, rn, rt);
    base |= (offset as u32 & I9_BITS) << 12;
    base |= FLAG;

    base.to_ne_bytes()
}

// STR Rt [Rn, offset]!
const fn str_immpre(is_64_bit: bool, offset: i16, rn: u8, rt: u8) -> [u8; 4] {
    debug_assert!(offset >= -256 && offset < 255);

    const I9_BITS: u32 = 0b111111111;
    const FLAG: u32 = 0b11 << 10;

    let mut base = str_imm_base(is_64_bit, rn, rt);
    base |= (offset as u32 & I9_BITS) << 12;
    base |= FLAG;

    base.to_ne_bytes()
}

// STR Rt [Rn, offset]
const fn str_immunsigned(is_64_bit: bool, offset: u16, rn: u8, rt: u8) -> [u8; 4] {
    debug_assert!((is_64_bit && offset <= 32760) || offset <= 16380);

    const FLAG: u32 = 1 << 24;
    let imm = if is_64_bit { offset / 8 } else { offset / 4 };

    let mut base = str_imm_base(is_64_bit, rn, rt);
    base |= FLAG;
    base |= (imm as u32) << 10;

    base.to_ne_bytes()
}

const fn str_imm_base(is_64_bit: bool, rn: u8, rt: u8) -> u32 {
    debug_assert!(is_valid_reg(rn) && is_valid_reg(rt));
    const BASE_STR: u32 = 0b10111000000000000000000000000000;
    const SIZE: u32 = 1 << 30;

    let mut str = BASE_STR;

    if is_64_bit {
        str |= SIZE;
    }

    str |= (rn as u32) << 5;
    str |= rt as u32;

    str
}

/// check if it is a valid armv8 register
const fn is_valid_reg(rn: u8) -> bool {
    rn < 32
}

#[cfg(test)]
mod tests {
    use crate::{blr, str_immunsigned};

    #[test]
    fn op_eq() {
        let bytecode = [0x00, 0x01, 0x3f, 0xd6]; // blr x8 (LE)
        assert_eq!(blr(8), bytecode);

        let bytecode = [0xe3, 0x17, 0x00, 0xf9];
        assert_eq!(str_immunsigned(true, 0x28, 31 /* sp */, 3), bytecode);
    }
}
