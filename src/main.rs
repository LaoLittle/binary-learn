use std::ptr::null_mut;

use ffi::sys::windows::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};

fn main() {
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

#[inline]
const fn blr(rn: u8) -> [u8; 4] {
    branch_with_reg(BLR, rn)
}

#[inline]
const fn br(rn: u8) -> [u8; 4] {
    branch_with_reg(BR, rn)
}

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
    // 1101011 | 0(Z) | 0 | 00 (BR) | 11111 | 0000 | 0(A) | 0(M) | 00000(Rn) | 00000(Rm)
    const BR0: u32 = 0b11010110000111110000000000000000;
    let mut br = BR0;
    br |= (rn as u32) << 5;
    br |= (op as u32) << 21;

    br.to_le_bytes()
}

const SF: u32 = 1 << 31;

const fn movk(sf: bool, hw: u8, imm: u16, rd: u8) -> [u8; 4] {
    const BASE_MOVK: u32 = 0b01110010100000000000000000000000;
    let mut base = BASE_MOVK;

    if sf {
        base |= SF;
    }

    base |= (hw as u32) << 21;
    base |= (imm as u32) << 5;
    base |= rd as u32;

    base.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use crate::blr;

    #[test]
    fn op_eq() {
        let bytecode = [0x00, 0x01, 0x3f, 0xd6]; // blr x8 (LE)
        assert_eq!(blr(8), bytecode);
    }
}
