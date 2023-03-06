use std::arch::asm;
use std::ptr::null_mut;

use ffi::sys::windows::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualAlloc, VirtualProtect};

fn main() {
    static BLR_X8: &[u8] = &[
        0x00, 0x01, 0x3f, 0xd6, // blr x8
        //0xc0, 0x03, 0x5f, 0xd6 // ret
    ];

    let code = br(8);

    unsafe {
        let size = code.len();
        let mem = VirtualAlloc(null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if mem.is_null() {
            panic!("virtual alloc returns null, err: {}", std::io::Error::last_os_error());
        }

        let mem_w = mem as *mut u8;
        std::ptr::copy(code.as_ptr(), mem_w, size);

        let mut flag = 0;
        if VirtualProtect(mem, size, PAGE_EXECUTE, &mut flag) == 0 {
            panic!("failed to protect, err: {}", std::io::Error::last_os_error());
        }

        extern "C" fn execute() {
            println!("123");
        }

        asm!(
        "mov x8, {0}",
        in(reg) execute,
        );

        let fp: extern "C" fn() = std::mem::transmute(mem);

        fp();
    }
}

const BR: u8 = 0b00;
const BLR: u8 = 0b01;
const RET: u8 = 0b10;

#[inline]
const fn blr(rn: u8) -> [u8; 4] {
    branch_with_reg(BLR, rn)
}

const fn br(rn: u8) -> [u8; 4] {
    branch_with_reg(BR, rn)
}

#[inline]
const fn branch_with_reg(op: u8,rn: u8) -> [u8; 4] {
    // 1101011 | 0(Z) | 0 | 00 (BR) | 11111 | 0000 | 0(A) | 0(M) | 00000(Rn) | 00000(Rm)
    const BR: u32 = 0b11010110000111110000000000000000;
    let mut br = BR;
    br |= (rn as u32) << 5;
    br |= (op as u32) << 21;

    br.to_le_bytes()
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