use ffi::arg::Argument;
use ffi::mem::AllocatedMemory;

fn build_bytecode<I: Iterator<Item = Argument>>(
    args: I,
    cfunc: *const (),
    arg: *mut (),
) -> Vec<u8> {
    let mut reg_args = [[0u8; 4]; 8];

    let mut i = 0;
    // first pass integers
    for arg in args {
        if i == 8 {
            break;
        }

        let r = i as u8;
        match arg {
            Argument::Int8 | Argument::Int16 | Argument::Int32 => {
                reg_args[i] = mov_reg(false, r + 1, r);
            }
            Argument::Int64 | Argument::TinyStruct | Argument::LargeStruct => {
                reg_args[i] = mov_reg(true, r + 1, r);
            }
            Argument::SmallStruct => {
                reg_args[i] = mov_reg(true, r + 1, r);
                i += 1;
                reg_args[i] = mov_reg(true, r + 2, r + 1);
            }
        }

        i += 1;
    }

    let mut v = Vec::with_capacity((i + 9) * 4);

    let reg = if i == 7 { 9 } else { i as u8 + 1 };

    let [a, b, c, d]: [u16; 4] = unsafe { std::mem::transmute(cfunc) };
    let [o, p, q, r]: [u16; 4] = unsafe { std::mem::transmute(arg) };

    let to = &mut reg_args[..i];
    to.reverse();
    v.extend(to.concat());
    v.extend(
        [
            movk(true, 0, o, 0),
            movk(true, 1, p, 0),
            movk(true, 2, q, 0),
            movk(true, 3, r, 0),
            movk(true, 0, a, reg),
            movk(true, 1, b, reg),
            movk(true, 2, c, reg),
            movk(true, 3, d, reg),
            br(reg),
        ]
        .concat(),
    );

    v
}

#[cfg(test)]
mod t {
    use crate::build_bytecode;
    use ffi::arg::Argument;
    use ffi::mem::AllocatedMemory;

    #[test]
    fn tttt() {
        #[repr(C)]
        #[derive(Debug)]
        struct TinyS {
            i: i64,
        }

        const TEST_PTR: *mut () = 123usize as *mut ();
        extern "C" fn call(arg: *mut (), a: i32, b: TinyS) -> TinyS {
            assert_eq!(arg, TEST_PTR);
            println!("args: {a}, {b:?}");

            TinyS { i: 56778 }
        }
        let arguments = [Argument::Int32, Argument::TinyStruct];
        let v = build_bytecode(arguments.into_iter(), call as _, TEST_PTR);

        unsafe {
            let mut mem = AllocatedMemory::new(v.len()).unwrap();
            mem.write(&v, 0).unwrap();
            let cfunc: extern "C" fn(i32, TinyS) -> TinyS = std::mem::transmute(mem.as_ptr());

            println!("{:?}", cfunc(114, TinyS { i: 514 }));
        }
        #[repr(C)]
        #[derive(Debug)]
        struct LargeS {
            i: i64,
            i2: i64,
            i3: i64,
        }
        extern "C" fn call2(arg: *mut (), a: i32, large: LargeS) -> LargeS {
            assert_eq!(arg, TEST_PTR);
            println!("{a}, {large:?}");

            LargeS {
                i: 12,
                i2: 34,
                i3: 56,
            }
        }

        let v = build_bytecode(
            [Argument::Int32, Argument::LargeStruct].into_iter(),
            call2 as _,
            TEST_PTR,
        );

        unsafe {
            let mut mem = AllocatedMemory::new(v.len()).unwrap();
            mem.write(&v, 0).unwrap();
            let cfunc: extern "C" fn(i32, LargeS) -> LargeS = std::mem::transmute(mem.as_ptr());

            println!(
                "{:?}",
                cfunc(
                    114,
                    LargeS {
                        i: 514,
                        i2: 514,
                        i3: 33231
                    }
                )
            );
        }
    }
}

fn main() {
    let my = [0xe8, 0x2f, 0x00, 0xf9];
    let my = u32::from_ne_bytes(my);

    println!("{:b}", my);

    unsafe {
        #[repr(C)]
        #[derive(Debug)]
        struct B {
            a: i32,
            b: i64,
            c: i64,
        }
        fn extract<F: Fn(i64, B, i64) -> B>(f: &F) -> u64 {
            extern "C" fn invoke<F: Fn(i64, B, i64) -> B>(
                addr: *const F,
                f: i64,
                b: B,
                c: i64,
            ) -> B {
                unsafe { (*addr)(f, b, c) }
            }

            invoke::<F> as u64
        }

        union Imm {
            addr: u64,
            imms: [u16; 4],
        }

        let var = 1234;
        let closure = move |f: i64, b: B, c: i64| {
            println!("var={}, f={f}, b={b:?}, c={c}", var);

            B {
                a: 1588,
                b: 223,
                c: 11144,
            }
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
            mov_reg(true, 3, 2),
            mov_reg(true, 2, 1),
            mov_reg(true, 1, 0),
            movk(true, 0, o, 0),
            movk(true, 1, p, 0),
            movk(true, 2, q, 0),
            movk(true, 3, r, 0),
            movk(true, 0, a, 9),
            movk(true, 1, b, 9),
            movk(true, 2, c, 9),
            movk(true, 3, d, 9),
            br(9),
        ]
        .concat();

        let mut mem = AllocatedMemory::new(code.len()).unwrap();

        mem.write(&code, 0).unwrap();

        println!("pre call");
        let fp: extern "C" fn(i64, B, i64) -> B = std::mem::transmute(mem.as_ptr());
        let bb = fp(
            21415,
            B {
                a: 12,
                b: 114,
                c: 514,
            },
            1241,
        );
        println!("Got {:?}", bb);
        println!("post call");

        drop(closure)
    }
}

const BR: u8 = 0b00;
const BLR: u8 = 0b01;
const RET: u8 = 0b10;

const X31: u8 = 31;
const SP: u8 = X31;

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
    debug_assert!(offset >= -256 && offset <= 255);

    const I9_BITS: u32 = 0b111111111;
    const FLAG: u32 = 0b01 << 10;

    let mut base = str_imm_base(is_64_bit, rn, rt);
    base |= (offset as u32 & I9_BITS) << 12;
    base |= FLAG;

    base.to_ne_bytes()
}

// STR Rt [Rn, offset]!
const fn str_immpre(is_64_bit: bool, offset: i16, rn: u8, rt: u8) -> [u8; 4] {
    debug_assert!(offset >= -256 && offset <= 255);

    const I9_BITS: u32 = 0b111111111;
    const FLAG: u32 = 0b11 << 10;

    let mut base = str_imm_base(is_64_bit, rn, rt);
    base |= (offset as u32 & I9_BITS) << 12;
    base |= FLAG;

    base.to_ne_bytes()
}

// STR Rt [Rn, offset]
const fn str_immunsigned(is_64_bit: bool, offset: u16, rn: u8, rt: u8) -> [u8; 4] {
    debug_assert!(
        (is_64_bit && offset <= 32760 && (offset & 0b111 == 0))
            || offset <= 16380 && (offset & 0b11 == 0)
    );

    const FLAG: u32 = 1 << 24;
    let imm = if is_64_bit { offset >> 3 } else { offset >> 2 };

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

// ADD Rd, Rn, #<imm>{,<shift>}
// if sh, LSL #12
const fn add_imm(sf: bool, rd: u8, rn: u8, imm: u16, sh: bool) -> [u8; 4] {
    debug_assert!(imm >= 0 && imm <= 4095 && is_valid_reg(rd) && is_valid_reg(rn));

    const BASE_ADD: u32 = 0b00010001000000000000000000000000;
    const SF: u32 = 1 << 31;
    const SHIFT: u32 = 1 << 22;
    let mut base = BASE_ADD;

    if sf {
        base |= SF;
    }
    base |= rd as u32;
    base |= (rn as u32) << 5;
    base |= (imm as u32) << 10;
    if sh {
        base |= SHIFT;
    }

    base.to_ne_bytes()
}

const ORR_LSL: u32 = 0b00 << 22;
const ORR_LSR: u32 = 0b01 << 22;
const ORR_ASR: u32 = 0b10 << 22;
const ORR_ROR: u32 = 0b11 << 22;

// ORR Rd, Rn, Rm {,#<shift> #<amount>}
const fn orr_reg(sf: bool, rd: u8, rn: u8, rm: u8, shift: u32, amount: u8) -> [u8; 4] {
    debug_assert!(
        is_valid_reg(rd)
            && is_valid_reg(rn)
            && is_valid_reg(rm)
            && (shift >> 22) <= 0b11
            && (amount <= 31 || (sf && amount <= 63))
    );

    const ORR_BASE: u32 = 0b00101010000000000000000000000000;
    const SF: u32 = 1 << 31;
    let mut base = ORR_BASE;

    if sf {
        base |= SF;
    }
    base |= rd as u32;
    base |= (rn as u32) << 5;
    base |= (rm as u32) << 16;
    base |= (amount as u32) << 10;

    base.to_ne_bytes()
}

// MOV SP, Rn
// alias of ADD SP, Rn, 0
#[inline]
const fn mov_to_sp(sf: bool, rn: u8) -> [u8; 4] {
    add_imm(sf, SP, rn, 0, false)
}

// MOV Rn, SP
// alias of ADD Rn, SP, 0
#[inline]
const fn mov_from_sp(sf: bool, rn: u8) -> [u8; 4] {
    add_imm(sf, rn, SP, 0, false)
}

// MOV Rd, Rm
#[inline]
const fn mov_reg(sf: bool, rd: u8, rm: u8) -> [u8; 4] {
    orr_reg(sf, rd, 31, rm, 0, 0)
}

// check if it is a valid armv8 register
#[inline]
const fn is_valid_reg(rn: u8) -> bool {
    rn <= 31
}

#[cfg(test)]
mod tests {
    use crate::{blr, str_immunsigned};
    use std::mem::MaybeUninit;

    #[test]
    fn op_eq() {
        let bytecode = [0x00, 0x01, 0x3f, 0xd6]; // blr x8 (LE)
        assert_eq!(blr(8), bytecode);

        let bytecode = [0xe3, 0x17, 0x00, 0xf9];
        assert_eq!(str_immunsigned(true, 0x28, 31 /* sp */, 3), bytecode);
    }

    #[test]
    fn ab() {
        #[repr(C)]
        #[derive(Debug)]
        struct A {
            i: i32,
            b: i64,
            c: i32,
            d: i64,
        }
        const MY_A: A = A {
            i: 114,
            b: 514,
            c: 1919,
            d: 810,
        };

        #[repr(C)]
        struct B {
            a: i32,
        }

        extern "C" fn abc(
            a0: i64,
            a1: A,
            a2: i32,
            a3: i64,
            a4: f64,
            a5: i64,
            a6: i64,
            a7: A,
            a8: f64,
            a9: A,
            a10: A,
            a11: B,
        ) {
            println!(
                "{}, {:?}, {}, {}, {}, {}, {}, {:?}, {}, {:?}, {:?}, a11={}",
                a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11.a
            );
        }

        let a = Box::new(MY_A);
        let mut b = MY_A;
        b.d = 123456;
        let mut c = MY_A;
        c.i = 1442142;
        let bb = B { a: 32 };
        unsafe {
            std::arch::asm!(
            "sub sp, sp, 32",
            "mov x0, 12",
            "mov x2, 333",
            "mov x3, 114",
            "fmov d0, 20.0",
            "fmov d1, 14.0",
            "mov x4, 1234",
            "mov x5, 6789",
            "mov x6, x1",
            "mov x7, {1}",
            "str {2}, [sp]",
            "str {3}, [sp, 8]",
            "blr {0}",
            "add sp, sp, 32",
            in(reg) abc,
            in(reg) &b,
            in(reg) &c,
            in(reg) 141,
            in("x1") a.as_ref(),
            );
        }
    }

    #[test]
    fn ddd() {
        #[repr(C)]
        #[derive(Debug)]
        struct DA {
            a: i64,
            b: i64,
            c: i64,
        }
        extern "C" fn pass(a0: f64, a1: i64) -> DA {
            dbg!(a0, a1);

            DA {
                a: 114,
                b: 514,
                c: 123,
            }
        }

        let a: i64;
        let b: i64;
        let c: i64;
        let mut s = DA { a: 1, b: 2, c: 3 };
        unsafe {
            std::arch::asm!(
            "fmov d0, {1}", // a0
            "mov x0, 514", // a1
            "mov x8, {2}",
            "blr {0}",
            in(reg) pass,
            in(reg) 11.4,
            in(reg) &mut s,
            );
        }

        println!("{:?}", s);

        //println!("{:?}", (a));
    }
}
