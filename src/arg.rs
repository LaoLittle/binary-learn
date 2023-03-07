pub enum Argument {
    Int8,
    Int16,
    Int32,
    Int64,
    TinyStruct,  // [0..64]
    SmallStruct, // (64..128]
    LargeStruct, // (128..)
}

pub const fn arg_select<T>() -> Argument {
    let len = std::mem::size_of::<T>();

    match len {
        0..=64 => Argument::TinyStruct,
        65..=128 => Argument::SmallStruct,
        _ => Argument::LargeStruct,
    }
}
