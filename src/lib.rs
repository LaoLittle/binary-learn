use std::marker::PhantomData;
use std::ptr::NonNull;

pub mod arg;
pub mod mem;
mod sys;

/*
pub struct CFunction<'a> {
    compiled: NonNull<()>,
    _mark: PhantomData<&'a ()>
}

impl<'a> CFunction<'a> {
    pub fn from_raw(raw_cfuncion: extern "C" fn(*mut ()), arg: *mut ()) {

    }
}

 */
