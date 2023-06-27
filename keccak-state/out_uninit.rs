use crate::{IOBuf, Foldable, Switch, Squeezing};
use core::{alloc::Layout, mem::{self, MaybeUninit}, ptr};
#[cfg(feature = "alloc")] use alloc::{alloc::alloc, boxed::Box};

struct OutUninitStack<const N: usize> {
    data: [MaybeUninit<u8>; N],
}

impl<const N: usize> OutUninitStack<N> {
    fn new() -> Self {
        let data: [MaybeUninit<u8>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        Self { data }
    }

    fn finish(self) -> [u8; N] {
        let Self { data } = self;
        let res = unsafe { (data.as_ptr() as *const [u8; N]).read() };
        mem::forget(data);
        res
    }
}

impl<const N: usize> IOBuf for OutUninitStack<N> {
    #[inline(always)]
    fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize) {
        unsafe {
            ptr::copy_nonoverlapping(
                buf_part.as_ptr(),
                self.data.as_mut_ptr().cast::<u8>().offset(iobuf_offset as isize),
                len,
            );
        }
    }
}

pub trait SqueezeInitStack<const N: usize>: Foldable + Switch {
    fn squeeze_to_array(&mut self) -> [u8; N] {
        self.switch::<Squeezing>();
        let mut out = OutUninitStack::new();
        self.fold(&mut out);
        out.finish()
    }
}

#[cfg(feature = "alloc")]
struct OutUninitHeap {
    ptr: *mut u8,
    len: usize,
}

#[cfg(feature = "alloc")]
impl OutUninitHeap {
    fn new(len: usize) -> Self {
        let layout = Layout::array::<u8>(len).unwrap();
        let ptr = unsafe { alloc(layout) };
        Self { ptr, len }
    }

    fn finish(self) -> Box<[u8]> {
        let Self { ptr, len } = self;
        let slice_ptr = ptr::slice_from_raw_parts_mut(ptr, len);
        unsafe { Box::from_raw(slice_ptr) }
    }
}

#[cfg(feature = "alloc")]
impl IOBuf for OutUninitHeap {
    #[inline(always)]
    fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize) {
        unsafe {
            ptr::copy_nonoverlapping(
                buf_part.as_ptr(),
                self.ptr.offset(iobuf_offset as isize),
                len,
            );
        }
    }
}

#[cfg(feature = "alloc")]
pub trait SqueezeInitHeap<const N: usize>: Foldable + Switch {
    fn squeeze_to_box(&mut self, len: usize) -> Box<[u8]> {
        self.switch::<Squeezing>();
        let mut out = OutUninitHeap::new(len);
        self.fold(&mut out);
        out.finish()
    }
}
