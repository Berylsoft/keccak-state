use crate::{IOBuf, Foldable, Switch, Squeezing};
use core::{mem::MaybeUninit, ptr::copy_nonoverlapping};
#[cfg(feature = "alloc")] use core::{alloc::Layout, ptr::NonNull};
#[cfg(feature = "alloc")] use alloc::{alloc::{alloc, handle_alloc_error}, boxed::Box};

struct OutUninitStack<const N: usize> {
    data: [MaybeUninit<u8>; N],
}

impl<const N: usize> OutUninitStack<N> {
    fn new() -> Self {
        // use MaybeUninit::uninit_array() when stable
        let data: [MaybeUninit<u8>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        Self { data }
    }

    unsafe fn finish(self) -> [u8; N] {
        let Self { data } = self;
        // use data.array_assume_init() when stable
        (data.as_ptr() as *const [u8; N]).read()
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
            copy_nonoverlapping(
                buf_part.as_ptr(),
                self.data.as_mut_ptr().cast::<u8>().add(iobuf_offset),
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
        unsafe { out.finish() }
    }
}

// alloc::raw_vec::capacity_overflow
#[cfg(feature = "alloc")]
fn capacity_overflow() -> ! {
    panic!("capacity overflow");
}

#[cfg(feature = "alloc")]
fn alloc_bytes(len: usize) -> NonNull<[u8]> {
    assert_ne!(len, 0);
    let layout = Layout::array::<u8>(len).unwrap_or_else(|_| capacity_overflow());
    // use <alloc::alloc::Global as core::alloc::Allocator>::alloc when stable
    let raw_ptr = unsafe { alloc(layout) };
    let ptr = NonNull::new(raw_ptr).unwrap_or_else(|| handle_alloc_error(layout));
    NonNull::slice_from_raw_parts(ptr, len)
}

#[cfg(feature = "alloc")]
struct OutUninitHeap {
    ptr: NonNull<[u8]>,
}

#[cfg(feature = "alloc")]
impl OutUninitHeap {
    fn new(len: usize) -> Self {
        let ptr = alloc_bytes(len);
        Self { ptr }
    }

    unsafe fn finish(self) -> Box<[u8]> {
        let Self { mut ptr } = self;
        Box::from_raw(ptr.as_mut())
    }
}

#[cfg(feature = "alloc")]
impl IOBuf for OutUninitHeap {
    #[inline(always)]
    fn len(&self) -> usize {
        self.ptr.len()
    }

    #[inline(always)]
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize) {
        unsafe {
            copy_nonoverlapping(
                buf_part.as_ptr(),
                self.ptr.as_ptr().cast::<u8>().add(iobuf_offset),
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
        unsafe { out.finish() }
    }
}
