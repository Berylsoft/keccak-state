#![deny(unused_results)]

#![no_std]

#![feature(adt_const_params, const_param_ty_trait)]

#[cfg(feature = "alloc")] extern crate alloc;
#[cfg(feature = "zeroize-on-drop")] use zeroize::Zeroize;

// region: consts

pub const BITS: usize = 1600;

pub const fn words_from_bits(bits: usize) -> usize {
    bits / 64
}

pub const WORDS: usize = words_from_bits(BITS);

pub const fn bytes_from_bits(bits: usize) -> usize {
    bits / 8
}

pub const BYTES: usize = bytes_from_bits(BITS);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeccakType {
    KeccakF,
    KeccakP,
}

impl core::marker::ConstParamTy_ for KeccakType {}

pub const fn rate_from_bits(bits: usize) -> usize {
    200 - bits / 4
}

#[repr(usize)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rate {
    R128 = rate_from_bits(128),
    R224 = rate_from_bits(224),
    R256 = rate_from_bits(256),
    R288 = rate_from_bits(288),
    R384 = rate_from_bits(384),
    R512 = rate_from_bits(512),
    R544 = rate_from_bits(544),
}

impl core::marker::ConstParamTy_ for Rate {}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Delim {
    Keccak = 0x01,
    SHA3   = 0x06,
    SHAKE  = 0x1f,
    CSHAKE = 0x04,
}

impl core::marker::ConstParamTy_ for Delim {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FoldMode {
    Absorbing,
    Squeezing,
}

pub use FoldMode::*;

impl core::marker::ConstParamTy_ for FoldMode {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IOMode {
    XOR,
    COPY,
}

pub use IOMode::*;

impl core::marker::ConstParamTy_ for IOMode {}

// endregion

// region: iobuf

#[inline(always)]
fn xor(dst: &mut [u8], src: &[u8], len: usize) {
    let (dst, src) = (&mut dst[..len], &src[..len]);
    for i in 0..len {
        dst[i] ^= src[i];
    }
}

#[inline(always)]
fn copy(dst: &mut [u8], src: &[u8], len: usize) {
    let (dst, src) = (&mut dst[..len], &src[..len]);
    dst.copy_from_slice(src)
}

#[allow(clippy::len_without_is_empty)]
pub trait IOBuf {
    fn len(&self) -> usize;
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize);
}

pub struct In<'b, const F: IOMode>(pub &'b [u8]);

impl<'b, const F: IOMode> IOBuf for In<'b, F> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize) {
        (match F { COPY => copy, XOR => xor })(buf_part, &self.0[iobuf_offset..], len)
    }
}

pub struct Out<'b, const F: IOMode>(pub &'b mut [u8]);

impl<'b, const F: IOMode> IOBuf for Out<'b, F> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize) {
        (match F { COPY => copy, XOR => xor })(&mut self.0[iobuf_offset..], buf_part, len)
    }
}

pub struct Skip(pub usize);

impl IOBuf for Skip {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0
    }

    #[inline(always)]
    fn exec(&mut self, _buf_part: &mut [u8], _iobuf_offset: usize, _len: usize) { }
}

// endregion

// region: state

#[derive(Clone)]
pub struct KeccakState<const P: KeccakType, const R: Rate> {
    buf: [u8; BYTES],
    offset: usize,
    delim: Delim,
    mode: FoldMode,
}

#[cfg(feature = "zeroize-on-drop")]
impl<const P: KeccakType, const R: Rate> Drop for KeccakState<P, R> {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.offset = 0;
    }
}

impl<const P: KeccakType, const R: Rate> KeccakState<P, R> {
    pub fn with_initial(delim: Delim, buf: [u8; BYTES]) -> Self {
        KeccakState {
            buf,
            offset: 0,
            delim,
            mode: Absorbing,
        }
    }

    pub fn new(delim: Delim) -> Self {
        Self::with_initial(delim, [0; BYTES])
    }

    pub fn to_initial(self) -> Option<[u8; BYTES]> {
        if self.offset == 0 && matches!(self.mode, Absorbing) {
            Some(self.buf)
        } else {
            None
        }
    }

    fn pad(&mut self) {
        self.buf[self.offset] ^= self.delim as u8;
        self.buf[(R as usize) - 1] ^= 0x80;
    }

    pub fn change_delim(self, delim: Delim) -> Self {
        let KeccakState { buf, offset, mode, delim: _ } = self;
        KeccakState { buf, offset, mode, delim }
    }
}

// endregion

pub trait Foldable {
    fn fold<B: IOBuf>(&mut self, iobuf: &mut B);

    fn fill_block(&mut self);
}

pub trait Switch: Foldable {
    fn switch<const M: FoldMode>(&mut self);
}

impl<const P: KeccakType, const R: Rate> Foldable for KeccakState<P, R> {
    fn fold<B: IOBuf>(&mut self, iobuf: &mut B) {
        let mut iobuf_offset = 0;
        let mut iobuf_rest = iobuf.len();
        let mut len = (R as usize) - self.offset;
        while iobuf_rest >= len {
            iobuf.exec(&mut self.buf[self.offset..], iobuf_offset, len);
            self.fill_block();
            iobuf_offset += len;
            iobuf_rest -= len;
            len = R as usize;
        }
        iobuf.exec(&mut self.buf[self.offset..], iobuf_offset, iobuf_rest);
        self.offset += iobuf_rest;
    }

    fn fill_block(&mut self) {
        let words: &mut [u64; WORDS] = unsafe { core::mem::transmute(&mut self.buf) };
        #[cfg(target_endian = "big")]
        #[inline]
        fn swap_endianess(words: &mut [u64; WORDS]) {
            for item in words {
                *item = item.swap_bytes();
            }
        }
        #[cfg(target_endian = "big")]
        swap_endianess(words);
        match P {
            KeccakType::KeccakF => keccak::f1600(words),
            KeccakType::KeccakP => keccak::p1600(words, 12),
        }
        #[cfg(target_endian = "big")]
        swap_endianess(words);
        self.offset = 0;
    }
}

impl<const P: KeccakType, const R: Rate> Switch for KeccakState<P, R> {
    #[inline]
    fn switch<const M: FoldMode>(&mut self) {
        if self.mode != M {
            if M == Squeezing {
                self.pad();
            }
            self.fill_block();
            self.mode = M;
        }
    }
}

// region: traits

pub trait Absorb: Sized {
    fn absorb(&mut self, input: &[u8]);
    
    #[inline(always)]
    fn chain_absorb(mut self, input: &[u8]) -> Self {
        self.absorb(input);
        self
    }
}

// TODO merge to Absorb after Foldable complete
pub trait AbsorbZero {
    fn absorb_zero(&mut self, len: usize);
}

pub trait Squeeze {
    fn squeeze(&mut self, output: &mut [u8]);

    #[inline]
    fn squeeze_to_array<const N: usize>(&mut self) -> [u8; N] {
        let mut buf = [0; N];
        self.squeeze(&mut buf);
        buf
    }

    #[cfg(feature = "alloc")]
    #[inline]
    fn squeeze_to_vec(&mut self, len: usize) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::from_elem(0, len);
        self.squeeze(&mut buf);
        buf
    }
}

// TODO merge to Squeeze after Foldable complete
pub trait SqueezeXor {
    fn squeeze_xor(&mut self, output: &mut [u8]);
}

// TODO merge to Squeeze after Foldable complete
pub trait SqueezeSkip {
    fn squeeze_skip(&mut self, len: usize);
}

pub trait Reset {
    fn reset(&mut self);
}

// TODO merge to Absorb after Foldable complete
#[cfg(feature = "seed")]
pub trait AbsorbSeed: Absorb {
    fn absorb_seed<const N: usize>(&mut self) {
        let mut buf: [u8; N] = [0; N];
        getrandom::fill(&mut buf).unwrap();
        self.absorb(&buf);
        #[cfg(feature = "zeroize-on-drop")]
        buf.zeroize();
    }
}

#[cfg(feature = "seed")]
impl<T: Absorb> AbsorbSeed for T {}

// endregion

// region: trait impls

impl<T: Foldable + Switch> Absorb for T {
    fn absorb(&mut self, input: &[u8]) {
        self.switch::<{ Absorbing }>();
        self.fold(&mut In::<{ XOR }>(input));
    }
}

impl<T: Foldable + Switch> AbsorbZero for T {
    fn absorb_zero(&mut self, len: usize) {
        self.switch::<{ Absorbing }>();
        self.fold(&mut Skip(len));
    }
}

impl<T: Foldable + Switch> Squeeze for T {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.switch::<{ Squeezing }>();
        self.fold(&mut Out::<{ COPY }>(output));
    }
}

impl<T: Foldable + Switch> SqueezeXor for T {
    fn squeeze_xor(&mut self, output: &mut [u8]) {
        self.switch::<{ Squeezing }>();
        self.fold(&mut Out::<{ XOR }>(output));
    }
}

impl<T: Foldable + Switch> SqueezeSkip for T {
    fn squeeze_skip(&mut self, len: usize) {
        self.switch::<{ Squeezing }>();
        self.fold(&mut Skip(len));
    }
}

impl<const P: KeccakType, const R: Rate> Reset for KeccakState<P, R> {
    fn reset(&mut self) {
        #[cfg(feature = "zeroize-on-drop")]
        self.buf.zeroize();
        #[cfg(not(feature = "zeroize-on-drop"))]
        let _ = core::mem::replace(&mut self.buf, [0; BYTES]);
        self.offset = 0;
        self.mode = Absorbing;
    }
}

// endregion

pub mod out_uninit;

pub mod absorb_seed_unsafe;
