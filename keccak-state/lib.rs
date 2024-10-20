#![allow(non_upper_case_globals, non_snake_case)]
#![deny(unused_results)]

#![no_std]

#[cfg(feature = "alloc")] extern crate alloc;
#[cfg(feature = "zeroize-on-drop")] use zeroize::Zeroize;

// region: consts

pub const BITS: usize = 1600;

pub const fn WORDS(bits: usize) -> usize {
    bits / 64
}

pub const fn BYTES(bits: usize) -> usize {
    bits / 8
}

pub const KeccakF: bool = true;
pub const KeccakP: bool = false;

pub const fn R(bits: usize) -> usize {
    200 - bits / 4
}

pub const R128: usize = R(128);
pub const R224: usize = R(224);
pub const R256: usize = R(256);
pub const R288: usize = R(288);
pub const R384: usize = R(384);
pub const R512: usize = R(512);
pub const R544: usize = R(544);

pub const DKeccak : u8 = 0x01;
pub const DSHA3   : u8 = 0x06;
pub const DSHAKE  : u8 = 0x1f;
pub const DCSHAKE : u8 = 0x04;

pub const Absorbing: bool = true;
pub const Squeezing: bool = false;

pub const XOR: bool = true;
pub const COPY: bool = false;

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

pub struct In<'b, const F: bool>(pub &'b [u8]);

impl<'b, const F: bool> IOBuf for In<'b, F> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize) {
        (match F { COPY => copy, XOR => xor })(buf_part, &self.0[iobuf_offset..], len)
    }
}

pub struct Out<'b, const F: bool>(pub &'b mut [u8]);

impl<'b, const F: bool> IOBuf for Out<'b, F> {
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
pub struct KeccakState<const P: bool, const R: usize> {
    buf: [u8; BYTES(BITS)],
    offset: usize,
    delim: u8,
    mode: bool,
}

#[cfg(feature = "zeroize-on-drop")]
impl<const P: bool, const R: usize> Drop for KeccakState<P, R> {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.offset = 0;
    }
}

impl<const P: bool, const R: usize> KeccakState<P, R> {
    pub fn with_initial(delim: u8, buf: [u8; BYTES(BITS)]) -> Self {
        // TODO complie time
        assert!(R != 0, "rate cannot be equal 0");
        KeccakState {
            buf,
            offset: 0,
            delim,
            mode: Absorbing,
        }
    }

    pub fn new(delim: u8) -> Self {
        Self::with_initial(delim, [0; BYTES(BITS)])
    }

    pub fn to_initial(self) -> Option<[u8; BYTES(BITS)]> {
        if self.offset == 0 && matches!(self.mode, Absorbing) {
            Some(self.buf)
        } else {
            None
        }
    }

    fn pad(&mut self) {
        self.buf[self.offset] ^= self.delim;
        self.buf[R - 1] ^= 0x80;
    }

    pub fn change_delim(self, delim: u8) -> Self {
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
    fn switch<const M: bool>(&mut self);
}

impl<const P: bool, const R: usize> Foldable for KeccakState<P, R> {
    fn fold<B: IOBuf>(&mut self, iobuf: &mut B) {
        let mut iobuf_offset = 0;
        let mut iobuf_rest = iobuf.len();
        let mut len = R - self.offset;
        while iobuf_rest >= len {
            iobuf.exec(&mut self.buf[self.offset..], iobuf_offset, len);
            self.fill_block();
            iobuf_offset += len;
            iobuf_rest -= len;
            len = R;
        }
        iobuf.exec(&mut self.buf[self.offset..], iobuf_offset, iobuf_rest);
        self.offset += iobuf_rest;
    }

    fn fill_block(&mut self) {
        let words: &mut [u64; WORDS(BITS)] = unsafe { core::mem::transmute(&mut self.buf) };
        #[cfg(target_endian = "big")]
        #[inline]
        fn swap_endianess(words: &mut [u64; WORDS(BITS)]) {
            for item in words {
                *item = item.swap_bytes();
            }
        }
        #[cfg(target_endian = "big")]
        swap_endianess(words);
        if P == KeccakF {
            keccak::f1600(words);
        } else {
            keccak::p1600(words, 12);
        }
        #[cfg(target_endian = "big")]
        swap_endianess(words);
        self.offset = 0;
    }
}

impl<const P: bool, const R: usize> Switch for KeccakState<P, R> {
    #[inline]
    fn switch<const M: bool>(&mut self) {
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
        use core::mem::MaybeUninit;
        let mut buf: [MaybeUninit<u8>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        let ready_buf = getrandom::getrandom_uninit(&mut buf).unwrap();
        self.absorb(ready_buf);
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
        self.switch::<Absorbing>();
        self.fold(&mut In::<XOR>(input));
    }
}

impl<T: Foldable + Switch> AbsorbZero for T {
    fn absorb_zero(&mut self, len: usize) {
        self.switch::<Absorbing>();
        self.fold(&mut Skip(len));
    }
}

impl<T: Foldable + Switch> Squeeze for T {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.switch::<Squeezing>();
        self.fold(&mut Out::<COPY>(output));
    }
}

impl<T: Foldable + Switch> SqueezeXor for T {
    fn squeeze_xor(&mut self, output: &mut [u8]) {
        self.switch::<Squeezing>();
        self.fold(&mut Out::<XOR>(output));
    }
}

impl<T: Foldable + Switch> SqueezeSkip for T {
    fn squeeze_skip(&mut self, len: usize) {
        self.switch::<Squeezing>();
        self.fold(&mut Skip(len));
    }
}

impl<const P: bool, const R: usize> Reset for KeccakState<P, R> {
    fn reset(&mut self) {
        #[cfg(feature = "zeroize-on-drop")]
        self.buf.zeroize();
        #[cfg(not(feature = "zeroize-on-drop"))]
        let _ = core::mem::replace(&mut self.buf, [0; BYTES(BITS)]);
        self.offset = 0;
        self.mode = Absorbing;
    }
}

// endregion
