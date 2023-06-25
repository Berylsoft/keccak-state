#![no_std]
#![allow(non_upper_case_globals, non_snake_case)]

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

pub const NOP: bool = false;
pub const COPY: bool = false;
pub const XOR: bool = true;

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

enum IOBuf<'b, const F: bool> {
    In(&'b [u8]),
    Out(&'b mut [u8]),
    Skip(usize),
}

impl<'b, const F: bool> IOBuf<'b, F> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            IOBuf::In(iobuf) => iobuf.len(),
            IOBuf::Out(iobuf) => iobuf.len(),
            IOBuf::Skip(len) => *len,
        }
    }

    #[inline]
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize) {
        let f = match F {
            COPY => copy,
            XOR => xor,
        };
        match self {
            IOBuf::In(iobuf) => f(buf_part, &iobuf[iobuf_offset..], len),
            IOBuf::Out(iobuf) => f(&mut iobuf[iobuf_offset..], buf_part, len),
            IOBuf::Skip(_) => {},
        }
    }
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

    fn fold<const F: bool>(&mut self, mut iobuf: IOBuf<F>) {
        let mut iobuf_offset = 0;
        let mut iobuf_rest = iobuf.len();
        let mut len = R - self.offset;
        while iobuf_rest >= len {
            iobuf.exec(&mut self.buf[self.offset..], iobuf_offset, len);
            self.permute();
            iobuf_offset += len;
            iobuf_rest -= len;
            len = R;
        }
        iobuf.exec(&mut self.buf[self.offset..], iobuf_offset, iobuf_rest);
        self.offset += iobuf_rest;
    }

    fn pad(&mut self) {
        self.buf[self.offset] ^= self.delim;
        self.buf[R - 1] ^= 0x80;
    }

    fn permute(&mut self) {
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

    pub fn change_delim(self, delim: u8) -> Self {
        let KeccakState { buf, offset, mode, delim: _ } = self;
        KeccakState { buf, offset, mode, delim }
    }
}

// endregion

// region: traits

pub trait Absorb: Sized {
    fn absorb(&mut self, input: &[u8]);
    
    #[inline(always)]
    fn chain_absorb(mut self, input: &[u8]) -> Self {
        self.absorb(input);
        self
    }
}

pub trait FillBlock {
    fn fill_block(&mut self);
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

pub trait SqueezeXor {
    fn squeeze_xor(&mut self, output: &mut [u8]);
}

pub trait SqueezeSkip {
    fn squeeze_skip(&mut self, len: usize);

    // todo really need?
    #[inline(always)]
    fn squeeze_skip_const<const N: usize>(&mut self) {
        self.squeeze_skip(N)
    }
}

pub trait Reset {
    fn reset(&mut self);
}

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

impl<const P: bool, const R: usize> Absorb for KeccakState<P, R> {
    fn absorb(&mut self, input: &[u8]) {
        self.switch::<Absorbing>();
        self.fold::<XOR>(IOBuf::In(input));
    }
}

impl<const P: bool, const R: usize> FillBlock for KeccakState<P, R> {
    fn fill_block(&mut self) {
        self.permute();
    }
}

impl<const P: bool, const R: usize> Squeeze for KeccakState<P, R> {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.switch::<Squeezing>();
        self.fold::<COPY>(IOBuf::Out(output));
    }
}

impl<const P: bool, const R: usize> SqueezeXor for KeccakState<P, R> {
    fn squeeze_xor(&mut self, output: &mut [u8]) {
        self.switch::<Squeezing>();
        self.fold::<XOR>(IOBuf::Out(output));
    }
}

impl<const P: bool, const R: usize> SqueezeSkip for KeccakState<P, R> {
    fn squeeze_skip(&mut self, len: usize) {
        self.switch::<Squeezing>();
        self.fold::<NOP>(IOBuf::Skip(len));
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
