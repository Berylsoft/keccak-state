#![no_std]
#![allow(non_upper_case_globals, non_snake_case)]

const BITS: usize = 1600;

pub const fn WORDS(bits: usize) -> usize {
    bits / 64
}

pub const fn BYTES(bits: usize) -> usize {
    bits / 8
}

pub const KeccakF: bool = true;
pub const KeccakP: bool = false;

pub const fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}

pub const R128: usize = bits_to_rate(128);
pub const R224: usize = bits_to_rate(224);
pub const R256: usize = bits_to_rate(256);
pub const R384: usize = bits_to_rate(384);
pub const R512: usize = bits_to_rate(512);

pub const DKeccak : u8 = 0x01;
pub const DSHA3   : u8 = 0x06;
pub const DSHAKE  : u8 = 0x1f;
pub const DCSHAKE : u8 = 0x04;

#[cfg(feature = "zeroize-on-drop")]
use zeroize::Zeroize;

#[derive(Clone, Copy)]
enum Mode {
    Absorbing,
    Squeezing,
}
use Mode::*;

#[derive(Clone)]
pub struct KeccakState<const P: bool, const R: usize> {
    buf: [u8; BYTES(BITS)],
    offset: usize,
    delim: u8,
    mode: Mode,
}

#[cfg(feature = "zeroize-on-drop")]
impl<const P: bool, const R: usize> Drop for KeccakState<P, R> {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.offset = 0;
    }
}

impl<const P: bool, const R: usize> KeccakState<P, R> {
    pub fn init(delim: u8) -> Self {
        // TODO complie time
        assert!(R != 0, "rate cannot be equal 0");
        KeccakState {
            buf: [0; BYTES(BITS)],
            offset: 0,
            delim,
            mode: Absorbing,
        }
    }

    fn fold<F: FnMut(&mut [u8], usize, usize, usize)>(&mut self, iobuf_len: usize, mut f: F) {
        let mut iobuf_offset = 0;
        let mut iobuf_rest = iobuf_len;
        let mut current_len = R - self.offset;
        while iobuf_rest >= current_len {
            f(&mut self.buf, self.offset, iobuf_offset, current_len);
            self.keccak();
            self.offset = 0;
            iobuf_offset += current_len;
            iobuf_rest -= current_len;
            current_len = R;
        }
        f(&mut self.buf, self.offset, iobuf_offset, iobuf_rest);
        self.offset += iobuf_rest;
    }

    fn pad(&mut self) {
        self.buf[self.offset] ^= self.delim;
        self.buf[R - 1] ^= 0x80;
    }

    fn keccak(&mut self) {
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
    }

    pub fn fill_block(&mut self) {
        self.keccak();
        self.offset = 0;
    }

    fn switch_to_absorb(&mut self) {
        if let Squeezing = self.mode {
            self.mode = Absorbing;
            self.fill_block();
        }
    }

    fn switch_to_squeeze(&mut self) {
        if let Absorbing = self.mode {
            self.mode = Squeezing;
            self.pad();
            self.fill_block();
        }
    }

    pub fn absorb(&mut self, input: &[u8]) {
        self.switch_to_absorb();
        self.fold(input.len(), |buf, buf_offset, iobuf_offset, len| {
            let dst = &mut buf[buf_offset..][..len];
            let src = &input[iobuf_offset..][..len];
            for i in 0..len {
                dst[i] ^= src[i];
            }
        });
    }

    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.switch_to_squeeze();
        self.fold(output.len(), |buf, buf_offset, iobuf_offset, len| {
            let dst = &mut output[iobuf_offset..][..len];
            let src = &buf[buf_offset..][..len];
            dst.copy_from_slice(src)
        });
    }

    pub fn squeeze_xor(&mut self, output: &mut [u8]) {
        self.switch_to_squeeze();
        self.fold(output.len(), |buf, buf_offset, iobuf_offset, len| {
            let dst = &mut output[iobuf_offset..][..len];
            let src = &buf[buf_offset..][..len];
            for i in 0..len {
                dst[i] ^= src[i];
            }
        });
    }

    pub fn squeeze_skip(&mut self, len: usize) {
        self.switch_to_squeeze();
        self.fold(len, |_buf, _buf_offset, _iobuf_offset, _len| {
            // do nothing
        });
    }

    pub fn reset(&mut self) {
        #[cfg(feature = "zeroize-on-drop")]
        self.buf.zeroize();
        #[cfg(not(feature = "zeroize-on-drop"))]
        let _ = core::mem::replace(&mut self.buffer, [0; BYTES(BITS)]);
        self.offset = 0;
        self.mode = Absorbing;
    }

    #[cfg(feature = "left-encode")]
    pub fn absorb_len_left(&mut self, len: usize) {
        if len == 0 {
            self.absorb(&[1, 0]);
        } else {
            let lz = len.leading_zeros() / 8;
            let len = len.to_be_bytes();
            self.absorb(&[(core::mem::size_of::<usize>() as u8) - (lz as u8)]);
            self.absorb(&len[lz as usize..]);
        }
    }

    #[cfg(feature = "right-encode")]
    pub fn absorb_len_right(&mut self, len: usize) {
        if len == 0 {
            self.absorb(&[0, 1]);
        } else {
            let lz = len.leading_zeros() / 8;
            let len = len.to_be_bytes();
            self.absorb(&len[lz as usize..]);
            self.absorb(&[(core::mem::size_of::<usize>() as u8) - (lz as u8)]);
        }
    }

    pub fn change_delim(self, delim: u8) -> Self {
        let KeccakState { buf, offset, mode, delim: _ } = self;
        KeccakState { buf, offset, mode, delim }
    }
}
