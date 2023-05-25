#![no_std]
#![allow(non_upper_case_globals)]

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const WORDS: usize = BITS / 64;
const BYTES: usize = BITS / 8;
const BITS: usize = 1600;

const KECCAK_F_RC: [u64; 24] = [
    1,
    0x8082,
    0x800000000000808a,
    0x8000000080008000,
    0x808b,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8a,
    0x88,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];

const KECCAK_P_RC: [u64; 12] = [
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];

#[cfg(feature = "zeroize-on-drop")]
use zeroize::Zeroize;

#[allow(unused_assignments, non_snake_case)]
#[inline(always)]
pub fn keccak<const ROUNDS: usize>(a: &mut [u64; WORDS], RC: &[u64; ROUNDS]) {
    for i in 0..ROUNDS {
        use crunchy::unroll;

        let mut array: [u64; 5] = [0; 5];

        // Theta
        unroll! {
            for x in 0..5 {
                unroll! {
                    for y_count in 0..5 {
                        let y = y_count * 5;
                        array[x] ^= a[x + y];
                    }
                }
            }
        }

        unroll! {
            for x in 0..5 {
                unroll! {
                    for y_count in 0..5 {
                        let y = y_count * 5;
                        a[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                    }
                }
            }
        }

        // Rho and pi
        let mut last = a[1];
        unroll! {
            for x in 0..24 {
                array[0] = a[PI[x]];
                a[PI[x]] = last.rotate_left(RHO[x]);
                last = array[0];
            }
        }

        // Chi
        unroll! {
            for y_step in 0..5 {
                let y = y_step * 5;

                unroll! {
                    for x in 0..5 {
                        array[x] = a[y + x];
                    }
                }

                unroll! {
                    for x in 0..5 {
                        a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                    }
                }
            }
        };

        // Iota
        a[0] ^= RC[i];

        #[cfg(feature = "zeroize-on-drop")]
        array.zeroize()    
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Absorbing,
    Squeezing,
}
use Mode::*;

pub struct KeccakState<const P: bool, const R: usize> {
    buf: [u8; BYTES],
    offset: usize,
    delim: u8,
    mode: Mode,
}

impl<const P: bool, const R: usize> Clone for KeccakState<P, R> {
    fn clone(&self) -> Self {
        KeccakState {
            buf: self.buf.clone(),
            offset: self.offset,
            delim: self.delim,
            mode: self.mode,
        }
    }
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
            buf: [0; BYTES],
            offset: 0,
            delim,
            mode: Absorbing,
        }
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

    fn flodp<F: FnMut(&mut [u8], usize, usize, usize)>(&mut self, iobuf_len: usize, mut f: F) {
        let mut iobuf_offset = 0;
        let mut iobuf_rest = iobuf_len;
        let mut current_len = R - self.offset;
        let mut buf_offset = self.offset;
        while iobuf_rest >= current_len {
            f(&mut self.buf, buf_offset, iobuf_offset, current_len);
            self.keccak();
            iobuf_offset += current_len;
            iobuf_rest -= current_len;
            current_len = R;
            buf_offset = 0;
        }
        f(&mut self.buf, buf_offset, iobuf_offset, iobuf_rest);
        self.offset = buf_offset + iobuf_rest;
    }

    fn pad(&mut self) {
        self.buf[self.offset] ^= self.delim;
        self.buf[R - 1] ^= 0x80;
    }

    fn keccak(&mut self) {
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
        if P == KeccakF {
            keccak::<{ KECCAK_F_RC.len() }>(words, &KECCAK_F_RC);
        } else {
            keccak::<{ KECCAK_P_RC.len() }>(words, &KECCAK_P_RC);
        }
        #[cfg(target_endian = "big")]
        swap_endianess(words);
    }

    pub fn absorb(&mut self, input: &[u8]) {
        self.switch_to_absorb();
        self.flodp(input.len(), |buf: &mut [u8], buf_offset: usize, iobuf_offset: usize, len: usize| {
            let dst = &mut buf[buf_offset..][..len];
            let src = &input[iobuf_offset..][..len];
            for i in 0..len {
                dst[i] ^= src[i];
            }
        });
    }

    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.switch_to_squeeze();
        self.flodp(output.len(), |buf: &mut [u8], buf_offset: usize, iobuf_offset: usize, len: usize| {
            let dst = &mut output[iobuf_offset..][..len];
            let src = &buf[buf_offset..][..len];
            dst.copy_from_slice(src)
        });
    }

    pub fn squeeze_xor(&mut self, output: &mut [u8]) {
        self.switch_to_squeeze();
        self.flodp(output.len(), |buf: &mut [u8], buf_offset: usize, iobuf_offset: usize, len: usize| {
            let dst = &mut output[iobuf_offset..][..len];
            let src = &buf[buf_offset..][..len];
            for i in 0..len {
                dst[i] ^= src[i];
            }
        });
    }

    pub fn squeeze_skip(&mut self, len: usize) {
        self.switch_to_squeeze();
        self.flodp(len, |_buf: &mut [u8], _buf_offset: usize, _iobuf_offset: usize, _len: usize| {
            // do nothing
        });
    }

    pub fn fill_block(&mut self) {
        self.keccak();
        self.offset = 0;
    }

    pub fn reset(&mut self) {
        #[cfg(feature = "zeroize-on-drop")]
        self.buf.zeroize();
        #[cfg(not(feature = "zeroize-on-drop"))]
        let _ = core::mem::replace(&mut self.buffer, [0; BYTES]);
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

pub const fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}

pub const DKeccak : u8 = 0x01;
pub const DSHA3   : u8 = 0x06;
pub const DSHAKE  : u8 = 0x1f;
pub const DCSHAKE : u8 = 0x04;

pub const KeccakF: bool = true;
pub const KeccakP: bool = false;

pub const R128: usize = bits_to_rate(128);
pub const R224: usize = bits_to_rate(224);
pub const R256: usize = bits_to_rate(256);
pub const R384: usize = bits_to_rate(384);
pub const R512: usize = bits_to_rate(512);
