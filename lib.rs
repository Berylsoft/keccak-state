#![no_std]

use crunchy::unroll;

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const WORDS: usize = 25;

macro_rules! keccak_impl {
    ($doc:expr, $name:ident, $struct_name:ident, $rounds:expr, $rc:expr) => {
        #[doc = $doc]
        #[allow(unused_assignments)]
        #[allow(non_upper_case_globals)]
        pub fn $name(a: &mut [u64; WORDS]) {
            const ROUNDS: usize = $rounds;
            const RC: [u64; ROUNDS] = $rc;

            for i in 0..ROUNDS {
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
            }
        }

        pub struct $struct_name;

        impl Permutation for $struct_name {
            fn execute(buffer: &mut Buffer) {
                $name(buffer.words());
            }
        }
    }
}

pub struct EncodedLen {
    offset: usize,
    buffer: [u8; 9],
}

impl EncodedLen {
    pub fn value(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }
}

pub fn left_encode(len: usize) -> EncodedLen {
    let mut buffer = [0u8; 9];
    buffer[1..].copy_from_slice(&(len as u64).to_be_bytes());
    let offset = buffer.iter().position(|i| *i != 0).unwrap_or(8);
    buffer[offset - 1] = 9 - offset as u8;

    EncodedLen {
        offset: offset - 1,
        buffer,
    }
}

pub fn right_encode(len: usize) -> EncodedLen {
    let mut buffer = [0u8; 9];
    buffer[..8].copy_from_slice(&(len as u64).to_be_bytes());
    let offset = buffer.iter().position(|i| *i != 0).unwrap_or(7);
    buffer[8] = 8 - offset as u8;
    EncodedLen { offset, buffer }
}

#[derive(Default, Clone)]
pub struct Buffer([u64; WORDS]);

impl Buffer {
    #[inline]
    fn words(&mut self) -> &mut [u64; WORDS] {
        &mut self.0
    }

    #[inline]
    fn bytes(&mut self) -> &mut [u8; WORDS * 8] {
        unsafe { core::mem::transmute(self.words()) }
    }

    #[cfg(target_endian = "little")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        f(&mut self.bytes()[offset..][..len]);
    }

    #[cfg(target_endian = "big")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        fn swap_endianess(buffer: &mut [u64]) {
            for item in buffer {
                *item = item.swap_bytes();
            }
        }

        let start = offset / 8;
        let end = (offset + len + 7) / 8;
        swap_endianess(&mut self.0[start..end]);
        f(&mut self.bytes()[offset..][..len]);
        swap_endianess(&mut self.0[start..end]);
    }

    fn setout(&mut self, dst: &mut [u8], offset: usize, len: usize) {
        self.execute(offset, len, |buffer| dst[..len].copy_from_slice(buffer));
    }

    fn xorin(&mut self, src: &[u8], offset: usize, len: usize) {
        self.execute(offset, len, |dst| {
            assert!(dst.len() <= src.len());
            for i in 0..dst.len() {
                dst[i] ^= src[i];
            }
        });
    }

    fn pad(&mut self, offset: usize, delim: u8, rate: usize) {
        self.execute(offset, 1, |buff| buff[0] ^= delim);
        self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);
    }
}

#[cfg(feature = "zeroize-on-drop")]
impl Drop for Buffer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize()
    }
}

pub trait Permutation {
    fn execute(a: &mut Buffer);
}

keccak_impl!("`keccak-f[1600, 24]`", keccakf, KeccakF, 24, [
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
]);

keccak_impl!("`keccak-p[1600, 12]`", keccakp, KeccakP, 12, [
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]);

#[derive(Clone, Copy)]
enum Mode {
    Absorbing,
    Squeezing,
}

pub struct KeccakState<P> {
    buffer: Buffer,
    offset: usize,
    rate: usize,
    delim: u8,
    mode: Mode,
    permutation: core::marker::PhantomData<P>,
}

impl<P> Clone for KeccakState<P> {
    fn clone(&self) -> Self {
        KeccakState {
            buffer: self.buffer.clone(),
            offset: self.offset,
            rate: self.rate,
            delim: self.delim,
            mode: self.mode,
            permutation: core::marker::PhantomData,
        }
    }
}

impl<P: Permutation> KeccakState<P> {
    pub fn new(rate: usize, delim: u8) -> Self {
        assert!(rate != 0, "rate cannot be equal 0");
        KeccakState {
            buffer: Buffer::default(),
            offset: 0,
            rate,
            delim,
            mode: Mode::Absorbing,
            permutation: core::marker::PhantomData,
        }
    }

    fn keccak(&mut self) {
        P::execute(&mut self.buffer);
    }

    pub fn absorb(&mut self, input: &[u8]) {
        if let Mode::Squeezing = self.mode {
            self.mode = Mode::Absorbing;
            self.fill_block();
        }

        // first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.xorin(&input[ip..], offset, rate);
            self.keccak();
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.xorin(&input[ip..], offset, l);
        self.offset = offset + l;
    }

    fn pad(&mut self) {
        self.buffer.pad(self.offset, self.delim, self.rate);
    }

    pub fn squeeze(&mut self, output: &mut [u8]) {
        if let Mode::Absorbing = self.mode {
            self.mode = Mode::Squeezing;
            self.pad();
            self.fill_block();
        }

        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.setout(&mut output[op..], offset, rate);
            self.keccak();
            op += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.setout(&mut output[op..], offset, l);
        self.offset = offset + l;
    }

    pub fn fill_block(&mut self) {
        self.keccak();
        self.offset = 0;
    }

    pub fn reset(&mut self) {
        #[cfg(feature = "zeroize-on-drop")]
        {
            use zeroize::Zeroize;
            self.buffer.0.zeroize();
        }
        #[cfg(not(feature = "zeroize-on-drop"))]
        {
            self.buffer = Buffer::default();
        }
        self.offset = 0;
        self.mode = Mode::Absorbing;
    }
}

pub const fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}

pub const DELIM_KECCAK : u8 = 0x01;
pub const DELIM_SHA3   : u8 = 0x06;
pub const DELIM_SHAKE  : u8 = 0x1f;
pub const DELIM_CSHAKE : u8 = 0x04;

#[cfg(test)]
mod tests {
    use crate::{left_encode, right_encode};

    #[test]
    fn test_left_encode() {
        assert_eq!(left_encode(0).value(), &[1, 0]);
        assert_eq!(left_encode(128).value(), &[1, 128]);
        assert_eq!(left_encode(65536).value(), &[3, 1, 0, 0]);
        assert_eq!(left_encode(4096).value(), &[2, 16, 0]);
        assert_eq!(left_encode(54321).value(), &[2, 212, 49]);
    }

    #[test]
    fn test_right_encode() {
        assert_eq!(right_encode(0).value(), &[0, 1]);
        assert_eq!(right_encode(128).value(), &[128, 1]);
        assert_eq!(right_encode(65536).value(), &[1, 0, 0, 3]);
        assert_eq!(right_encode(4096).value(), &[16, 0, 2]);
        assert_eq!(right_encode(54321).value(), &[212, 49, 2]);
    }
}
