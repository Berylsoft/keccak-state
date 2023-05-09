#![no_std]

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const WORDS: usize = 25;

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
        {
            use zeroize::Zeroize;
            array.zeroize()    
        }
    }
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
            let len = dst.len();

            // Check *before* looping that both are long enough,
            // in a way that makes it directly obvious to LLVM
            // that the indexing below will be in-bounds.
            // ref: https://users.rust-lang.org/t/93119/10
            let (dst, src) = (&mut dst[..len], &src[..len]);
        
            for i in 0..len {
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

macro_rules! keccak_impl {
    ($doc:expr, $name:ident, $struct_name:ident, $rc:expr) => {
        #[doc = $doc]
        pub fn $name(a: &mut [u64; WORDS]) {
            keccak::<{ $rc.len() }>(a, &$rc)
        }

        pub struct $struct_name;

        impl Permutation for $struct_name {
            fn execute(buffer: &mut Buffer) {
                $name(buffer.words());
            }
        }
    }
}

keccak_impl!("`keccak-f[1600, 24]`", keccakf, KeccakF, KECCAK_F_RC);

keccak_impl!("`keccak-p[1600, 12]`", keccakp, KeccakP, KECCAK_P_RC);

#[derive(Clone, Copy)]
enum Mode {
    Absorbing,
    Squeezing,
}

pub struct KeccakState<P> {
    buffer: Buffer,
    offset: usize,
    rate: usize,
    pub delim: u8,
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

    pub fn absorb_len_left(&mut self, len: usize) {
        let lz = len.leading_zeros() / 8;
        let len = len.to_be_bytes();
        self.absorb(&[(core::mem::size_of::<usize>() as u8) - (lz as u8)]);
        self.absorb(&len[lz as usize..]);
    }

    pub fn absorb_len_right(&mut self, len: usize) {
        let lz = len.leading_zeros() / 8;
        let len = len.to_be_bytes();
        self.absorb(&len[lz as usize..]);
        self.absorb(&[(core::mem::size_of::<usize>() as u8) - (lz as u8)]);
    }
}

pub const fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}

pub const DELIM_KECCAK : u8 = 0x01;
pub const DELIM_SHA3   : u8 = 0x06;
pub const DELIM_SHAKE  : u8 = 0x1f;
pub const DELIM_CSHAKE : u8 = 0x04;
