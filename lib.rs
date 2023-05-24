#![no_std]

#[inline]
pub fn xor(dst: &mut [u8], src: &[u8]) {
    let len = dst.len();

    // Check *before* looping that both are long enough,
    // in a way that makes it directly obvious to LLVM
    // that the indexing below will be in-bounds.
    // ref: https://users.rust-lang.org/t/93119/10
    let (dst, src) = (&mut dst[..len], &src[..len]);

    for i in 0..len {
        dst[i] ^= src[i];
    }
}

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const WORDS: usize = 25;

#[cfg(feature = "keccak-f")]
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

#[cfg(feature = "keccak-p")]
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

pub trait Permutation {
    fn execute(a: &mut [u64; WORDS]);
}

macro_rules! keccak_impl {
    ($doc:expr, $name:ident, $struct_name:ident, $rc:expr) => {
        #[doc = $doc]
        pub fn $name(a: &mut [u64; WORDS]) {
            keccak::<{ $rc.len() }>(a, &$rc)
        }

        pub struct $struct_name;

        impl Permutation for $struct_name {
            fn execute(buffer: &mut [u64; WORDS]) {
                $name(buffer);
            }
        }
    }
}

#[cfg(feature = "keccak-f")]
keccak_impl!("`keccak-f[1600, 24]`", keccakf, KeccakF, KECCAK_F_RC);

#[cfg(feature = "keccak-p")]
keccak_impl!("`keccak-p[1600, 12]`", keccakp, KeccakP, KECCAK_P_RC);

#[derive(Clone, Copy)]
enum Mode {
    Absorbing,
    Squeezing,
}

pub struct KeccakState<P> {
    buffer: [u64; WORDS],
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

#[cfg(feature = "zeroize-on-drop")]
impl<P> Drop for KeccakState<P> {
    fn drop(&mut self) {
        self.buffer.zeroize();
        self.offset = 0;
    }
}

macro_rules! flodp {
    ($self:expr, $buf:expr, $bufl:expr, $exec:ident) => {{
        let mut p = 0;
        let mut l = $bufl;
        let mut rate = $self.rate - $self.offset;
        let mut offset = $self.offset;
        while l >= rate {
            $self.$exec($buf, p, offset, rate);
            $self.keccak();
            p += rate;
            l -= rate;
            rate = $self.rate;
            offset = 0;
        }
        $self.$exec($buf, p, offset, l);
        $self.offset = offset + l;
    }};
}

macro_rules! absorb_pre {
    ($self:expr) => {{
        if let Mode::Squeezing = $self.mode {
            $self.mode = Mode::Absorbing;
            $self.fill_block();
        }
    }};
}

macro_rules! squeeze_pre {
    ($self:expr) => {{
        if let Mode::Absorbing = $self.mode {
            $self.mode = Mode::Squeezing;
            $self.pad();
            $self.fill_block();
        }
    }};
}

impl<P: Permutation> KeccakState<P> {
    pub fn new(rate: usize, delim: u8) -> Self {
        assert!(rate != 0, "rate cannot be equal 0");
        KeccakState {
            buffer: Default::default(),
            offset: 0,
            rate,
            delim,
            mode: Mode::Absorbing,
            permutation: core::marker::PhantomData,
        }
    }

    #[inline(always)]
    fn words(&mut self) -> &mut [u64; WORDS] {
        &mut self.buffer
    }

    #[inline(always)]
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

    fn xorin(&mut self, src: &[u8], p: usize, offset: usize, len: usize) {
        self.execute(offset, len, |dst| xor(dst, &src[p..]));
    }

    fn setout(&mut self, dst: &mut [u8], p: usize, offset: usize, len: usize) {
        self.execute(offset, len, |buffer| dst[p..][..len].copy_from_slice(buffer));
    }

    fn xorout(&mut self, dst: &mut [u8], p: usize, offset: usize, len: usize) {
        self.execute(offset, len, |src| xor(&mut dst[p..][..len], src));
    }

    #[inline(always)]
    fn skipout(&mut self, _dst: &mut [u8], _p: usize, _offset: usize, _len: usize) {
    }

    fn pad(&mut self) {
        let delim = self.delim;
        self.execute(self.offset, 1, |buff| buff[0] ^= delim);
        self.execute(self.rate - 1, 1, |buff| buff[0] ^= 0x80);
    }

    fn keccak(&mut self) {
        P::execute(&mut self.words());
    }

    pub fn absorb(&mut self, input: &[u8]) {
        absorb_pre!(self);
        flodp!(self, input, input.len(), xorin)
    }

    pub fn squeeze(&mut self, output: &mut [u8]) {
        squeeze_pre!(self);
        flodp!(self, output, output.len(), setout)
    }

    pub fn squeeze_xor(&mut self, output: &mut [u8]) {
        squeeze_pre!(self);
        flodp!(self, output, output.len(), xorout)
    }

    pub fn squeeze_skip(&mut self, len: usize) {
        squeeze_pre!(self);
        flodp!(self, &mut [], len, skipout)
    }

    pub fn fill_block(&mut self) {
        self.keccak();
        self.offset = 0;
    }

    pub fn reset(&mut self) {
        #[cfg(feature = "zeroize-on-drop")]
        self.buffer.zeroize();
        #[cfg(not(feature = "zeroize-on-drop"))]
        let _ = core::mem::replace(&mut self.buffer, Default::default());
        self.offset = 0;
        self.mode = Mode::Absorbing;
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
}

pub const fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}

pub const DELIM_KECCAK : u8 = 0x01;
pub const DELIM_SHA3   : u8 = 0x06;
pub const DELIM_SHAKE  : u8 = 0x1f;
pub const DELIM_CSHAKE : u8 = 0x04;
