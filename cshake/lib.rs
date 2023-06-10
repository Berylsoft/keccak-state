#![cfg_attr(not(feature = "alloc"), no_std)]

pub use keccak_state::{self, Absorb, FillBlock, Squeeze, SqueezeXor, SqueezeSkip, Reset};
#[cfg(feature = "seed")]
pub use keccak_state::AbsorbSeed;
use keccak_state::{KeccakState, KeccakF, R256, DCSHAKE, DSHAKE, BYTES, BITS};
#[cfg(feature = "zeroize-on-drop")]
use zeroize::Zeroize;

// region: encode len

pub trait AbsorbLenLeft: Absorb {
    fn absorb_len_left(&mut self, len: usize) {
        if len == 0 {
            self.absorb(&[1, 0]);
        } else {
            let lz = len.leading_zeros() / 8;
            let len = len.to_be_bytes();
            self.absorb(&[(core::mem::size_of::<usize>() as u8) - (lz as u8)]);
            self.absorb(&len[lz as usize..]);
        }
    }
}

impl<T: Absorb> AbsorbLenLeft for T {}

#[cfg(feature = "right-encode")]
pub trait AbsorbLenRight: Absorb {
    fn absorb_len_right(&mut self, len: usize) {
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

#[cfg(feature = "right-encode")]
impl<T: Absorb> AbsorbLenRight for T {}

// endregion

// region: state

const R: usize = R256;

pub struct CShake<C: CShakeCustom> {
    ctx: KeccakState<KeccakF, R>,
    custom: C,
}

impl<C: CShakeCustom> CShake<C> {
    #[inline(always)]
    pub fn custom(&self) -> &C {
        &self.custom
    }

    fn init(&mut self) {
        if !C::is_empty() {
            self.ctx.absorb_len_left(R);
            self.ctx.absorb_len_left(C::NAME.len() * 8);
            self.ctx.absorb(C::NAME.as_bytes());
            self.ctx.absorb_len_left(C::CUSTOM_STRING.len() * 8);
            self.ctx.absorb(C::CUSTOM_STRING.as_bytes());
            self.ctx.fill_block();
        }
    }

    pub fn create_with_initial(custom: C, initial: [u8; BYTES(BITS)]) -> Self {
        CShake { ctx: KeccakState::with_initial(C::delim(), initial), custom }
    }

    pub fn create(custom: C) -> CShake<C> {
        let mut _self = CShake { ctx: KeccakState::new(C::delim()), custom };
        _self.init();
        _self
    }

    pub fn squeeze_to_ctx<const N: usize, C2: CShakeCustom>(&mut self, custom: C2) -> CShake<C2> {
        #[allow(unused_mut)]
        let mut buf = self.squeeze_to_array::<N>();
        let ctx = custom.create().chain_absorb(&buf);
        #[cfg(feature = "zeroize-on-drop")]
        buf.zeroize();
        ctx
    }
}

// endregion

// region: trait impls

impl<C: CShakeCustom> Absorb for CShake<C> {
    #[inline(always)]
    fn absorb(&mut self, input: &[u8]) {
        self.ctx.absorb(input);
    }
}

impl<C: CShakeCustom> FillBlock for CShake<C> {
    #[inline(always)]
    fn fill_block(&mut self) {
        self.ctx.fill_block();
    }
}

impl<C: CShakeCustom> Squeeze for CShake<C> {
    #[inline(always)]
    fn squeeze(&mut self, output: &mut [u8]) {
        self.ctx.squeeze(output);
    }
}

impl<C: CShakeCustom> SqueezeXor for CShake<C> {
    #[inline(always)]
    fn squeeze_xor(&mut self, output: &mut [u8]) {
        self.ctx.squeeze_xor(output);
    }
}

impl<C: CShakeCustom> SqueezeSkip for CShake<C> {
    #[inline(always)]
    fn squeeze_skip(&mut self, len: usize) {
        self.ctx.squeeze_skip(len)
    }
}

impl<C: CShakeCustom> Reset for CShake<C> {
    fn reset(&mut self) {
        self.ctx.reset();
        self.init();
    }
}

// endregion

// region: custom

pub trait CShakeCustom: Sized {
    const NAME: &'static str = "";
    const CUSTOM_STRING: &'static str;
    const INITIAL: Option<&'static [u8; BYTES(BITS)]> = None;

    /* const */ fn is_empty() -> bool {
        Self::NAME.is_empty() && Self::CUSTOM_STRING.is_empty()
    }

    /* const */ fn delim() -> u8 {
        // if there is no name and no customization string
        // cSHAKE is SHAKE
        if Self::is_empty() { DSHAKE } else { DCSHAKE }
    }

    #[inline]
    fn create(self) -> CShake<Self> {
        if let Some(initial) = Self::INITIAL {
            CShake::create_with_initial(self, *initial)
        } else {
            CShake::create(self)
        }
    }

    #[inline]
    fn once(self, input: &[u8], output: &mut [u8]) {
        self.create().chain_absorb(input).squeeze(output)
    }

    #[inline]
    fn once_to_array<const N: usize>(self, input: &[u8]) -> [u8; N] {
        self.create().chain_absorb(input).squeeze_to_array()
    }
}

pub struct NoCustom;

impl CShakeCustom for NoCustom {
    const CUSTOM_STRING: &'static str = "";
}

#[macro_export]
macro_rules! cshake_customs {
    ($prefix:literal $($name:ident)*) => {$(
        #[allow(non_camel_case_types)]
        pub struct $name;

        impl CShakeCustom for $name {
            const CUSTOM_STRING: &'static str = concat!($prefix, stringify!($name));
        }
    )*};
}

// endregion

#[cfg(feature = "rand")]
pub mod rand {
    use crate::{CShake, Squeeze, Reset, AbsorbSeed, CShakeCustom};

    pub struct ReseedableRng<C: CShakeCustom, const I: usize, const L: usize> {
        ctx: CShake<C>,
        offset: usize,
    }

    impl<C: CShakeCustom, const I: usize, const L: usize> ReseedableRng<C, I, L> {
        pub fn init(custom: C) -> Self {
            let mut ctx = custom.create();
            ctx.absorb_seed::<L>();
            ReseedableRng { ctx, offset: 0 }
        }
    }

    impl<C: CShakeCustom, const I: usize, const L: usize> Squeeze for ReseedableRng<C, I, L> {
        // from KeccakState::fold
        fn squeeze(&mut self, output: &mut [u8]) {
            let mut iobuf_offset = 0;
            let mut iobuf_rest = output.len();
            let mut len = I - self.offset;
            while iobuf_rest >= len {
                self.ctx.squeeze(&mut output[iobuf_offset..][..len]);
                self.reset();
                iobuf_offset += len;
                iobuf_rest -= len;
                len = I;
            }
            self.ctx.squeeze(&mut output[iobuf_offset..][..iobuf_rest]);
            self.offset += iobuf_rest;
        }
    }

    impl<C: CShakeCustom, const I: usize, const L: usize> Reset for ReseedableRng<C, I, L> {
        fn reset(&mut self) {
            self.ctx.reset();
            self.ctx.absorb_seed::<L>();
            self.offset = 0;
        }
    }

    pub const DEFAULT_RESEED_INTERVAL: usize = 1024 * 64;
    pub const DEFAULT_SEED_LEN: usize = 32;

    #[cfg(feature = "alloc")]
    mod thread {
        use std::{thread_local, rc::Rc, cell::UnsafeCell};
        use crate::{Squeeze, Reset, NoCustom};
        use super::{ReseedableRng, DEFAULT_RESEED_INTERVAL, DEFAULT_SEED_LEN};

        type ThreadRngState = ReseedableRng<NoCustom, DEFAULT_RESEED_INTERVAL, DEFAULT_SEED_LEN>;

        thread_local! {
            static THREAD_RNG: Rc<UnsafeCell<ThreadRngState>> = Rc::new(UnsafeCell::new(ReseedableRng::init(NoCustom)));
        }

        pub struct ThreadRng(Rc<UnsafeCell<ThreadRngState>>);

        pub fn thread_rng() -> ThreadRng {
            ThreadRng(THREAD_RNG.with(Clone::clone))
        }

        impl ThreadRng {
            // SAFETY: usage should be controlled to avoid aliasing mutable references
            #[inline(always)]
            unsafe fn get_mut(&self) -> &mut ThreadRngState {
                &mut *self.0.get()
            }
        }

        impl Squeeze for ThreadRng {
            #[inline(always)]
            fn squeeze(&mut self, output: &mut [u8]) {
                unsafe { self.get_mut() }.squeeze(output)
            }
        }

        impl Reset for ThreadRng {
            #[inline(always)]
            fn reset(&mut self) {
                unsafe { self.get_mut() }.reset()
            }
        }

        pub fn random_array<const N: usize>() -> [u8; N] {
            thread_rng().squeeze_to_array()
        }
    }

    #[cfg(feature = "alloc")]
    pub use thread::*;
}
