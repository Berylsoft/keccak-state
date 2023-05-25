#![cfg_attr(not(feature = "alloc"), no_std)]

use keccak_state::{KeccakState, KeccakF, R256, DCSHAKE, DSHAKE};
#[cfg(feature = "zeroize-on-drop")]
use zeroize::Zeroize;

fn init(name: &[u8], custom_string: &[u8]) -> KeccakState<KeccakF, R256> {
    // if there is no name and no customization string
    // cSHAKE is SHAKE
    if name.is_empty() && custom_string.is_empty() {
        KeccakState::init(DSHAKE)
    } else {
        let mut ctx = KeccakState::init(DCSHAKE);
        ctx.absorb_len_left(R256);
        ctx.absorb_len_left(name.len() * 8);
        ctx.absorb(name);
        ctx.absorb_len_left(custom_string.len() * 8);
        ctx.absorb(custom_string);
        ctx.fill_block();
        ctx
    }
}

pub trait Absorb: Sized {
    fn absorb(&mut self, input: &[u8]);
    
    #[inline(always)]
    fn chain_absorb(mut self, input: &[u8]) -> Self {
        self.absorb(input);
        self
    }
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
    fn squeeze_to_vec(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        self.squeeze(&mut buf);
        buf
    }
}

pub trait SqueezeXor {
    fn squeeze_xor(&mut self, output: &mut [u8]);
}

pub trait SqueezeSkip {
    fn skip(&mut self, len: usize);

    #[inline(always)]
    fn skip_const<const N: usize>(&mut self) {
        self.skip(N)
    }
}

pub trait Once: Absorb + Squeeze {
    #[inline]
    fn once(mut self, input: &[u8], output: &mut [u8]) {
        self.absorb(input);
        self.squeeze(output);
    }

    #[inline]
    fn once_to_array<const N: usize>(mut self, input: &[u8]) -> [u8; N] {
        self.absorb(input);
        self.squeeze_to_array()
    }
}

impl<T: Absorb + Squeeze> Once for T {}
pub struct CShake<C: CShakeCustom> {
    ctx: KeccakState<KeccakF, R256>,
    custom: C,
}

impl<C: CShakeCustom> Absorb for CShake<C> {
    #[inline(always)]
    fn absorb(&mut self, input: &[u8]) {
        self.ctx.absorb(input);
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
    fn skip(&mut self, len: usize) {
        self.ctx.squeeze_skip(len)
    }
}

impl<C: CShakeCustom> CShake<C> {
    #[inline(always)]
    pub fn custom(&self) -> &C {
        &self.custom
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

pub trait CShakeCustom: Sized {
    const CUSTOM_STRING: &'static str;

    #[inline]
    fn create(self) -> CShake<Self> {
        CShake {
            ctx: init(&[], Self::CUSTOM_STRING.as_bytes()),
            custom: self,
        }
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

#[cfg(feature = "rand")]
pub mod rand {
    use std::{thread_local, rc::Rc, cell::UnsafeCell, mem::MaybeUninit};
    use crate::{CShake, Absorb, Squeeze, CShakeCustom, NoCustom};

    #[must_use]
    #[inline(always)]
    pub const fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
        // SAFETY: An uninitialized `[MaybeUninit<_>; LEN]` is valid.
        unsafe { MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init() }
    }

    fn init() -> CShake<NoCustom> {
        let mut buf = uninit_array::<u8, 32>();
        let ready_buf = getrandom::getrandom_uninit(&mut buf).unwrap();
        let ctx = NoCustom.create().chain_absorb(&ready_buf);
        ctx
    }

    thread_local! {
        static THREAD_RNG: Rc<UnsafeCell<CShake<NoCustom>>> = Rc::new(UnsafeCell::new(init()));
    }

    pub struct ThreadRng(Rc<UnsafeCell<CShake<NoCustom>>>);

    pub fn thread_rng() -> ThreadRng {
        ThreadRng(THREAD_RNG.with(Clone::clone))
    }

    impl Squeeze for ThreadRng {
        #[inline(always)]
        fn squeeze(&mut self, output: &mut [u8]) {
            let ctx = unsafe { &mut *self.0.get() };
            ctx.squeeze(output);
        }
    }

    pub fn random_array<const N: usize>() -> [u8; N] {
        thread_rng().squeeze_to_array()
    }
}
