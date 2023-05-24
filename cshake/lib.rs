#![cfg_attr(not(feature = "alloc"), no_std)]

use keccak_core::{KeccakState, KeccakF};
#[cfg(feature = "zeroize-on-drop")]
use zeroize::Zeroize;

fn init(name: &[u8], custom_string: &[u8]) -> KeccakState<KeccakF> {
    use keccak_core::{bits_to_rate, DELIM_CSHAKE, DELIM_SHAKE};
    let rate = bits_to_rate(256);
    // if there is no name and no customization string
    // cSHAKE is SHAKE
    if name.is_empty() && custom_string.is_empty() {
        KeccakState::new(rate, DELIM_SHAKE)
    } else {
        let mut ctx = KeccakState::new(rate, DELIM_CSHAKE);
        ctx.absorb_len_left(rate);
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
        // TODO use MaybeUninit
        let mut buf = vec![0; len];
        self.squeeze(&mut buf);
        buf
    }

    // TODO: necessary to zeroize?

    fn skip_const<const N: usize>(&mut self) {
        #[allow(unused_variables, unused_mut)]
        let mut buf = self.squeeze_to_array::<N>();
        #[cfg(feature = "zeroize-on-drop")]
        buf.zeroize();
    }

    #[cfg(feature = "alloc")]
    fn skip(&mut self, len: usize) {
        #[allow(unused_variables, unused_mut)]
        let mut buf = self.squeeze_to_vec(len);
        #[cfg(feature = "zeroize-on-drop")]
        buf.zeroize();
    }

    fn squeeze_xor_array<const N: usize>(&mut self, dest: &mut [u8; N]) {
        #[allow(unused_mut)]
        let mut mask = self.squeeze_to_array::<N>();
        for i in 0..N {
            dest[i] ^= mask[i];
        }
        #[cfg(feature = "zeroize-on-drop")]
        mask.zeroize();
    }

    #[cfg(feature = "alloc")]
    fn squeeze_xor_slice(&mut self, dest: &mut [u8]) {
        let len = dest.len();
        #[allow(unused_mut)]
        let mut mask = self.squeeze_to_vec(len);
        for i in 0..len {
            dest[i] ^= mask[i];
        }
        #[cfg(feature = "zeroize-on-drop")]
        mask.zeroize();
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
    ctx: KeccakState<KeccakF>,
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
    use std::{thread_local, rc::Rc, cell::UnsafeCell};
    use crate::{CShake, Absorb, Squeeze, CShakeCustom, NoCustom};

    fn init() -> CShake<NoCustom> {
        let mut buf = [0; 32];
        getrandom::getrandom(&mut buf).unwrap();
        let ctx = NoCustom.create().chain_absorb(&buf);
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
}
