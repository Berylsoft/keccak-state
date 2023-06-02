#![cfg_attr(not(feature = "alloc"), no_std)]

pub use keccak_state;
use keccak_state::{KeccakState, KeccakF, R256, DCSHAKE, DSHAKE, BYTES, BITS};
#[cfg(feature = "zeroize-on-drop")]
use zeroize::Zeroize;

const P: bool = KeccakF;
const R: usize = R256;

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

pub trait Reset {
    fn reset(&mut self);
}

pub struct CShake<C: CShakeCustom> {
    ctx: KeccakState<P, R>,
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

impl<C: CShakeCustom> Reset for CShake<C> {
    fn reset(&mut self) {
        self.ctx.reset();
        self.init();
    }
}

impl<C: CShakeCustom> CShake<C> {
    pub fn squeeze_to_ctx<const N: usize, C2: CShakeCustom>(&mut self, custom: C2) -> CShake<C2> {
        #[allow(unused_mut)]
        let mut buf = self.squeeze_to_array::<N>();
        let ctx = custom.create().chain_absorb(&buf);
        #[cfg(feature = "zeroize-on-drop")]
        buf.zeroize();
        ctx
    }

    #[cfg(feature = "seed")]
    pub fn absorb_seed<const N: usize>(&mut self) {
        use core::mem::MaybeUninit;
        let mut buf: [MaybeUninit<u8>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        let ready_buf = getrandom::getrandom_uninit(&mut buf).unwrap();
        self.absorb(ready_buf);
    }
}

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
    use foldable::*;
    use keccak_state::{BITS, BYTES};
    use crate::{CShake, Squeeze, Reset, CShakeCustom};

    pub struct ReseedableRng<C: CShakeCustom, const R: usize, const L: usize> {
        ctx: CShake<C>,
        offset: usize,
    }

    impl<C: CShakeCustom, const R: usize, const L: usize> ReseedableRng<C, R, L> {
        pub fn init(custom: C) -> Self {
            let mut ctx = custom.create();
            ctx.absorb_seed::<L>();
            ReseedableRng { ctx, offset: 0 }
        }
    }

    impl<C: CShakeCustom, const R: usize, const L: usize> Permute for ReseedableRng<C, R, L> {
        fn permute(&mut self) {
            self.ctx.reset();
            self.ctx.absorb_seed::<L>();
        }
    }

    impl<C: CShakeCustom, const R: usize, const L: usize> Foldable<{BYTES(BITS)}, R> for ReseedableRng<C, R, L> {
        fn buf_mut(&mut self) -> &mut [u8; BYTES(BITS)] { self.ctx.ctx.buf_mut() }
    }

    impl<C: CShakeCustom, const R: usize, const L: usize> Squeeze for ReseedableRng<C, R, L> {
        fn squeeze(&mut self, output: &mut [u8]) {
            self.offset = IOBuf::Out(output, copy).fold(self, self.offset);
        }
    }

    impl<C: CShakeCustom, const R: usize, const L: usize> Reset for ReseedableRng<C, R, L> {
        fn reset(&mut self) {
            self.permute();
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
