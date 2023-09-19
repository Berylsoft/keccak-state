#![no_std]

#[cfg(feature = "alloc")] extern crate alloc;
#[cfg(feature = "std")] extern crate std;
#[cfg(feature = "zeroize-on-drop")] use zeroize::Zeroize;
pub use keccak_state::{self, Absorb, AbsorbZero, Squeeze, SqueezeXor, SqueezeSkip, Reset};
#[cfg(feature = "seed")] pub use keccak_state::AbsorbSeed;
use keccak_state::{KeccakState, KeccakF, R256, DCSHAKE, DSHAKE, BYTES, BITS, Foldable, IOBuf, Switch};

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
        if !self.custom.is_empty() {
            self.ctx.absorb_len_left(R);
            self.ctx.absorb_len_left(self.custom.name().len() * 8);
            self.ctx.absorb(self.custom.name());
            self.ctx.absorb_len_left(self.custom.custom_string().len() * 8);
            self.ctx.absorb(self.custom.custom_string());
            self.ctx.fill_block();
        }
    }

    pub fn create_with_initial(custom: C, initial: [u8; BYTES(BITS)]) -> Self {
        CShake { ctx: KeccakState::with_initial(custom.delim(), initial), custom }
    }

    pub fn create(custom: C) -> CShake<C> {
        let mut _self = CShake { ctx: KeccakState::new(custom.delim()), custom };
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

impl<C: CShakeCustom> Foldable for CShake<C> {
    #[inline(always)]
    fn fold<B: IOBuf>(&mut self, iobuf: &mut B) {
        self.ctx.fold(iobuf)
    }

    #[inline(always)]
    fn fill_block(&mut self) {
        self.ctx.fill_block();
    }
}

impl<C: CShakeCustom> Switch for CShake<C> {
    #[inline(always)]
    fn switch<const M: bool>(&mut self) {
        self.ctx.switch::<M>()
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
    fn name(&self) -> &[u8] { &[] }
    fn custom_string(&self) -> &[u8];
    fn initial(&self) -> Option<&[u8; BYTES(BITS)]> { None }

    /* const */ fn is_empty(&self) -> bool {
        self.name().is_empty() && self.custom_string().is_empty()
    }

    /* const */ fn delim(&self) -> u8 {
        // if there is no name and no customization string
        // cSHAKE is SHAKE
        if self.is_empty() { DSHAKE } else { DCSHAKE }
    }

    #[inline]
    fn create(self) -> CShake<Self> {
        if let Some(initial) = self.initial() {
            let initial = *initial;
            CShake::create_with_initial(self, initial)
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
    fn custom_string(&self) -> &'static [u8] { &[] }
}

#[macro_export]
macro_rules! cshake_customs {
    ($prefix:literal $($name:ident)*) => {$(
        #[allow(non_camel_case_types)]
        pub struct $name;

        impl $crate::CShakeCustom for $name {
            fn custom_string(&self) -> &'static [u8] {
                concat!($prefix, stringify!($name)).as_bytes()
            }
        }
    )*};
    ($($name:ident -> $custom:literal)*) => {$(
        #[allow(non_camel_case_types)]
        pub struct $name;

        impl $crate::CShakeCustom for $name {
            fn custom_string(&self) -> &'static [u8] {
                $custom.as_bytes()
            }
        }
    )*};
}

#[cfg(feature = "alloc")]
mod owned_custom {
    use alloc::sync::Arc;
    use crate::{CShake, CShakeCustom, BYTES, BITS};

    #[derive(Clone)]
    pub struct OwnedCustom {
        name: Option<Arc<[u8]>>,
        custom_string: Option<Arc<[u8]>>,
        initial: Option<Arc<[u8; BYTES(BITS)]>>,
    }

    impl OwnedCustom {
        pub fn new(
            name: Option<&[u8]>,
            custom_string: Option<&[u8]>,
            initial: Option<&[u8; BYTES(BITS)]>,
        ) -> Self {
            OwnedCustom {
                name: name.map(From::from),
                custom_string: custom_string.map(From::from),
                initial: initial.map(Clone::clone).map(From::from),
            }
        }

        pub fn new_with_create_initial(
            name: Option<&[u8]>,
            custom_string: Option<&[u8]>,
        ) -> Self {
            let _self = OwnedCustom {
                name: name.map(From::from),
                custom_string: custom_string.map(From::from),
                initial: None,
            };
            let CShake { ctx, custom: mut _self } = _self.create();
            let initial = ctx.to_initial().unwrap();
            let _ = core::mem::replace(&mut _self.initial, Some(Arc::new(initial)));
            _self
        }
    }

    impl CShakeCustom for OwnedCustom {
        fn name(&self) -> &[u8] {
            self.name.as_deref().unwrap_or(&[])
        }

        fn custom_string(&self) -> &[u8] {
            self.custom_string.as_deref().unwrap_or(&[])
        }

        fn initial(&self) -> Option<&[u8; BYTES(BITS)]> {
            self.initial.as_deref()
        }
    }
}

#[cfg(feature = "alloc")]
pub use owned_custom::OwnedCustom;

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

    #[cfg(feature = "std")]
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

    #[cfg(feature = "std")]
    pub use thread::*;
}
