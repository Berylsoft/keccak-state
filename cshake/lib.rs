#![cfg_attr(not(feature = "alloc"), no_std)]

use foundations::xor;
use keccak_core::{KeccakState, KeccakF};

#[cfg(feature = "zeroize-on-drop")]
use zeroize::Zeroize;

pub struct CShake<C: CShakeCustom> {
    ctx: KeccakState<KeccakF>,
    custom: C,
}

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

impl<C: CShakeCustom> CShake<C> {
    #[inline]
    pub fn custom(&self) -> &C {
        &self.custom
    }

    #[inline]
    pub fn absorb(&mut self, input: &[u8]) {
        self.ctx.absorb(input);
    }

    #[inline]
    pub fn chain_absorb(mut self, input: &[u8]) -> CShake<C> {
        self.ctx.absorb(input);
        self
    }

    #[inline]
    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.ctx.squeeze(output);
    }

    #[inline]
    pub fn squeeze_to_array<const N: usize>(&mut self) -> [u8; N] {
        let mut buf = [0; N];
        self.ctx.squeeze(&mut buf);
        buf
    }

    #[cfg(feature = "alloc")]
    #[inline]
    pub fn squeeze_to_vec(&mut self, len: usize) -> Vec<u8> {
        // TODO use MaybeUninit
        let mut buf = vec![0; len];
        self.ctx.squeeze(&mut buf);
        buf
    }

    // TODO(below 3 methods): necessary to zeroize?
    // TODO(below 5 methods): inline?

    #[inline]
    pub fn skip<const N: usize>(&mut self) {
        #[allow(unused_variables)]
        let buf = self.squeeze_to_array::<N>();
        #[cfg(feature = "zeroize-on-drop")]
        buf.zeroize();
    }

    #[inline]
    pub fn squeeze_xor_array<const N: usize>(&mut self, dest: &mut [u8; N]) {
        #[allow(unused_mut)]
        let mut mask = self.squeeze_to_array();
        xor::xor_array(dest, &mask);
        #[cfg(feature = "zeroize-on-drop")]
        mask.zeroize();
    }

    #[cfg(feature = "alloc")]
    #[inline]
    pub fn squeeze_xor_slice(&mut self, dest: &mut [u8]) {
        #[allow(unused_mut)]
        let mut mask = self.squeeze_to_vec(dest.len());
        // hardcode inline without reslicing because no need to check
        xor::xor(dest, &mask);
        #[cfg(feature = "zeroize-on-drop")]
        mask.zeroize();
    }

    #[inline]
    pub fn once(mut self, input: &[u8], output: &mut [u8]) {
        self.ctx.absorb(input);
        self.ctx.squeeze(output);
    }

    #[inline]
    pub fn once_to_array<const N: usize>(mut self, input: &[u8]) -> [u8; N] {
        self.ctx.absorb(input);
        self.squeeze_to_array()
    }

    #[inline]
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
