#[cfg(feature = "seed")]
pub trait AbsorbSeedUnsafe: Absorb {
    fn absorb_seed_unsafe<const N: usize>(&mut self) {
        use core::mem::MaybeUninit;
        let mut buf: [MaybeUninit<u8>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        let ready_buf = getrandom::fill_uninit(&mut buf).unwrap();
        self.absorb(ready_buf);
        #[cfg(feature = "zeroize-on-drop")]
        buf.zeroize();
    }
}
