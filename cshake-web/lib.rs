use cshake::{CShakeCustom, OwnedCustom, Absorb, Squeeze};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn shake256_once(data: &[u8], len: u32) -> Vec<u8> {
    OwnedCustom::new(None, None, None)
        .create()
        .chain_absorb(data)
        .squeeze_to_vec(len as usize)
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn it_works() {
        assert_eq!(
            shake256_once("Hello, World!".as_bytes(), 32),
            hex_literal::hex!("b3be97bfd978833a65588ceae8a34cf59e95585af62063e6b89d0789f372424e"),
        )
    }
}
