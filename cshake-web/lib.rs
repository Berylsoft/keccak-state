use cshake::{CShakeCustom, NoCustom, Absorb, Squeeze};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn shake256_once(data: &[u8], len: u32) -> Vec<u8> {
    NoCustom
        .create()
        .chain_absorb(data)
        .squeeze_to_vec(len as usize)
}
