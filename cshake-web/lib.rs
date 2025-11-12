use wasm_bindgen::prelude::wasm_bindgen;
use cshake::*;

#[wasm_bindgen]
pub struct Custom(OwnedCustom);

#[wasm_bindgen]
pub struct Context(CShake<OwnedCustom>);

#[wasm_bindgen]
impl Custom {
    pub fn shake() -> Custom {
        Custom(OwnedCustom::new(None, None, None))
    }

    pub fn new_from_bytes(name: Option<Box<[u8]>>, custom_string: Option<Box<[u8]>>) -> Custom {
        Custom(OwnedCustom::new(name.as_deref(), custom_string.as_deref(), None))
    }

    pub fn new(name: Option<String>, custom_string: Option<String>) -> Custom {
        Custom(OwnedCustom::new(name.as_ref().map(|s| s.as_bytes()), custom_string.as_ref().map(|s| s.as_bytes()), None))
    }

    pub fn create(self) -> Context {
        Context(self.0.create())
    }

    pub fn once_to_bytes(self, input: &[u8], len: u32) -> Vec<u8> {
        self.0.create().chain_absorb(input).squeeze_to_vec(len as usize)
    }
}

#[wasm_bindgen]
impl Context {
    pub fn custom(&self) -> Custom {
        Custom(self.0.custom().clone())
    }

    pub fn create(custom: Custom) -> Context {
        Context(custom.0.create())
    }

    pub fn absorb(&mut self, input: &[u8]) {
        self.0.absorb(input);
    }

    pub fn chain_absorb(self, input: &[u8]) -> Context {
        Context(self.0.chain_absorb(input))
    }

    pub fn absorb_zero(&mut self, len: u32) {
        self.0.absorb_zero(len as usize);
    }

    pub fn squeeze_to_bytes(&mut self, len: u32) -> Vec<u8> {
        self.0.squeeze_to_vec(len as usize)
    }

    pub fn squeeze_xor(&mut self, mut output: Box<[u8]>) -> Box<[u8]> {
        self.0.squeeze_xor(output.as_mut());
        output
    }

    pub fn squeeze_skip(&mut self, len: u32) {
        self.0.squeeze_skip(len as usize);
    }

    pub fn reset(&mut self) {
        self.0.reset();
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn it_works() {
        assert_eq!(
            Custom::shake().once_to_bytes("Hello, World!".as_bytes(), 32),
            hex_literal::hex!("b3be97bfd978833a65588ceae8a34cf59e95585af62063e6b89d0789f372424e"),
        );
        assert_eq!(
            Custom::new(Some("test".to_owned()), Some("test".to_owned())).once_to_bytes("Hello, World!".as_bytes(), 32),
            hex_literal::hex!("41922b47e8129c3750687c6afcad57ac39dee8a20785ccce324393c787b08552"),
        );
    }
}
