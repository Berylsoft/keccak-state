use tiny_keccak_core::{KeccakState, keccakf::KeccakF};

fn cshake256_init(name: &[u8], custom_string: &[u8]) -> KeccakState<KeccakF> {
    use tiny_keccak_core::{bits_to_rate, left_encode};
    let rate = bits_to_rate(256);
    // if there is no name and no customization string
    // cSHAKE is SHAKE
    if name.is_empty() && custom_string.is_empty() {
        KeccakState::new(rate, 0x1f)
    } else {
        let mut state = KeccakState::new(rate, 0x04);
        state.update(left_encode(rate).value());
        state.update(left_encode(name.len() * 8).value());
        state.update(name);
        state.update(left_encode(custom_string.len() * 8).value());
        state.update(custom_string);
        state.fill_block();
        state
    }
}

fn main() {
    let mut ibuf = [0; 4096];
    getrandom::getrandom(&mut ibuf).unwrap();

    let a = {
        use tiny_keccak::{CShake, Hasher, Xof};
        let mut ctx = CShake::v256(b"name", b"custom_string");
        ctx.update(&ibuf);
        let mut obuf = [0; 4096];
        ctx.squeeze(&mut obuf);
        obuf
    };

    let b = {
        let mut ctx = cshake256_init(b"name", b"custom_string");
        ctx.update(&ibuf);
        let mut obuf = [0; 4096];
        ctx.squeeze(&mut obuf);
        obuf
    };

    assert_eq!(a, b);
}
