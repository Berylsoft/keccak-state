use keccak_core::{KeccakState, KeccakF};

fn cshake256_init(name: &[u8], custom_string: &[u8]) -> KeccakState<KeccakF> {
    use keccak_core::{bits_to_rate, DELIM_CSHAKE, DELIM_SHAKE};
    let rate = bits_to_rate(256);
    // if there is no name and no customization string
    // cSHAKE is SHAKE
    if name.is_empty() && custom_string.is_empty() {
        KeccakState::new(rate, DELIM_SHAKE)
    } else {
        let mut state = KeccakState::new(rate, DELIM_CSHAKE);
        state.absorb_len_left(rate);
        state.absorb_len_left(name.len() * 8);
        state.absorb(name);
        state.absorb_len_left(custom_string.len() * 8);
        state.absorb(custom_string);
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
        ctx.absorb(&ibuf);
        let mut obuf = [0; 4096];
        ctx.squeeze(&mut obuf);
        obuf
    };

    assert_eq!(a, b);
}
