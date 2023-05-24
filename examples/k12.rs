use keccak_core::{bits_to_rate, KeccakState};

struct EncodedLen {
    offset: usize,
    buffer: [u8; 9],
}

impl EncodedLen {
    fn value(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }
}

fn encode_len(len: usize) -> EncodedLen {
    let len_view = (len as u64).to_be_bytes();
    let offset = len_view.iter().position(|i| *i != 0).unwrap_or(8);
    let mut buffer = [0u8; 9];
    buffer[..8].copy_from_slice(&len_view);
    buffer[8] = 8 - offset as u8;

    EncodedLen { offset, buffer }
}

#[derive(Clone)]
pub struct KangarooTwelve<T> {
    state: KeccakState<false>,
    current_chunk: KeccakState<false>,
    custom_string: Option<T>,
    written: usize,
    chunks: usize,
}

impl<T> KangarooTwelve<T> {
    const MAX_CHUNK_SIZE: usize = 8192;

    pub fn new(custom_string: T) -> Self {
        let rate = bits_to_rate(128);
        KangarooTwelve {
            state: KeccakState::new(rate, 0),
            current_chunk: KeccakState::new(rate, 0x0b),
            custom_string: Some(custom_string),
            written: 0,
            chunks: 0,
        }
    }
}

impl<T: AsRef<[u8]>> KangarooTwelve<T> {
    fn update(&mut self, input: &[u8]) {
        let mut to_absorb = input;
        if self.chunks == 0 {
            let todo = core::cmp::min(Self::MAX_CHUNK_SIZE - self.written, to_absorb.len());
            self.state.absorb(&to_absorb[..todo]);
            self.written += todo;
            to_absorb = &to_absorb[todo..];

            if to_absorb.len() > 0 && self.written == Self::MAX_CHUNK_SIZE {
                self.state.absorb(&[0x03, 0, 0, 0, 0, 0, 0, 0]);
                self.written = 0;
                self.chunks += 1;
            }
        }

        while to_absorb.len() > 0 {
            if self.written == Self::MAX_CHUNK_SIZE {
                let mut chunk_hash = [0u8; 32];
                let mut current_chunk = self.current_chunk.clone();
                self.current_chunk.reset();
                current_chunk.squeeze(&mut chunk_hash);
                self.state.absorb(&chunk_hash);
                self.written = 0;
                self.chunks += 1;
            }

            let todo = core::cmp::min(Self::MAX_CHUNK_SIZE - self.written, to_absorb.len());
            self.current_chunk.absorb(&to_absorb[..todo]);
            self.written += todo;
            to_absorb = &to_absorb[todo..];
        }
    }

    fn finalize(self, output: &mut [u8]) {
        let mut xof = self.into_xof();
        xof.squeeze(output);
    }
}

#[derive(Clone)]
pub struct KangarooTwelveXof {
    state: KeccakState<false>,
}

impl<T: AsRef<[u8]>> KangarooTwelve<T> {
    fn into_xof(mut self) -> KangarooTwelveXof {
        let custom_string = self
            .custom_string
            .take()
            .expect("KangarooTwelve cannot be initialized without custom_string; qed");
        let encoded_len = encode_len(custom_string.as_ref().len());
        self.update(custom_string.as_ref());
        self.update(encoded_len.value());

        if self.chunks == 0 {
            self.state.delim = 0x07;
        } else {
            let encoded_chunks = encode_len(self.chunks);
            let mut tmp_chunk = [0u8; 32];
            self.current_chunk.squeeze(&mut tmp_chunk);
            self.state.absorb(&tmp_chunk);
            self.state.absorb(encoded_chunks.value());
            self.state.absorb(&[0xff, 0xff]);
            self.state.delim = 0x06;
        }

        KangarooTwelveXof { state: self.state }
    }
}

impl KangarooTwelveXof {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.state.squeeze(output);
    }
}

fn main() {
    let mut ibuf = [0; 4096];
    getrandom::getrandom(&mut ibuf).unwrap();

    let a = {
        use tiny_keccak::{KangarooTwelve, Hasher};
        let mut ctx = KangarooTwelve::new(b"custom_string");
        ctx.update(&ibuf);
        let mut obuf = [0; 4096];
        ctx.finalize(&mut obuf);
        obuf
    };

    let b = {
        let mut ctx = KangarooTwelve::new(b"custom_string");
        ctx.update(&ibuf);
        let mut obuf = [0; 4096];
        ctx.finalize(&mut obuf);
        obuf
    };

    assert_eq!(a, b);
}
