type Operator = fn(&mut [u8], &[u8], usize);

pub fn xor(dst: &mut [u8], src: &[u8], len: usize) {
    let (dst, src) = (&mut dst[..len], &src[..len]);
    for i in 0..len {
        dst[i] ^= src[i];
    }
}

pub fn copy(dst: &mut [u8], src: &[u8], len: usize) {
    let (dst, src) = (&mut dst[..len], &src[..len]);
    dst.copy_from_slice(src)
}

pub enum IOBuf<'io> {
    In(&'io [u8], Operator),
    Out(&'io mut [u8], Operator),
    Skip(usize),
}

impl<'io> IOBuf<'io> {
    #[inline]
    fn len(&self) -> usize {
        match self {
            IOBuf::In(iobuf, _) => iobuf.len(),
            IOBuf::Out(iobuf, _) => iobuf.len(),
            IOBuf::Skip(len) => *len,
        }
    }

    #[inline]
    fn exec(&mut self, buf_part: &mut [u8], iobuf_offset: usize, len: usize) {
        match self {
            IOBuf::In(iobuf, f) => {
                let dst = buf_part;
                let src = &iobuf[iobuf_offset..];
                f(dst, src, len);
            },
            IOBuf::Out(iobuf, f) => {
                let dst = &mut iobuf[iobuf_offset..];
                let src = buf_part;
                f(dst, src, len);
            },
            IOBuf::Skip(_) => {},
        }
    }

    pub fn fold<const L: usize, const R: usize, F: Foldable<L, R>>(mut self, foldable: &mut F, mut offset: usize) -> usize {
        let mut iobuf_offset = 0;
        let mut iobuf_rest = self.len();
        let mut current_len = R - offset;
        while iobuf_rest >= current_len {
            self.exec(&mut foldable.buf_mut()[offset..], iobuf_offset, current_len);
            foldable.permute();
            offset = 0;
            iobuf_offset += current_len;
            iobuf_rest -= current_len;
            current_len = R;
        }
        self.exec(&mut foldable.buf_mut()[offset..], iobuf_offset, iobuf_rest);
        offset + iobuf_rest
    }
}

pub trait Permute {
    fn permute(&mut self);
}

pub trait Foldable<const L: usize, const R: usize>: Permute {
    fn buf_mut(&mut self) -> &mut [u8; L];
}
