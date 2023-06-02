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
}

pub trait Permute {
    fn permute(&mut self);
}

pub trait Foldable<const L: usize, const R: usize>: Permute {
    fn buf_mut(&mut self) -> &mut [u8; L];

    fn fold(&mut self, mut offset: usize, mut iobuf: IOBuf) -> usize {
        let mut iobuf_offset = 0;
        let mut iobuf_rest = iobuf.len();
        let mut current_len = R - offset;
        while iobuf_rest >= current_len {
            iobuf.exec(&mut self.buf_mut()[offset..], iobuf_offset, current_len);
            self.permute();
            offset = 0;
            iobuf_offset += current_len;
            iobuf_rest -= current_len;
            current_len = R;
        }
        iobuf.exec(&mut self.buf_mut()[offset..], iobuf_offset, iobuf_rest);
        offset + iobuf_rest
    }

    // pub fn pipe_fold<const L2: usize, const R2: usize, P2: Permute<L2>>(&mut self, len: usize, other: &mut FoldableBuffer<L2, R2, P2>, in_f: Operator, out_f: Operator) {
    // }
}
