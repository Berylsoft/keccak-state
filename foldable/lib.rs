#[cfg(feature = "zeroize-on-drop")]
use zeroize::Zeroize;

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

pub trait Permute<const L: usize> {
    fn permute(buf: &mut [u8; L]);
}

#[derive(Clone)]
pub struct FoldableBuffer<const L: usize, const R: usize, P> {
    buf: [u8; L],
    offset: usize,
    _phantom: core::marker::PhantomData<P>,
}

impl<const L: usize, const R: usize, P> Default for FoldableBuffer<L, R, P> {
    fn default() -> Self {
        Self {
            buf: [0; L],
            offset: 0,
            _phantom: core::marker::PhantomData,
        }
    }
}

#[cfg(feature = "zeroize-on-drop")]
impl<const L: usize, const R: usize, P> Drop for FoldableBuffer<L, R, P> {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.offset = 0;
    }
}

impl<const L: usize, const R: usize, P: Permute<L>> FoldableBuffer<L, R, P> {
    pub fn reset(&mut self) {
        #[cfg(feature = "zeroize-on-drop")]
        self.buf.zeroize();
        #[cfg(not(feature = "zeroize-on-drop"))]
        let _ = core::mem::replace(&mut self.buf, [0; L]);
        self.offset = 0;
    }

    pub fn fold(&mut self, mut iobuf: IOBuf) {
        let mut iobuf_offset = 0;
        let mut iobuf_rest = iobuf.len();
        let mut current_len = R - self.offset;
        while iobuf_rest >= current_len {
            iobuf.exec(&mut self.buf[self.offset..], iobuf_offset, current_len);
            P::permute(&mut self.buf);
            self.offset = 0;
            iobuf_offset += current_len;
            iobuf_rest -= current_len;
            current_len = R;
        }
        iobuf.exec(&mut self.buf[self.offset..], iobuf_offset, iobuf_rest);
        self.offset += iobuf_rest;
    }

    // pub fn pipe_fold<const L2: usize, const R2: usize, P2: Permute<L2>>(&mut self, len: usize, other: &mut FoldableBuffer<L2, R2, P2>, in_f: Operator, out_f: Operator) {
    // }
}
