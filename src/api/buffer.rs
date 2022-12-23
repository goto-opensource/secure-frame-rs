use crate::error::Result;

pub trait Buffer {
    type BufferSlice: AsMut<[u8]> + AsRef<[u8]>;
    fn allocate<'buf>(&'buf mut self, size: usize) -> Result<&'buf mut Self::BufferSlice>;
}

#[derive(Debug, Default)]
pub struct VectorBuffer {
    pub buffer: Vec<u8>,
}

impl Buffer for VectorBuffer {
    type BufferSlice = Vec<u8>;
    fn allocate<'buf>(&'buf mut self, size: usize) -> Result<&'buf mut Self::BufferSlice> {
        log::trace!("Allocating buffer of size {}", size);

        self.buffer.resize(size, 0);
        Ok(&mut self.buffer)
    }
}
