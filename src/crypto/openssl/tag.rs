pub struct Tag(Vec<u8>);

impl Tag {
    pub fn new(len: usize) -> Self {
        Tag(vec![0; len])
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Tag {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<Vec<u8>> for Tag {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}
