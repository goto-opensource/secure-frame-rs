use crate::{
    crypto::{
        cipher_suite::CipherSuite,
        key_expansion::{KeyMaterial, Secret},
    },
    error::Result,
    header::{FrameCountGenerator, KeyId},
    CipherSuiteVariant,
};

pub struct Key {
    pub(crate) key_id: KeyId,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) secret: Secret,
    pub(crate) frame_counter: FrameCountGenerator,
}

impl Key {
    pub fn expand<Buffer>(
        key_id: u64,
        variant: CipherSuiteVariant,
        key_material: &Buffer,
    ) -> Result<Self>
    where
        Buffer: AsRef<[u8]>,
    {
        let cipher_suite = variant.into();
        let secret = KeyMaterial(key_material.as_ref()).expand_as_secret(&cipher_suite)?;
        Ok(Self {
            cipher_suite,
            secret,
            key_id: key_id.into(),
            frame_counter: Default::default(),
        })
    }
}
