// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use crate::{
    crypto::aead::{AeadDecrypt, AeadEncrypt},
    error::Result,
    header::FrameCount,
};

use crate::{
    crypto::{
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        secret::Secret,
    },
    error::SframeError,
};

pub struct Tag(Vec<u8>);
impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AeadEncrypt for CipherSuite {
    // TODO
    type AuthTag = Tag;
    fn encrypt<IoBuffer, Aad>(
        &self,
        io_buffer: &mut IoBuffer,
        secret: &Secret,
        aad_buffer: &Aad,
        frame_count: FrameCount,
    ) -> Result<Tag>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized,
    {
        todo!()
    }
}

impl AeadDecrypt for CipherSuite {
    fn decrypt<'a, IoBuffer, Aad>(
        &self,
        io_buffer: &'a mut IoBuffer,
        secret: &Secret,
        aad_buffer: &Aad,
        frame_count: FrameCount,
    ) -> Result<&'a mut [u8]>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized,
    {
        todo!()
    }
}
