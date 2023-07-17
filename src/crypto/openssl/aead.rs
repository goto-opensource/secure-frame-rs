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

const NONCE_LEN: usize = 12;

pub struct Tag(Vec<u8>);

impl Tag {
    fn new(len: usize) -> Self {
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

impl AeadEncrypt for CipherSuite {
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
        let io_buffer = io_buffer.as_mut();

        let cipher = self.variant.into();
        let nonce = secret.create_nonce::<NONCE_LEN>(&frame_count);
        let mut tag = Tag::new(self.auth_tag_len);

        let out = openssl::symm::encrypt_aead(
            cipher,
            &secret.key,
            Some(&nonce),
            aad_buffer.as_ref(),
            io_buffer,
            tag.as_mut(),
        )
        .map_err(|_| SframeError::EncryptionFailure)?;

        debug_assert!(
            out.len() == io_buffer.len(),
            "For a symmetric encryption it is given that the output has the same length as the input"
        );
        io_buffer.copy_from_slice(&out[..io_buffer.len()]);

        Ok(tag)
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
        let io_buffer = io_buffer.as_mut();
        if io_buffer.len() < self.auth_tag_len {
            return Err(SframeError::DecryptionFailure);
        }

        let cipher = self.variant.into();
        let nonce = secret.create_nonce::<NONCE_LEN>(&frame_count);

        let encrypted_len = io_buffer.len() - self.auth_tag_len;
        let encrypted_data = &io_buffer[..encrypted_len];
        let tag = &io_buffer[encrypted_len..];

        let out = openssl::symm::decrypt_aead(
            cipher,
            &secret.key,
            Some(&nonce),
            aad_buffer.as_ref(),
            encrypted_data,
            tag,
        )
        .map_err(|_| SframeError::EncryptionFailure)?;

        debug_assert!(
            out.len() == encrypted_len,
            "For a symmetric encryption it is given that the output has the same length as the input"
        );
        io_buffer[..encrypted_len].copy_from_slice(&out);

        Ok(&mut io_buffer[..encrypted_len])
    }
}

impl From<CipherSuiteVariant> for openssl::symm::Cipher {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            CipherSuiteVariant::AesGcm128Sha256 => openssl::symm::Cipher::aes_128_gcm(),
            CipherSuiteVariant::AesGcm256Sha512 => openssl::symm::Cipher::aes_256_gcm(),
        }
    }
}
