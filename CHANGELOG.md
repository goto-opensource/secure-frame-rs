# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2023-10-28

### Features

- Update key derivation / tag computation to draft-03

## [0.2.2] - 2023-08-02

### Features

- Aes ctr mode ciphers for openssl

## [0.2.1] - 2023-07-17

### Bug Fixes

- Wrong auth tag size

### Features

- Crypto library feature handling
- Openssl aead implemenation
- Implement hkdf with openssl
- Add openssl crypto crate stub
- Update to draft enc-01

## [0.2.0] - 2023-04-28

### Performance

- Reusable, internal buffer in sender/receiver
- Improved nonce creation

## [0.1.0] - 2022-12-16

### Features

* github actions
  ([bc1c759](https://github.com/goto-opensource/secure-frame-rs/commit/bc1c7591959bb2ff5a1cb6d2e7434517d2264bae))
* allow configuring ciphersuite of sender and receiver
  ([ca15a48](https://github.com/goto-opensource/secure-frame-rs/commit/ca15a480178ef127940aee7c757f5b75c99f9ca0))
* implement AesGcm128Sha256
  ([6b8fd43](https://github.com/goto-opensource/secure-frame-rs/commit/6b8fd43f55c3057617f802f2d895dcf6068db267))
* impl from trait for KeyId
  ([37873e1](https://github.com/goto-opensource/secure-frame-rs/commit/37873e1fd8e0c0576c84bd08300ba36cec713585))
* add FrameValidation in Receiver
  ([77e4f05](https://github.com/goto-opensource/secure-frame-rs/commit/77e4f05b13294198e35b8520de9a86ff6cff719f))
* add Receiver::remove_encryption_key()
  ([082e6f3](https://github.com/goto-opensource/secure-frame-rs/commit/082e6f31af783e131cc53b1d68dc155e4665ec80))
