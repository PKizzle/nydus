// Copyright (C) 2022-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt::{self, Debug, Formatter};
use std::io::Error;
use std::str::FromStr;
use std::sync::Arc;

use aes::cipher::typenum::{U12, U16};
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::AesGcm;
use aes_gcm::aead::AeadInOut;
use aes_gcm::aead::inout::InOutBuf;
use xts_mode::Xts128;

/// AES-256-GCM with a 16-byte IV and 12-byte tag, matching the sizes nydus
/// historically used with OpenSSL's `aes-256-gcm`.
type Aes256GcmCipher = AesGcm<Aes256, U16, U12>;

// The length of the data unit to be encrypted.
pub const DATA_UNIT_LENGTH: usize = 16;
// The length of thd iv (Initialization Vector) to do AES-XTS encryption.
pub const AES_XTS_IV_LENGTH: usize = 16;
// The length of the key to do AES-128-XTS encryption.
pub const AES_128_XTS_KEY_LENGTH: usize = 32;
// The length of the key to do AES-256-XTS encryption.
pub const AES_256_XTS_KEY_LENGTH: usize = 64;
// The length of the key to do AES-256-GCM encryption.
pub const AES_256_GCM_KEY_LENGTH: usize = 32;

// The padding magic end.
pub const PADDING_MAGIC_END: [u8; 2] = [0x78, 0x90];
// DATA_UNIT_LENGTH + length of PADDING_MAGIC_END.
pub const PADDING_LENGTH: usize = 18;
// Openssl rejects keys with identical first and second halves for xts.
// Use a default key for such cases.
const DEFAULT_CE_KEY: [u8; 32] = [
    0xac, 0xed, 0x14, 0x69, 0x94, 0x23, 0x1e, 0xca, 0x44, 0x8c, 0xed, 0x2f, 0x6b, 0x40, 0x0c, 0x00,
    0xfd, 0xbb, 0x3f, 0xac, 0xdd, 0xc7, 0xd9, 0xee, 0x83, 0xf6, 0x5c, 0xd9, 0x3c, 0xaa, 0x28, 0x7c,
];
const DEFAULT_CE_KEY_64: [u8; 64] = [
    0xac, 0xed, 0x14, 0x69, 0x94, 0x23, 0x1e, 0xca, 0x44, 0x8c, 0xed, 0x2f, 0x6b, 0x40, 0x0c, 0x00,
    0xfd, 0xbb, 0x3f, 0xac, 0xdd, 0xc7, 0xd9, 0xee, 0x83, 0xf6, 0x5c, 0xd9, 0x3c, 0xaa, 0x28, 0x7c,
    0xfd, 0xbb, 0x3f, 0xac, 0xdd, 0xc7, 0xd9, 0xee, 0x83, 0xf6, 0x5c, 0xd9, 0x3c, 0xaa, 0x28, 0x7c,
    0xac, 0xed, 0x14, 0x69, 0x94, 0x23, 0x1e, 0xca, 0x44, 0x8c, 0xed, 0x2f, 0x6b, 0x40, 0x0c, 0x00,
];

/// Supported cipher algorithms.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Algorithm {
    #[default]
    None = 0,
    Aes128Xts = 1,
    Aes256Xts = 2,
    Aes256Gcm = 3,
}

impl Algorithm {
    /// Create a new cipher object.
    pub fn new_cipher(&self) -> Result<Cipher, Error> {
        match self {
            Algorithm::None => Ok(Cipher::None),
            Algorithm::Aes128Xts => Ok(Cipher::Aes128Xts),
            Algorithm::Aes256Xts => Ok(Cipher::Aes256Xts),
            Algorithm::Aes256Gcm => Ok(Cipher::Aes256Gcm),
        }
    }

    /// Check whether data encryption is enabled or not.
    pub fn is_encryption_enabled(&self) -> bool {
        *self != Algorithm::None
    }

    /// Check whether algorithm is AEAD.
    pub fn is_aead(&self) -> bool {
        match self {
            Algorithm::None => false,
            Algorithm::Aes128Xts => false,
            Algorithm::Aes256Xts => false,
            Algorithm::Aes256Gcm => true,
        }
    }

    /// Get size of tag associated with encrypted data.
    pub fn tag_size(&self) -> usize {
        match self {
            Algorithm::None => 0,
            Algorithm::Aes128Xts => 0,
            Algorithm::Aes256Xts => 0,
            Algorithm::Aes256Gcm => 12,
        }
    }

    /// Get key size of the encryption algorithm.
    pub fn key_length(&self) -> usize {
        match self {
            Algorithm::None => 0,
            Algorithm::Aes128Xts => AES_128_XTS_KEY_LENGTH,
            Algorithm::Aes256Xts => AES_256_XTS_KEY_LENGTH,
            Algorithm::Aes256Gcm => AES_256_GCM_KEY_LENGTH,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "aes128xts" => Ok(Self::Aes128Xts),
            "aes256xts" => Ok(Self::Aes256Xts),
            "aes256gcm" => Ok(Self::Aes256Gcm),
            _ => Err(einval!("cypher algorithm should be none or aes_gcm")),
        }
    }
}

impl TryFrom<u32> for Algorithm {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == Algorithm::None as u32 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Aes128Xts as u32 {
            Ok(Algorithm::Aes128Xts)
        } else if value == Algorithm::Aes256Xts as u32 {
            Ok(Algorithm::Aes256Xts)
        } else if value == Algorithm::Aes256Gcm as u32 {
            Ok(Algorithm::Aes256Gcm)
        } else {
            Err(())
        }
    }
}

impl TryFrom<u64> for Algorithm {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == Algorithm::None as u64 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Aes128Xts as u64 {
            Ok(Algorithm::Aes128Xts)
        } else if value == Algorithm::Aes256Xts as u64 {
            Ok(Algorithm::Aes256Xts)
        } else if value == Algorithm::Aes256Gcm as u64 {
            Ok(Algorithm::Aes256Gcm)
        } else {
            Err(())
        }
    }
}

/// Cipher object to encrypt/decrypt data.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Cipher {
    #[default]
    None,
    Aes128Xts,
    Aes256Xts,
    Aes256Gcm,
}

impl Debug for Cipher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Cipher::None => write!(f, "cipher: none"),
            Cipher::Aes128Xts => write!(f, "cypher: aes128_xts"),
            Cipher::Aes256Xts => write!(f, "cypher: aes256_xts"),
            Cipher::Aes256Gcm => write!(f, "cipher: aes256_gcm"),
        }
    }
}

impl Cipher {
    /// Encrypt plaintext with optional IV and return the encrypted data.
    ///
    /// For XTS, the caller needs to ensure that the top half of key is not identical to the
    /// bottom half of the key, otherwise the encryption will fail.
    pub fn encrypt<'a>(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        data: &'a [u8],
    ) -> Result<Cow<'a, [u8]>, Error> {
        match self {
            Cipher::None => Ok(Cow::from(data)),
            Cipher::Aes128Xts => {
                assert_eq!(key.len(), AES_128_XTS_KEY_LENGTH);
                let mut buf;
                let data = if data.len() >= DATA_UNIT_LENGTH {
                    data
                } else {
                    // CMS (Cryptographic Message Syntax).
                    // This pads with the same value as the number of padding bytes
                    // and appends the magic padding end.
                    let val = (DATA_UNIT_LENGTH - data.len()) as u8;
                    buf = [val; PADDING_LENGTH];
                    buf[..data.len()].copy_from_slice(data);
                    buf[DATA_UNIT_LENGTH..PADDING_LENGTH].copy_from_slice(&PADDING_MAGIC_END);
                    &buf
                };
                Self::xts_crypt::<Aes128>(key, iv, data, true).map(Cow::from)
            }
            Cipher::Aes256Xts => {
                assert_eq!(key.len(), AES_256_XTS_KEY_LENGTH);
                let mut buf;
                let data = if data.len() >= DATA_UNIT_LENGTH {
                    data
                } else {
                    let val = (DATA_UNIT_LENGTH - data.len()) as u8;
                    buf = [val; PADDING_LENGTH];
                    buf[..data.len()].copy_from_slice(data);
                    buf[DATA_UNIT_LENGTH..PADDING_LENGTH].copy_from_slice(&PADDING_MAGIC_END);
                    &buf
                };
                Self::xts_crypt::<Aes256>(key, iv, data, true).map(Cow::from)
            }
            Cipher::Aes256Gcm => Err(einval!("Cipher::encrypt() doesn't support Aes256Gcm")),
        }
    }

    /// Decrypt encrypted data with optional IV and return the decrypted data.
    pub fn decrypt(&self, key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut data = match self {
            Cipher::None => Ok(data.to_vec()),
            Cipher::Aes128Xts => Self::xts_crypt::<Aes128>(key, iv, data, false),
            Cipher::Aes256Xts => Self::xts_crypt::<Aes256>(key, iv, data, false),
            Cipher::Aes256Gcm => Err(einval!("Cipher::decrypt() doesn't support Aes256Gcm")),
        }?;

        // Trim possible padding.
        if data.len() == PADDING_LENGTH
            && data[PADDING_LENGTH - PADDING_MAGIC_END.len()..PADDING_LENGTH] == PADDING_MAGIC_END
        {
            let val = data[DATA_UNIT_LENGTH - 1] as usize;
            if val < DATA_UNIT_LENGTH {
                data.truncate(DATA_UNIT_LENGTH - val);
            } else {
                return Err(einval!(format!(
                    "Cipher::decrypt: invalid padding data, value {}",
                    val,
                )));
            }
        };

        Ok(data)
    }

    /// Encrypt plaintext and return the ciphertext with authentication tag.
    pub fn encrypt_aead(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Cipher::Aes256Gcm => Self::gcm_encrypt(key, iv, data, tag),
            _ => Err(einval!("invalid algorithm for encrypt_aead()")),
        }
    }

    /// Decrypt plaintext and return the encrypted data with authentication tag.
    pub fn decrypt_aead(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Cipher::Aes256Gcm => Self::gcm_decrypt(key, iv, data, tag),
            _ => Err(einval!("invalid algorithm for decrypt_aead()")),
        }
    }

    /// Get size of tag associated with encrypted data.
    pub fn tag_size(&self) -> usize {
        match self {
            Cipher::Aes256Gcm => 12,
            _ => 0,
        }
    }

    /// Get size of ciphertext from size of plaintext.
    pub fn encrypted_size(&self, plaintext_size: usize) -> usize {
        match self {
            Cipher::None => plaintext_size,
            Cipher::Aes128Xts | Cipher::Aes256Xts => {
                if plaintext_size < DATA_UNIT_LENGTH {
                    DATA_UNIT_LENGTH
                } else {
                    plaintext_size
                }
            }
            Cipher::Aes256Gcm => {
                assert!(plaintext_size.checked_add(12).is_some());
                plaintext_size + 12
            }
        }
    }

    /// Tweak key for XTS mode.
    pub fn tweak_key_for_xts(key: &[u8]) -> Cow<'_, [u8]> {
        let len = key.len() >> 1;
        if key[..len] == key[len..] {
            let mut buf = if key[len] == 0xa5 {
                vec![0x5a; key.len()]
            } else {
                vec![0xa5; key.len()]
            };
            buf[len..].copy_from_slice(&key[len..]);
            Cow::from(buf)
        } else {
            Cow::from(key)
        }
    }

    /// AES-XTS encrypt/decrypt a single data unit, using `iv` as the 16-byte tweak.
    ///
    /// Matches OpenSSL's `aes-128-xts` / `aes-256-xts` EVP ciphers: the key is split into two
    /// equal halves (data key || tweak key), the IV is the raw tweak, and inputs whose length is
    /// not a multiple of the 16-byte block use IEEE P1619 ciphertext stealing (handled by
    /// `xts-mode`). Compatibility with the previous OpenSSL output is pinned by the known-answer
    /// tests in this module.
    fn xts_crypt<C>(
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>, Error>
    where
        C: KeyInit + BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    {
        let iv = iv.ok_or_else(|| einval!("XTS mode requires an IV"))?;
        let tweak: [u8; AES_XTS_IV_LENGTH] = iv
            .try_into()
            .map_err(|_| einval!(format!("XTS IV must be {} bytes", AES_XTS_IV_LENGTH)))?;
        let half = key.len() / 2;
        let cipher_1 =
            C::new_from_slice(&key[..half]).map_err(|_| einval!("invalid XTS key length"))?;
        let cipher_2 =
            C::new_from_slice(&key[half..]).map_err(|_| einval!("invalid XTS key length"))?;
        let xts = Xts128::new(cipher_1, cipher_2);
        let mut buf = data.to_vec();
        if encrypt {
            xts.encrypt_sector(&mut buf, tweak.into());
        } else {
            xts.decrypt_sector(&mut buf, tweak.into());
        }
        Ok(buf)
    }

    fn gcm_encrypt(
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>, Error> {
        let iv = iv.ok_or_else(|| einval!("GCM mode requires an IV"))?;
        let nonce: &Array<u8, U16> = iv
            .try_into()
            .map_err(|_| einval!(format!("GCM IV must be {} bytes", AES_XTS_IV_LENGTH)))?;
        let cipher =
            Aes256GcmCipher::new_from_slice(key).map_err(|_| einval!("invalid GCM key length"))?;
        let mut buf = data.to_vec();
        let out_tag = cipher
            .encrypt_inout_detached(nonce, &[], InOutBuf::from(&mut buf[..]))
            .map_err(|e| eother!(format!("failed to encrypt data, {}", e)))?;
        if tag.len() != out_tag.len() {
            return Err(einval!(format!(
                "GCM tag buffer must be {} bytes",
                out_tag.len()
            )));
        }
        tag.copy_from_slice(out_tag.as_slice());
        Ok(buf)
    }

    fn gcm_decrypt(
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let iv = iv.ok_or_else(|| einval!("GCM mode requires an IV"))?;
        let nonce: &Array<u8, U16> = iv
            .try_into()
            .map_err(|_| einval!(format!("GCM IV must be {} bytes", AES_XTS_IV_LENGTH)))?;
        let tag: &Array<u8, U12> = tag
            .try_into()
            .map_err(|_| einval!("GCM tag must be 12 bytes"))?;
        let cipher =
            Aes256GcmCipher::new_from_slice(key).map_err(|_| einval!("invalid GCM key length"))?;
        let mut buf = data.to_vec();
        cipher
            .decrypt_inout_detached(nonce, &[], InOutBuf::from(&mut buf[..]), tag)
            .map_err(|e| eother!(format!("failed to decrypt data, {}", e)))?;
        Ok(buf)
    }

    pub fn generate_random_key(cipher_algo: Algorithm) -> Result<Vec<u8>, Error> {
        let length = cipher_algo.key_length();
        let mut buf = vec![0u8; length];
        getrandom::fill(&mut buf)
            .map_err(|e| eother!(format!("failed to generate key for {}, {}", cipher_algo, e)))?;
        Ok(Self::tweak_key_for_xts(&buf).to_vec())
    }

    pub fn generate_random_iv() -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; AES_XTS_IV_LENGTH];
        getrandom::fill(&mut buf).map_err(|e| eother!(format!("failed to generate iv, {}", e)))?;
        Ok(buf)
    }
}

/// Struct to provide context information for data encryption/decryption.
#[derive(Default, Debug, Clone)]
pub struct CipherContext {
    key: Vec<u8>,
    iv: Vec<u8>,
    convergent_encryption: bool,
    cipher_algo: Algorithm,
}

impl CipherContext {
    /// Create a new instance of [CipherContext].
    pub fn new(
        key: Vec<u8>,
        iv: Vec<u8>,
        convergent_encryption: bool,
        cipher_algo: Algorithm,
    ) -> Result<Self, Error> {
        let key_length = key.len();
        if key_length != cipher_algo.key_length() {
            return Err(einval!(format!(
                "invalid key length {} for {} encryption",
                key_length, cipher_algo
            )));
        } else if key[0..key_length >> 1] == key[key_length >> 1..key_length] {
            return Err(einval!("invalid symmetry key for encryption"));
        }

        Ok(CipherContext {
            key,
            iv,
            convergent_encryption,
            cipher_algo,
        })
    }

    /// Generate context information from data for encryption/decryption.
    pub fn generate_cipher_meta<'a>(&'a self, data: &'a [u8]) -> (&'a [u8], Vec<u8>) {
        let length = data.len();
        assert_eq!(length, self.cipher_algo.key_length());
        let iv = vec![0u8; AES_XTS_IV_LENGTH];
        if self.convergent_encryption {
            if length == AES_128_XTS_KEY_LENGTH && data[0..length >> 1] == data[length >> 1..length]
            {
                (&DEFAULT_CE_KEY, iv)
            } else if length == AES_256_XTS_KEY_LENGTH
                && data[0..length >> 1] == data[length >> 1..length]
            {
                (&DEFAULT_CE_KEY_64, iv)
            } else {
                (data, iv)
            }
        } else {
            (&self.key, iv)
        }
    }

    /// Get context information for meta data encryption/decryption.
    pub fn get_cipher_meta(&self) -> (&[u8], &[u8]) {
        (&self.key, &self.iv)
    }
}

// Encrypt data with Cipher and CipherContext.
pub fn encrypt_with_context<'a>(
    data: &'a [u8],
    cipher_obj: &Arc<Cipher>,
    cipher_ctx: &Option<CipherContext>,
    encrypted: bool,
) -> Result<Cow<'a, [u8]>, Error> {
    if encrypted {
        if let Some(cipher_ctx) = cipher_ctx {
            let (key, iv) = cipher_ctx.get_cipher_meta();
            Ok(cipher_obj.encrypt(key, Some(iv), data)?)
        } else {
            Err(einval!("the encrypt context can not be none"))
        }
    } else {
        Ok(Cow::Borrowed(data))
    }
}

// Decrypt data with Cipher and CipherContext.
pub fn decrypt_with_context<'a>(
    data: &'a [u8],
    cipher_obj: &Arc<Cipher>,
    cipher_ctx: &Option<CipherContext>,
    encrypted: bool,
) -> Result<Cow<'a, [u8]>, Error> {
    if encrypted {
        if let Some(cipher_ctx) = cipher_ctx {
            let (key, iv) = cipher_ctx.get_cipher_meta();
            Ok(Cow::from(cipher_obj.decrypt(key, Some(iv), data)?))
        } else {
            Err(einval!("the decrypt context can not be none"))
        }
    } else {
        Ok(Cow::Borrowed(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_xts_encrypt() {
        let mut key = [0xcu8; 32];
        key[31] = 0xa;

        let cipher = Algorithm::Aes128Xts.new_cipher().unwrap();
        assert_eq!(cipher.encrypted_size(1), 16);
        assert_eq!(cipher.encrypted_size(16), 16);
        assert_eq!(cipher.encrypted_size(17), 17);

        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(ciphertext2.len(), PADDING_LENGTH);

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        assert_eq!(ciphertext3.len(), 17);

        let ciphertext4 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        assert_eq!(ciphertext4.len(), 17);
        assert_ne!(ciphertext4, ciphertext3);

        let ciphertext5 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"21111111111111111")
            .unwrap();
        assert_eq!(ciphertext5.len(), 17);
        assert_ne!(ciphertext5, ciphertext4);
    }

    #[test]
    fn test_aes_256_xts_encrypt() {
        let mut key = [0xcu8; 64];
        key[31] = 0xa;

        let cipher = Algorithm::Aes256Xts.new_cipher().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(ciphertext2.len(), PADDING_LENGTH);

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        assert_eq!(ciphertext3.len(), 17);

        let ciphertext4 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        assert_eq!(ciphertext4.len(), 17);
        assert_ne!(ciphertext4, ciphertext3);

        let ciphertext5 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"21111111111111111")
            .unwrap();
        assert_eq!(ciphertext5.len(), 17);
        assert_ne!(ciphertext5, ciphertext4);
    }

    #[test]
    fn test_aes_128_xts_decrypt() {
        let mut key = [0xcu8; 32];
        key[31] = 0xa;

        let cipher = Algorithm::Aes128Xts.new_cipher().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let plaintext1 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext1)
            .unwrap();
        assert_eq!(&plaintext1, b"1");

        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext2 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext2)
            .unwrap();
        assert_eq!(&plaintext2, b"11111111111111111");

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext3 = cipher
            .decrypt(key.as_slice(), Some(&[1u8; 16]), &ciphertext3)
            .unwrap();
        assert_eq!(&plaintext3, b"11111111111111111");
    }

    #[test]
    fn test_aes_256_xts_decrypt() {
        let mut key = [0xcu8; 64];
        key[31] = 0xa;

        let cipher = Algorithm::Aes256Xts.new_cipher().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let plaintext1 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext1)
            .unwrap();
        assert_eq!(&plaintext1, b"1");

        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext2 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext2)
            .unwrap();
        assert_eq!(&plaintext2, b"11111111111111111");

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext3 = cipher
            .decrypt(key.as_slice(), Some(&[1u8; 16]), &ciphertext3)
            .unwrap();
        assert_eq!(&plaintext3, b"11111111111111111");
    }

    #[test]
    fn test_aes_256_gcm() {
        let key = [0xcu8; 32];
        let mut tag = vec![0u8; 12];

        let cipher = Algorithm::Aes256Gcm.new_cipher().unwrap();
        assert_eq!(cipher.tag_size(), 12);
        assert_eq!(cipher.encrypted_size(1), 13);

        let ciphertext1 = cipher
            .encrypt_aead(key.as_slice(), Some(&[0u8; 16]), b"1", &mut tag)
            .unwrap();
        assert_eq!(ciphertext1.len(), 1);
        assert_eq!(tag.len(), 12);
        let plaintext1 = cipher
            .decrypt_aead(key.as_slice(), Some(&[0u8; 16]), &ciphertext1, &tag)
            .unwrap();
        assert_eq!(&plaintext1, b"1");

        let ciphertext2 = cipher
            .encrypt_aead(
                key.as_slice(),
                Some(&[0u8; 16]),
                b"11111111111111111",
                &mut tag,
            )
            .unwrap();
        assert_eq!(ciphertext2.len(), 17);
        assert_eq!(tag.len(), 12);
        let plaintext2 = cipher
            .decrypt_aead(key.as_slice(), Some(&[0u8; 16]), &ciphertext2, &tag)
            .unwrap();
        assert_eq!(&plaintext2, b"11111111111111111");

        let ciphertext3 = cipher
            .encrypt_aead(
                key.as_slice(),
                Some(&[1u8; 16]),
                b"11111111111111111",
                &mut tag,
            )
            .unwrap();
        assert_ne!(ciphertext3, ciphertext2);
        assert_eq!(ciphertext3.len(), 17);
        assert_eq!(tag.len(), 12);
        let plaintext3 = cipher
            .decrypt_aead(key.as_slice(), Some(&[1u8; 16]), &ciphertext3, &tag)
            .unwrap();
        assert_eq!(&plaintext3, b"11111111111111111");
    }

    #[test]
    fn test_tweak_key_for_xts() {
        let buf = vec![0x0; 32];
        let buf2 = Cipher::tweak_key_for_xts(&buf);
        assert_eq!(buf2[0], 0xa5);
        assert_eq!(buf2[16], 0x0);

        let buf = vec![0xa5; 32];
        let buf2 = Cipher::tweak_key_for_xts(&buf);
        assert_eq!(buf2[0], 0x5a);
        assert_eq!(buf2[16], 0xa5);
    }

    #[test]
    fn test_attribute() {
        let none = Algorithm::None.new_cipher().unwrap();
        let aes128xts = Algorithm::Aes128Xts.new_cipher().unwrap();
        let aes256xts = Algorithm::Aes256Xts.new_cipher().unwrap();
        let aes256gcm = Algorithm::Aes256Gcm.new_cipher().unwrap();

        assert!(!Algorithm::None.is_encryption_enabled());
        assert!(Algorithm::Aes128Xts.is_encryption_enabled());
        assert!(Algorithm::Aes256Xts.is_encryption_enabled());
        assert!(Algorithm::Aes256Gcm.is_encryption_enabled());

        assert!(!Algorithm::None.is_aead());
        assert!(!Algorithm::Aes128Xts.is_aead());
        assert!(!Algorithm::Aes256Xts.is_aead());
        assert!(Algorithm::Aes256Gcm.is_aead());

        assert_eq!(Algorithm::None.tag_size(), 0);
        assert_eq!(Algorithm::Aes128Xts.tag_size(), 0);
        assert_eq!(Algorithm::Aes256Xts.tag_size(), 0);
        assert_eq!(Algorithm::Aes256Gcm.tag_size(), 12);

        assert_eq!(Algorithm::None.key_length(), 0);
        assert_eq!(Algorithm::Aes128Xts.key_length(), AES_128_XTS_KEY_LENGTH);
        assert_eq!(Algorithm::Aes256Xts.key_length(), AES_256_XTS_KEY_LENGTH);
        assert_eq!(Algorithm::Aes256Gcm.key_length(), AES_256_GCM_KEY_LENGTH);

        print!("{}", Algorithm::Aes128Xts);
        assert!(Algorithm::from_str("none").is_ok());
        assert!(Algorithm::from_str("aes128xts").is_ok());
        assert!(Algorithm::from_str("aes256xts").is_ok());
        assert!(Algorithm::from_str("aes256gcm").is_ok());
        assert!(Algorithm::from_str("non-exist").is_err());

        assert!(Algorithm::try_from(Algorithm::None as u32).is_ok());
        assert!(Algorithm::try_from(Algorithm::Aes128Xts as u32).is_ok());
        assert!(Algorithm::try_from(Algorithm::Aes256Xts as u32).is_ok());
        assert!(Algorithm::try_from(Algorithm::Aes256Gcm as u32).is_ok());
        assert!(Algorithm::try_from(u32::MAX).is_err());

        assert!(Algorithm::try_from(Algorithm::None as u64).is_ok());
        assert!(Algorithm::try_from(Algorithm::Aes128Xts as u64).is_ok());
        assert!(Algorithm::try_from(Algorithm::Aes256Xts as u64).is_ok());
        assert!(Algorithm::try_from(Algorithm::Aes256Gcm as u64).is_ok());
        assert!(Algorithm::try_from(u64::MAX).is_err());

        println!("{:?},{:?},{:?},{:?}", none, aes128xts, aes256xts, aes256gcm);
    }

    #[test]
    fn test_crypt_with_context() {
        let error_key = [0xcu8, 64];
        let symmetry_key = [0xcu8, 32];
        let mut key = [0xcu8; 32];
        key[31] = 0xa;
        let iv = [0u8; 16];
        let data = b"11111111111111111";
        // create with mismatch key length and algo
        assert!(
            CipherContext::new(error_key.to_vec(), iv.to_vec(), true, Algorithm::Aes128Xts)
                .is_err()
        );
        // create with symmetry key
        assert!(
            CipherContext::new(
                symmetry_key.to_vec(),
                iv.to_vec(),
                true,
                Algorithm::Aes128Xts
            )
            .is_err()
        );

        // test context is none
        let ctx =
            CipherContext::new(key.to_vec(), iv.to_vec(), false, Algorithm::Aes128Xts).unwrap();
        let obj = Arc::new(Algorithm::Aes128Xts.new_cipher().unwrap());
        assert!(encrypt_with_context(data, &obj, &None, true).is_err());
        assert!(decrypt_with_context(b"somedata", &obj, &None, true).is_err());

        // test encrypted is false
        let no_change = encrypt_with_context(data, &obj, &Some(ctx.clone()), false).unwrap();
        assert_eq!(no_change.clone().into_owned(), data);
        let bind = no_change.into_owned();
        let plain_text_no_change =
            decrypt_with_context(&bind, &obj, &Some(ctx.clone()), false).unwrap();
        assert_eq!(plain_text_no_change.into_owned(), data);

        // test normal encrypt and decrypt
        let encrypt_text = encrypt_with_context(data, &obj, &Some(ctx.clone()), true).unwrap();
        let bind = encrypt_text.into_owned();
        let plain_text = decrypt_with_context(&bind, &obj, &Some(ctx), true).unwrap();
        assert_eq!(&plain_text.into_owned(), data);
    }

    fn test_gen_key(convergent_encryption: bool) {
        let mut key = [0xcu8; 32];
        key[31] = 0xa;
        let iv = [0u8; 16];
        let data = b"11111111111111111";
        let ctx = CipherContext::new(
            key.to_vec(),
            iv.to_vec(),
            convergent_encryption,
            Algorithm::Aes128Xts,
        )
        .unwrap();
        let obj = Arc::new(Algorithm::Aes128Xts.new_cipher().unwrap());
        let (gen_key, gen_iv) = ctx.generate_cipher_meta(&key);
        let ciphertext = obj.encrypt(gen_key, Some(&gen_iv), data).unwrap();
        let plaintext = obj.decrypt(gen_key, Some(&gen_iv), &ciphertext).unwrap();
        assert_eq!(&plaintext, data);
    }

    #[test]
    fn test_generate_cipher_meta() {
        test_gen_key(true);
        test_gen_key(false);
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Known-answer tests pinning byte-for-byte compatibility with the previous OpenSSL
    /// implementation. The expected ciphertexts/tags were captured from OpenSSL 0.10.80
    /// (aes-128-xts / aes-256-xts / aes-256-gcm) for these exact key/iv/data inputs, so any
    /// divergence in the RustCrypto (aes/xts-mode/aes-gcm) output — tweak handling, ciphertext
    /// stealing, or GCM J0/tag derivation — fails here and prevents shipping an incompatible
    /// change that would make existing encrypted blobs undecryptable.
    #[test]
    fn test_openssl_known_answer_vectors() {
        let mut k128 = [0xcu8; 32];
        k128[31] = 0xa;
        let c = Algorithm::Aes128Xts.new_cipher().unwrap();
        // padded short input, exact block, and ciphertext-stealing (17B) cases.
        assert_eq!(
            c.encrypt(&k128, Some(&[0u8; 16]), b"1").unwrap().as_ref(),
            unhex("1df853e84717cce491f7bcb79c9edfb42ed2").as_slice()
        );
        assert_eq!(
            c.encrypt(&k128, Some(&[0u8; 16]), b"helloworldtest!!")
                .unwrap()
                .as_ref(),
            unhex("4a55f66681c93e363de843b3016c5ea1").as_slice()
        );
        assert_eq!(
            c.encrypt(&k128, Some(&[0u8; 16]), b"11111111111111111")
                .unwrap()
                .as_ref(),
            unhex("67a2d8fcc3beed670bb626feab5a03f295").as_slice()
        );
        assert_eq!(
            c.encrypt(&k128, Some(&[1u8; 16]), b"11111111111111111")
                .unwrap()
                .as_ref(),
            unhex("8c944448ca484c752ad2b850951cf3ed81").as_slice()
        );
        // old ciphertext must still decrypt to the original plaintext.
        assert_eq!(
            c.decrypt(
                &k128,
                Some(&[0u8; 16]),
                &unhex("67a2d8fcc3beed670bb626feab5a03f295")
            )
            .unwrap(),
            b"11111111111111111"
        );

        let mut k256 = [0xcu8; 64];
        k256[31] = 0xa;
        let c = Algorithm::Aes256Xts.new_cipher().unwrap();
        assert_eq!(
            c.encrypt(&k256, Some(&[0u8; 16]), b"1").unwrap().as_ref(),
            unhex("e27081f539a4bd9caa803848b553ff7bffd3").as_slice()
        );
        assert_eq!(
            c.encrypt(&k256, Some(&[0u8; 16]), b"11111111111111111")
                .unwrap()
                .as_ref(),
            unhex("34110f1b1bb3f5017c53c162ff1aa1dd17").as_slice()
        );

        let kg = [0xcu8; 32];
        let c = Algorithm::Aes256Gcm.new_cipher().unwrap();
        let mut tag = vec![0u8; 12];
        let ct = c
            .encrypt_aead(&kg, Some(&[0u8; 16]), b"11111111111111111", &mut tag)
            .unwrap();
        assert_eq!(
            ct.as_slice(),
            unhex("e31df8f1a318235602196b2472bceb58b9").as_slice()
        );
        assert_eq!(tag.as_slice(), unhex("c812164983ddf058f424c99e").as_slice());
        let pt = c.decrypt_aead(&kg, Some(&[0u8; 16]), &ct, &tag).unwrap();
        assert_eq!(pt, b"11111111111111111");
    }
}
