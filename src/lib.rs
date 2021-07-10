//! Encrypt and decrypt bitcoin private keys with bip-0038 standard.

// TODO: test working functions, implement fmt to 'Error'

use aes::Aes256;
use aes::cipher::{
    BlockDecrypt,
    BlockEncrypt,
    generic_array::GenericArray,
    NewBlockCipher
};
use rand::RngCore;
use ripemd160::Ripemd160;
use scrypt::Params;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Digest;
use unicode_normalization::UnicodeNormalization;

/// Number of bytes of a public key compressed.
const NBBY_PUBC: usize = 33;

/// Number of bytes of a public key uncompressed.
const NBBY_PUBU: usize = 65;

/// Prefix of all ec encrypted keys.
const PRE_EC: [u8; 2] = [0x01, 0x43];

/// Prefix of all non ec encrypted keys.
const PRE_NON_EC: [u8; 2] = [0x01, 0x42];

/// Errors of 'bip38' crate
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub enum Error {
    /// If an invalid base 58 string is processed.
    Base58,
    /// Invalid checksum was found.
    Check,
    /// Invalid result of elliptic curve multiplication.
    EcMul,
    /// Found invalid encrypted private key.
    EncKey,
    /// Invalid number of public key bytes.
    NbPubB,
    /// Found invalid passphrase.
    Passwd,
    /// Found invalid public key.
    PubKey,
    /// Trowed if an error occurs when using scrypt function.
    ScryptF,
    /// Trowed if an invalid scrypt Param is inserted.
    ScryptP,
    /// Invalid secret entropy found (could not generate address).
    SecEnt,
}

// TODO: show only public functions on documentation
/// Internal Functions to manipulate an arbitrary number of bytes [u8].
trait BytesManipulation {
    /// Encode informed data in base 58 check.
    fn encode_base58ck(&self) -> String;

    /// Sha256 and ripemd160 in sequence.
    fn hash160(&self) -> [u8; 20];

    /// Receives bytes and return 32 bytes of a dual sha256 hash.
    fn hash256(&self) -> [u8; 32];

    /// Create an p2wpkh address according length bytes of the public key.
    fn p2wpkh(&self) -> Result<String, Error>;
}

/// Public trait to allow decryption of encrypted private keys in srt format.
pub trait Decrypt {
    /// Decrypt an encrypted private key.
    /// TODO: example tests
    fn decrypt(&self, pass: &str) -> Result<([u8; 32], bool), Error>;
}

/// Public trait to allow encryption of private keys in [u8; 32] format.
pub trait Encrypt {
    /// Encrypt private key.
    /// TODO: example tests
    fn encrypt(
        &self,
        pass: &str,
        compress: bool
    ) -> Result<(String, Vec<u8>), Error>;

}

/// Internal trait to manipulate private keys (32 bytes).
trait PrivateKeyManipulation {
    /// Generate secp256k1 point based on target secret key.
    fn public(&self, compress: bool) -> Result<Vec<u8>, Error>;
}

/// Internal Functions to manipulate strings.
trait StringManipulation {
    /// Decode informed base 58 string into bytes (payload only).
    fn decode_base58ck(&self) -> Result<Vec<u8>, Error>;

    /// Decrypt encrypted private key with ec multiply mode.
    fn decrypt_ec(&self, pass: &str) -> Result<([u8; 32], bool), Error>;

    /// Decrypt a non-ec encrypted private key.
    fn decrypt_non_ec(&self, pass: &str) -> Result<([u8; 32], bool), Error>;
}

impl BytesManipulation for [u8] {
    #[inline]
    fn encode_base58ck(&self) -> String {
        let mut decoded: Vec<u8> = self.to_vec();
        decoded.append(&mut decoded.hash256()[..4].to_vec());
        bs58::encode(decoded).into_string()
    }

    #[inline]
    fn hash160(&self) -> [u8; 20] {
        let mut result = [0x00; 20];
        result[..].copy_from_slice(
            &Ripemd160::digest(&sha2::Sha256::digest(self))
        );
        result
    }

    #[inline]
    fn hash256(&self) -> [u8; 32] {
        let mut result = [0x00; 32];
        result[..].copy_from_slice(
            &sha2::Sha256::digest(&sha2::Sha256::digest(self))
        );
        result
    }

    #[inline]
    fn p2wpkh(&self) -> Result<String, Error> {
        if self.len() != NBBY_PUBC && self.len() != NBBY_PUBU {
            return Err(Error::NbPubB);
        }
        let mut address_bytes = vec![0x00];
        address_bytes.append(&mut self.hash160().to_vec());
        Ok(address_bytes.encode_base58ck())
    }
}

impl Decrypt for str {
    #[inline]
    fn decrypt(&self, pass: &str) -> Result<([u8; 32], bool), Error> {
        Ok(
            if self.decode_base58ck()?[..2] == PRE_NON_EC {
                self.decrypt_non_ec(pass)?
            } else if self.decode_base58ck()?[..2] == PRE_EC {
                self.decrypt_ec(pass)?
            } else {
                return Err(Error::EncKey);
            }
        )
    }
}

impl Encrypt for [u8; 32] {
    #[inline]
    fn encrypt(
        &self,
        pass: &str,
        compress: bool
    ) -> Result<(String, Vec<u8>), Error> {
        let pubk = self.public(compress)?;
        let address = pubk.p2wpkh()?;
        let checksum = &address.as_bytes().hash256()[..4];
        let mut scrypt_key = [0x00; 64];

        scrypt::scrypt(
            pass.nfc().collect::<String>().as_bytes(),
            checksum,
            &Params::new(14, 8, 8).map_err(|_| Error::ScryptP)?,
            &mut scrypt_key
        ).map_err(|_| Error::ScryptF)?;

        let mut half1 = [0x00; 32];
        half1[..].copy_from_slice(&scrypt_key[..32]);

        let cipher = Aes256::new(GenericArray::from_slice(&scrypt_key[32..]));

        for idx in 0..32 {
            half1[idx] ^= self[idx];
        }

        let mut part1 = GenericArray::clone_from_slice(&half1[..16]);
        let mut part2 = GenericArray::clone_from_slice(&half1[16..]);

        cipher.encrypt_block(&mut part1);
        cipher.encrypt_block(&mut part2);

        let mut buffer = [0x00; 39];
        buffer[..2].copy_from_slice(&PRE_NON_EC);
        buffer[2] = if compress { 0xe0 } else { 0xc0 };
        buffer[3..7].copy_from_slice(checksum);
        buffer[7..23].copy_from_slice(&part1);
        buffer[23..].copy_from_slice(&part2);

        Ok((buffer.encode_base58ck(), pubk))
    }
}

impl PrivateKeyManipulation for [u8; 32] {
    #[inline]
    fn public(&self, compress: bool) -> Result<Vec<u8>, Error> {
        let secp_pub = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(self).map_err(|_| Error::SecEnt)?
        );

        if compress {
            Ok(secp_pub.serialize().to_vec())
        } else {
            Ok(secp_pub.serialize_uncompressed().to_vec())
        }
    }
}

impl StringManipulation for str {
    #[inline]
    fn decode_base58ck(&self) -> Result<Vec<u8>, Error> {
        let raw = bs58::decode(self).into_vec().map_err(|_| Error::Base58)?;
        if raw[raw.len() - 4..] == raw[..raw.len() - 4].hash256()[..4] {
            Ok(raw[..(raw.len() - 4)].to_vec())
        } else { Err(Error::Check) }
    }

    #[inline]
    fn decrypt_ec(&self, pass: &str) -> Result<([u8; 32], bool), Error> {
        let eprvk = self.decode_base58ck()?;
        if eprvk[..2] != PRE_EC { return Err(Error::EncKey); }
        let address_hash = &eprvk[3..7];
        let encrypted_p1 = &eprvk[15..23];
        let encrypted_p2 = &eprvk[23..39];
        let flag_byte: u8 = eprvk[2];
        let compress = (flag_byte & 0x20) == 0x20;
        let has_lot = (flag_byte & 0x04) == 0x04;
        let owner_entropy = &eprvk[7..15];
        let owner_salt = &eprvk[7..15 - (flag_byte & 0x04) as usize];
        let mut pre_factor = [0x00; 32];
        let mut pass_factor = [0x00; 32];

        scrypt::scrypt(
            pass.nfc().collect::<String>().as_bytes(),
            owner_salt,
            &Params::new(14, 8, 8).map_err(|_| Error::ScryptP)?,
            &mut pre_factor
        ).map_err(|_| Error::ScryptF)?;

        if has_lot {
            let mut tmp: Vec<u8> = Vec::new();
            tmp.append(&mut pre_factor.to_vec());
            tmp.append(&mut owner_entropy.to_vec());
            pass_factor[..].copy_from_slice(&tmp.hash256());
        } else {
            pass_factor = pre_factor;
        }

        let pass_point = pass_factor.public(true)?;
        let mut seed_b_pass = [0x00; 64];

        scrypt::scrypt(
            &pass_point,
            &eprvk[3..15], // 1024 log2 = 10
            &Params::new(10, 1, 1).map_err(|_| Error::ScryptP)?,
            &mut seed_b_pass
        ).map_err(|_| Error::ScryptF)?;

        let derived_half1 = &seed_b_pass[..32];
        let derived_half2 = &seed_b_pass[32..];

        let cipher = Aes256::new(GenericArray::from_slice(derived_half2));

        let mut de_p2 = GenericArray::clone_from_slice(encrypted_p2);

        cipher.decrypt_block(&mut de_p2);

        for idx in 0..16 {
            de_p2[idx] ^= derived_half1[idx + 16];
        }

        let seed_b_part2 = &de_p2[8..];

        let mut tmp = [0x00; 16];
        tmp[..8].copy_from_slice(encrypted_p1);
        tmp[8..].copy_from_slice(&de_p2[..8]);

        let mut de_p1 = GenericArray::clone_from_slice(&tmp);

        cipher.decrypt_block(&mut de_p1);

        for idx in 0..16 {
            de_p1[idx] ^= derived_half1[idx];
        }

        let mut seed_b = [0x00; 24];
        seed_b[..16].copy_from_slice(&de_p1);
        seed_b[16..].copy_from_slice(seed_b_part2);

        let factor_b = seed_b.hash256();

        let mut prv = SecretKey::from_slice(&pass_factor)
            .map_err(|_| Error::SecEnt)?;

        prv.mul_assign(&factor_b).map_err(|_| Error::SecEnt)?;

        let mut result = [0x00; 32];
        result[..].copy_from_slice(&prv[..]);

        let address = result.public(compress)?.p2wpkh()?;
        let checksum = &address.as_bytes().hash256()[..4];

        if checksum != address_hash { return Err(Error::Passwd) }

        Ok((result, compress))
    }

    #[inline]
    fn decrypt_non_ec(&self, pass: &str) -> Result<([u8; 32], bool), Error> {
        let eprvk = self.decode_base58ck()?;
        if eprvk[..2] != PRE_NON_EC { return Err(Error::EncKey); }
        let compress = (eprvk[2] & 0x20) == 0x20;
        let mut scrypt_key = [0x00; 64];

        scrypt::scrypt(
            pass.nfc().collect::<String>().as_bytes(), // normalization
            &eprvk[3..7], // 16384 log2 = 14
            &Params::new(14, 8, 8).map_err(|_| Error::ScryptP)?,
            &mut scrypt_key
        ).map_err(|_| Error::ScryptF)?;

        let cipher = Aes256::new(GenericArray::from_slice(&scrypt_key[32..]));

        let mut derived_half1 = GenericArray::clone_from_slice(&eprvk[7..23]);
        let mut derived_half2 = GenericArray::clone_from_slice(&eprvk[23..39]);

        cipher.decrypt_block(&mut derived_half1);
        cipher.decrypt_block(&mut derived_half2);

        for idx in 0..16 {
            derived_half1[idx] ^= scrypt_key[idx];
            derived_half2[idx] ^= scrypt_key[idx + 16];
        }

        let mut prvk = [0x00; 32];
        prvk[..16].copy_from_slice(&derived_half1);
        prvk[16..].copy_from_slice(&derived_half2);

        let address = prvk.public(compress)?.p2wpkh()?;
        let checksum = &address.as_bytes().hash256()[..4];

        if checksum != &eprvk[3..7] { return Err(Error::Passwd) }

        Ok((prvk, compress))
    }
}

/// Encrypt private key based on passphrase with ec multiply.
/// TODO: example tests
pub fn encrypt_ec(
    pass: &str,
    compress: bool
) -> Result<(String, Vec<u8>), Error> {
    let mut owner_salt = [0x00; 8];
    let mut pass_factor = [0x00; 32];
    let mut seed_b = [0x00; 24];

    rand::thread_rng().fill_bytes(&mut owner_salt);

    scrypt::scrypt(
        pass.nfc().collect::<String>().as_bytes(),
        &owner_salt,
        &Params::new(14, 8, 8).map_err(|_| Error::ScryptP)?,
        &mut pass_factor
    ).map_err(|_| Error::ScryptF)?;

    let pass_point = pass_factor.public(true)?;

    let mut pass_point_mul = PublicKey::from_slice(&pass_point)
        .map_err(|_| Error::PubKey)?;

    rand::thread_rng().fill_bytes(&mut seed_b);

    let factor_b = seed_b.hash256();

    pass_point_mul.mul_assign(&Secp256k1::new(), &factor_b)
        .map_err(|_| Error::EcMul)?;

    let pubk: Vec<u8> = if compress {
        pass_point_mul.serialize().to_vec()
    } else {
        pass_point_mul.serialize_uncompressed().to_vec()
    };

    let address = pubk.p2wpkh()?;
    let address_hash = &address.as_bytes().hash256()[..4];
    let mut salt = [0x00; 12];
    let mut seed_b_pass = [0x00; 64];

    salt[..4].copy_from_slice(address_hash);
    salt[4..].copy_from_slice(&owner_salt);

    scrypt::scrypt(
        &pass_point,
        &salt,
        &Params::new(10, 1, 1).map_err(|_| Error::ScryptP)?,
        &mut seed_b_pass
    ).map_err(|_| Error::ScryptF)?;

    let derived_half1 = &seed_b_pass[..32];
    let derived_half2 = &seed_b_pass[32..];
    let en_p1 = &mut seed_b[..16];

    for idx in 0..16 {
        en_p1[idx] ^= derived_half1[idx];
    }

    let cipher = Aes256::new(GenericArray::from_slice(derived_half2));
    let mut encrypted_part1 = GenericArray::clone_from_slice(en_p1);

    cipher.encrypt_block(&mut encrypted_part1);

    let mut en_p2 = [0x00; 16];
    en_p2[..8].copy_from_slice(&encrypted_part1[8..]);
    en_p2[8..].copy_from_slice(&seed_b[16..]);

    for idx in 0..16 {
        en_p2[idx] ^= derived_half1[idx + 16];
    }

    let mut encrypted_part2 = GenericArray::clone_from_slice(&en_p2);

    cipher.encrypt_block(&mut encrypted_part2);

    let flag = if compress { 0x20 } else { 0x00 };

    let mut result_bytes = [0x00; 39];
    result_bytes[..2].copy_from_slice(&PRE_EC);
    result_bytes[2] = flag;
    result_bytes[3..7].copy_from_slice(address_hash);
    result_bytes[7..15].copy_from_slice(&owner_salt);
    result_bytes[15..23].copy_from_slice(&encrypted_part1[..8]);
    result_bytes[23..].copy_from_slice(&encrypted_part2);

    Ok((result_bytes.encode_base58ck(), pubk.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Encrypted secret keys obtained on test vectors of bip-0038.
    const TV_38_ENCRYPTED: [&str; 9] = [
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
        "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
        "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
        "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
        "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
        "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
        "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
        "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
        "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH"
    ];

    /// Resulting keys obtained in test vectors of bip-0038.
    const TV_38_KEY: [[u8; 32]; 9] = [
    [
        0xcb, 0xf4, 0xb9, 0xf7, 0x04, 0x70, 0x85, 0x6b, 0xb4, 0xf4, 0x0f, 0x80,
        0xb8, 0x7e, 0xdb, 0x90, 0x86, 0x59, 0x97, 0xff, 0xee, 0x6d, 0xf3, 0x15,
        0xab, 0x16, 0x6d, 0x71, 0x3a, 0xf4, 0x33, 0xa5
    ],
    [
        0x09, 0xc2, 0x68, 0x68, 0x80, 0x09, 0x5b, 0x1a, 0x4c, 0x24, 0x9e, 0xe3,
        0xac, 0x4e, 0xea, 0x8a, 0x01, 0x4f, 0x11, 0xe6, 0xf9, 0x86, 0xd0, 0xb5,
        0x02, 0x5a, 0xc1, 0xf3, 0x9a, 0xfb, 0xd9, 0xae
    ],
    [
        0x64, 0xee, 0xab, 0x5f, 0x9b, 0xe2, 0xa0, 0x1a, 0x83, 0x65, 0xa5, 0x79,
        0x51, 0x1e, 0xb3, 0x37, 0x3c, 0x87, 0xc4, 0x0d, 0xa6, 0xd2, 0xa2, 0x5f,
        0x05, 0xbd, 0xa6, 0x8f, 0xe0, 0x77, 0xb6, 0x6e
    ],
    [
        0xcb, 0xf4, 0xb9, 0xf7, 0x04, 0x70, 0x85, 0x6b, 0xb4, 0xf4, 0x0f, 0x80,
        0xb8, 0x7e, 0xdb, 0x90, 0x86, 0x59, 0x97, 0xff, 0xee, 0x6d, 0xf3, 0x15,
        0xab, 0x16, 0x6d, 0x71, 0x3a, 0xf4, 0x33, 0xa5
    ],
    [
        0x09, 0xc2, 0x68, 0x68, 0x80, 0x09, 0x5b, 0x1a, 0x4c, 0x24, 0x9e, 0xe3,
        0xac, 0x4e, 0xea, 0x8a, 0x01, 0x4f, 0x11, 0xe6, 0xf9, 0x86, 0xd0, 0xb5,
        0x02, 0x5a, 0xc1, 0xf3, 0x9a, 0xfb, 0xd9, 0xae
    ],
    [
        0xa4, 0x3a, 0x94, 0x05, 0x77, 0xf4, 0xe9, 0x7f, 0x5c, 0x4d, 0x39, 0xeb,
        0x14, 0xff, 0x08, 0x3a, 0x98, 0x18, 0x7c, 0x64, 0xea, 0x7c, 0x99, 0xef,
        0x7c, 0xe4, 0x60, 0x83, 0x39, 0x59, 0xa5, 0x19
    ],
    [
        0xc2, 0xc8, 0x03, 0x6d, 0xf2, 0x68, 0xf4, 0x98, 0x09, 0x93, 0x50, 0x71,
        0x8c, 0x4a, 0x3e, 0xf3, 0x98, 0x4d, 0x2b, 0xe8, 0x46, 0x18, 0xc2, 0x65,
        0x0f, 0x51, 0x71, 0xdc, 0xc5, 0xeb, 0x66, 0x0a
    ],
    [
        0x44, 0xea, 0x95, 0xaf, 0xbf, 0x13, 0x83, 0x56, 0xa0, 0x5e, 0xa3, 0x21,
        0x10, 0xdf, 0xd6, 0x27, 0x23, 0x2d, 0x0f, 0x29, 0x91, 0xad, 0x22, 0x11,
        0x87, 0xbe, 0x35, 0x6f, 0x19, 0xfa, 0x81, 0x90
    ],
    [
        0xca, 0x27, 0x59, 0xaa, 0x4a, 0xdb, 0x0f, 0x96, 0xc4, 0x14, 0xf3, 0x6a,
        0xbe, 0xb8, 0xdb, 0x59, 0x34, 0x29, 0x85, 0xbe, 0x9f, 0xa5, 0x0f, 0xaa,
        0xc2, 0x28, 0xc8, 0xe7, 0xd9, 0x0e, 0x30, 0x06
    ]];

    /// Passphrases obtained on test vectors of bip-0038.
    const TV_38_PASS: [&str; 9] = [
        "TestingOneTwoThree", "Satoshi",
        "\u{03d2}\u{0301}\u{0000}\u{010400}\u{01f4a9}", "TestingOneTwoThree",
        "Satoshi", "TestingOneTwoThree", "Satoshi", "MOLON LABE", "ΜΟΛΩΝ ΛΑΒΕ"
    ];

    /// First resulting wif key obtained in test vector of bip-0038.
    const TV_38_WIF: [&str; 9] = [
        "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
        "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
        "5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
        "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
        "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
        "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2",
        "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH",
        "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8",
        "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D"
    ];

    #[test]
    fn test_encode_base58ck() {
        assert_eq!("a".as_bytes().encode_base58ck(), "C2dGTwc");
        assert_eq!("abc".as_bytes().encode_base58ck(), "4h3c6RH52R");
    }

    #[test]
    fn test_hash160() {
        assert_eq!(
            "a".as_bytes().hash160(),
            [
                0x99, 0x43, 0x55, 0x19, 0x9e, 0x51, 0x6f, 0xf7, 0x6c, 0x4f,
                0xa4, 0xaa, 0xb3, 0x93, 0x37, 0xb9, 0xd8, 0x4c, 0xf1, 0x2b
            ]
        );
    }

    #[test]
    fn test_hash256() {
        assert_eq!(
            "a".as_bytes().hash256(),
            [
                0xbf, 0x5d, 0x3a, 0xff, 0xb7, 0x3e, 0xfd, 0x2e, 0xc6, 0xc3,
                0x6a, 0xd3, 0x11, 0x2d, 0xd9, 0x33, 0xef, 0xed, 0x63, 0xc4,
                0xe1, 0xcb, 0xff, 0xcf, 0xa8, 0x8e, 0x27, 0x59, 0xc1, 0x44,
                0xf2, 0xd8
            ]
        );
    }

}
