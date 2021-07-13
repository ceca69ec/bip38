//! Encrypt and decrypt bitcoin private keys with
//! [bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard.
//!
//! This crate treat bitcoin private keys as raw 32 bytes (`[u8; 32]`). Hexadecimal, wif or any
//! other representation (excepting the resulting encrypted private keys) are out of scope of this
//! implementation.
//!
//! # Basic examples
//!
//! #### Encryption
//! ```
//! use bip38::{Encrypt, Error};
//!
//! // true => compress
//! assert_eq!(
//!     [0x11; 32].encrypt("strong_pass", true).unwrap(),
//!     "6PYMgbeR64ypE4g8ZQhGo7ScudV5BLz1vMFUCs49AWpW3jVNWfH6cAdTi2"
//! );
//! // false => uncompress
//! assert_eq!(
//!     [0x11; 32].encrypt("strong_pass", false).unwrap(),
//!     "6PRVo8whLAhpRwSM5tJfmbAbZ9mCxjyZExaTXt6EMSXw3f5QJxMDFQQND2"
//! );
//! // [0x00; 32] is an invalid private key and cannot generate a valid bitcoin address
//! assert_eq!([0x00; 32].encrypt("strong_pass", true), Err(Error::PrvKey));
//! assert_eq!([0x00; 32].encrypt("strong_pass", false), Err(Error::PrvKey));
//! ```
//!
//! #### Decryption
//! ```
//! use bip38::{Decrypt, Error};
//!
//! assert_eq!(
//!     "6PYMgbeR64ypE4g8ZQhGo7ScudV5BLz1vMFUCs49AWpW3jVNWfH6cAdTi2".decrypt("strong_pass"),
//!     Ok(([0x11; 32], true)) // compress
//! );
//! assert_eq!(
//!     "6PRVo8whLAhpRwSM5tJfmbAbZ9mCxjyZExaTXt6EMSXw3f5QJxMDFQQND2".decrypt("strong_pass"),
//!     Ok(([0x11; 32], false)) // uncompress
//! );
//! assert_eq!(
//!     "6PRVo8whLAhpRwSM5tJfmbAbZ9mCxjyZExaTXt6EMSXw3f5QJxMDFQQND2".decrypt("wrong_pass"),
//!     Err(Error::Pass)
//! );
//! ```
//!
//! #### Generation (elliptic curve multiplication, not deterministic)
//! ```
//! use bip38::{Decrypt, Generate};
//!
//! // true => compress
//! assert!("passphrase".generate(true).unwrap().starts_with("6Pn"));
//!
//! // false => uncompress
//! assert!("passphrase".generate(false).unwrap().starts_with("6Pf"));
//!
//! // ぽー
//! assert!("バンドメイド".generate(true).unwrap().decrypt("バンドメイド").is_ok());
//! ```
//!
//! # Boolean flag
//!
//! * `true` always signify: use the public key of this private key `compressed` (33 bytes).
//! * `false` always signify: use the public key of this private key `uncompressed` (65 bytes).
//!
//! Obs: the use of uncompressed public keys is deprecated and discouraged. For new private keys
//! always choose the `true` flag.
//!
//! # Normalization
//!
//! This crate handle the normalization (`nfc`) of the passphrase as specified on `bip-0038`.
//! ```
//! use bip38::{Decrypt, Encrypt};
//!
//! assert_eq!(
//!     [0xba; 32].encrypt("ΜΟΛΩΝ ΛΑΒΕ", true).unwrap().decrypt("ΜΟΛΩΝ ΛΑΒΕ").unwrap(),
//!     ([0xba; 32], true)
//! );
//! ```
//!
//! # Testing
//!
//! Please always run `cargo test` with `--release` flag. Without the optimizations of a release
//! build running tests can consume long time (the encryption algorithm is, by design, heavy on
//! cpu).
//!
//! # Usage
//!
//! You can use this crate in your project by adding the following to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! bip38 = "1.0.0"
//! ```
//!
//! #### Decrypting
//! ```
//! use bip38::Decrypt;
//!
//! let user_ekey = String::from("6PnVMRLWZnQQGjLJPnzGnBM2hBwvT8padAsHToFXwhZBFQF1e6nckKXFG9");
//! let user_pass = String::from("ultra_secret_pass");
//!
//! let (private_key, compress) = user_ekey.decrypt(&user_pass).unwrap_or_else(|err| {
//!     eprintln!("{}", err); // in case of invalid passphrase or invalid encrypted private key
//!     std::process::exit(1);
//! });
//! ```
//!
//! #### Encrypting
//! ```
//! use bip38::Encrypt;
//!
//! let internal_prv_key = [0xd0; 32];
//! let user_pass = String::from("not_good_pass");
//!
//! let encrypted_prv_key = internal_prv_key.encrypt(&user_pass, true).unwrap_or_else(|err| {
//!     eprintln!("{}", err); // if the private key could not generate a valid bitcoin address
//!     std::process::exit(1);
//! });
//! ```
//!
//! #### Generating (elliptc curve multiplication)
//! ```
//! use bip38::Generate;
//!
//! let user_pass = String::from("a_good_pass_please");
//!
//! let encrypted_prv_key = user_pass.generate(false).unwrap_or_else(|err| {
//!     eprintln!("{}", err); // if the private key could not generate an address (a rare case)
//!     std::process::exit(1);
//! });
//! ```

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

/// Number of base58 characters on every encrypted private key.
const NBCH_EKEY: usize = 58;

/// Prefix of all ec encrypted keys.
const PRE_EC: [u8; 2] = [0x01, 0x43];

/// Prefix of all private keys encrypted with bip-0038 standard.
const PRE_EKEY: &str = "6P";

/// Prefix of all non ec encrypted keys.
const PRE_NON_EC: [u8; 2] = [0x01, 0x42];

/// Error variants of `bip38` crate.
///
/// The only errors that are intended to be handle are:
///
/// `Base58`, `Checksum`, `EncKey`, `Pass`, `PrvKey`.
///
/// All others exist for safety in case of something unexpected happens with dependencies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub enum Error {
    /// If an invalid base 58 string is processed.
    Base58,
    /// Invalid checksum was found.
    Checksum,
    /// Invalid result of elliptic curve multiplication.
    EcMul,
    /// Found invalid encrypted private key.
    EncKey,
    /// Invalid number of public key bytes.
    NbPubB,
    /// Found invalid passphrase.
    Pass,
    /// Invalid private key found (could not generate address).
    PrvKey,
    /// Found invalid public key.
    PubKey,
    /// Trowed if an error occurs when using `scrypt` function.
    ScryptFn,
    /// Trowed if an invalid `scrypt` parameter is used.
    ScryptParam,
}

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

/// Allow decryption of bitcoin encrypted private keys in `srt` format.
pub trait Decrypt {
    /// Decrypt an encrypted bitcoin private key in `str`format (both non-ec and ec).
    ///
    /// This function targets strings of 58 base58 characters with the version prefix `6P` and
    /// returns a tuple containing the decrypted private key (`[u8; 32]`) and a boolean indication
    /// of if this private key is intended to result in a compressed public key or not. So, if the
    /// flag is `true`, create an compressed public key (33 bytes), in case of `false`, use the full
    /// 65 bytes of the public key.
    ///
    /// # Examples
    ///
    ///
    /// ```
    /// use bip38::Decrypt;
    ///
    /// // decryption of non elliptic curve multiplication
    /// assert_eq!(
    ///     "6PYMgbeR6XCsX4yJx8E52vW4PJDoTiu1QeFLn81KoW6Shye5DZ4ZnDauno".decrypt("weakPass"),
    ///     Ok(([0x11; 32], true)) // indication to compress the public key of this private key
    /// );
    /// assert_eq!(
    ///     "6PRVo8whL3QbdrXpKk3gP2dGuxDbuvMsMqUq2imVigrm8oyRbvBoRUsbB3".decrypt("weakPass"),
    ///     Ok(([0x11; 32], false)) // indication do not compress the public key
    /// );
    ///
    /// // decryption of elliptic curve multiplication
    /// assert!(
    ///     "6PnPQGcDuPhCMmXzTebiryx8zHxr8PZvUJccSxarn9nLHVLX7yVj6Wcoj9".decrypt("weakPass").is_ok()
    /// );
    /// assert!(
    ///     "6PfVV4eYCodt6tRiHbHH356MX818xZvcN54oNd1rCr8Cbme3273xWAgBhx".decrypt("notWeak?").is_ok()
    /// );
    /// ```
    ///
    /// # Errors
    ///
    /// * `Error::Pass` is returned if an invalid passphrase is inserted.
    ///
    /// * `Error::EncKey` is returned if the target `str` is not an valid encrypted private key.
    ///
    /// * `Error::Checksum` is returned if the target `str` has valid encrypted private key format
    /// but invalid checksum.
    ///
    /// * `Error::Base58` is returned if an non `base58` character is found.
    ///
    /// ```
    /// use bip38::{Decrypt, Error};
    ///
    /// assert!(
    ///     "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq".decrypt("Satoshi").is_ok()
    /// );
    /// assert_eq!(
    ///     "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq".decrypt("Nakamoto"),
    ///     Err(Error::Pass)
    /// );
    /// assert_eq!(
    ///     "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByQ".decrypt("Satoshi"), // <- Q
    ///     Err(Error::Checksum)
    /// );
    /// assert_eq!(
    ///     "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWBy".decrypt("Satoshi"), // <- q?
    ///     Err(Error::EncKey)
    /// );
    /// assert_eq!(
    ///     "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWBy!".decrypt("Satoshi"), // <- !
    ///     Err(Error::Base58)
    /// );
    /// ```
    ///
    /// # Passphrase
    ///
    /// This function handle the normalization (`nfc`) of the passphrase as specified on `bip-0038`.
    /// ```
    /// use bip38::Decrypt;
    ///
    /// assert!(
    ///     "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn"
    ///         .decrypt("\u{03d2}\u{0301}\u{0000}\u{010400}\u{01f4a9}").is_ok()
    /// );
    /// ```
    fn decrypt(&self, pass: &str) -> Result<([u8; 32], bool), Error>;
}

/// Allow encryption of bitcoin private keys in `[u8; 32]` format.
pub trait Encrypt {
    /// Encrypt a bitcoin private key in the format of `[u8; 32]` (without elliptic curve
    /// multiplication) into a `String` of 58 base58 characters.
    ///
    /// When decrypting the boolean flag `compress` is just an indication, but here it influences on
    /// the resulting prefix of the encrypted private key and obviously on the indication when
    /// decrypting, but not in the private key itself.
    ///
    /// # Examples
    ///
    /// ```
    /// use bip38::Encrypt;
    ///
    /// assert_eq!(
    ///     [0x11; 32].encrypt("weakPass", true).unwrap(),
    ///     "6PYMgbeR6XCsX4yJx8E52vW4PJDoTiu1QeFLn81KoW6Shye5DZ4ZnDauno"
    /// );
    /// assert_eq!(
    ///     [0x11; 32].encrypt("weakPass", false).unwrap(),
    ///     "6PRVo8whL3QbdrXpKk3gP2dGuxDbuvMsMqUq2imVigrm8oyRbvBoRUsbB3"
    /// );
    /// ```
    ///
    /// # Errors
    ///
    /// The only case this function can fail by itself is if the provided private key could not
    /// result in a bitcoin address. All other errors are here for safety and are related to
    /// dependencies. This function don't `unwrap` internally to let the decision to do or not to
    /// the developer using the crate.
    ///
    /// ```
    /// use bip38::{Encrypt, Error};
    ///
    /// assert_eq!([0x00; 32].encrypt("oh_no!", true), Err(Error::PrvKey));
    /// assert_eq!([0xff; 32].encrypt("oh_no!", true), Err(Error::PrvKey));
    /// ```
    ///
    /// # Passphrase
    ///
    /// This function handle the normalization (`nfc`) of the passphrase as specified on `bip-0038`.
    /// ```
    /// use bip38::Encrypt;
    ///
    /// assert_eq!(
    ///     [
    ///         0x64, 0xee, 0xab, 0x5f, 0x9b, 0xe2, 0xa0, 0x1a, 0x83, 0x65, 0xa5, 0x79, 0x51, 0x1e,
    ///         0xb3, 0x37, 0x3c, 0x87, 0xc4, 0x0d, 0xa6, 0xd2, 0xa2, 0x5f, 0x05, 0xbd, 0xa6, 0x8f,
    ///         0xe0, 0x77, 0xb6, 0x6e
    ///     ].encrypt("\u{03d2}\u{0301}\u{0000}\u{010400}\u{01f4a9}", false).unwrap(),
    ///     "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn"
    /// );
    /// ```
    fn encrypt(&self, pass: &str, compress: bool) -> Result<String, Error>;
}

/// Allow generation of encrypted private keys using elliptic curve multiplication.
pub trait Generate {
    /// Create an encrypted private key in the form of a `String` of 58 base58 characters based on
    /// a passphrase (using elliptic curve multiplication and pseudo-random number generation).
    ///
    /// This function don't receives a private key, it's generated internally as specified in
    /// `bip-0038`. The target string is the passphrase to be used to decrypt. The resulting private
    /// key is only know if the encrypted private key is decrypted. So the result is, by design, not
    /// deterministic.
    ///
    /// When decrypting the boolean flag `compress` is just an indication, but here it influences on
    /// the resulting prefix of the encrypted private key and obviously on the indication when
    /// decrypting, but not in the private key itself.
    ///
    /// # Examples
    ///
    /// ```
    /// use bip38::{Decrypt, Generate};
    ///
    /// // true => compress
    /// assert!("hopefully_an_strong_passphrase".generate(true).unwrap().starts_with("6Pn"));
    ///
    /// // false => uncompress
    /// assert!("hopefully_an_strong_passphrase".generate(false).unwrap().starts_with("6Pf"));
    ///
    /// assert!("バンドメイド".generate(true).unwrap().decrypt("バンドメイド").is_ok());
    /// assert!("くるっぽー！".generate(false).unwrap().decrypt("くるっぽー！").is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// The only case this function can fail by itself is if the generated private key could not
    /// result in a bitcoin address. In this case the function results in `Error::PrvKey`. All other
    /// errors are here for safety and are related to dependencies. This function don't `unwrap`
    /// internally to let the decision to do or not to the developer using the crate.
    ///
    /// # Passphrase
    ///
    /// This function handle the normalization (`nfc`) of the passphrase as specified on `bip-0038`.
    /// ```
    /// use bip38::{Decrypt, Generate};
    ///
    /// assert!(
    ///     "\u{03d2}\u{0301}\u{0000}\u{010400}\u{01f4a9}".generate(true).unwrap()
    ///         .decrypt("\u{03d2}\u{0301}\u{0000}\u{010400}\u{01f4a9}").is_ok()
    /// );
    /// ```
    fn generate(&self, compress: bool) -> Result<String, Error>;
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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Base58 => write!(f, "invalid base58 string"),
            Error::Checksum => write!(f, "invalid checksum"),
            Error::EcMul => write!(f, "invalid elliptic curve multiplication"),
            Error::EncKey => write!(f, "invalid encrypted private key"),
            Error::NbPubB => write!(f, "invalid number of public key bytes"),
            Error::Pass => write!(f, "invalid passphrase"),
            Error::PrvKey => write!(f, "invalid private key"),
            Error::PubKey => write!(f, "invalid public key"),
            Error::ScryptFn => write!(f, "failure on scrypt function"),
            Error::ScryptParam => write!(f, "invalid scrypt parameter"),
        }
    }
}

impl BytesManipulation for [u8] {
    #[inline]
    fn encode_base58ck(&self) -> String {
        let mut decoded = self.to_vec();
        decoded.append(&mut decoded.hash256()[..4].to_vec());
        bs58::encode(decoded).into_string()
    }

    #[inline]
    fn hash160(&self) -> [u8; 20] {
        let mut result = [0x00; 20];
        result[..].copy_from_slice(&Ripemd160::digest(&sha2::Sha256::digest(self)));
        result
    }

    #[inline]
    fn hash256(&self) -> [u8; 32] {
        let mut result = [0x00; 32];
        result[..].copy_from_slice(&sha2::Sha256::digest(&sha2::Sha256::digest(self)));
        result
    }

    #[inline]
    fn p2wpkh(&self) -> Result<String, Error> {
        if self.len() != NBBY_PUBC && self.len() != NBBY_PUBU { return Err(Error::NbPubB); }
        let mut address_bytes = vec![0x00];
        address_bytes.append(&mut self.hash160().to_vec());
        Ok(address_bytes.encode_base58ck())
    }
}

impl Decrypt for str {
    #[inline]
    fn decrypt(&self, pass: &str) -> Result<([u8; 32], bool), Error> {
        Ok(
            if self.len() != NBCH_EKEY || (self.is_char_boundary(2) && &self[..2] != PRE_EKEY) {
                return Err(Error::EncKey);
            } else if self.decode_base58ck()?[..2] == PRE_NON_EC {
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
    fn encrypt(&self, pass: &str, compress: bool) -> Result<String, Error> {
        let address = self.public(compress)?.p2wpkh()?;
        let checksum = &address.as_bytes().hash256()[..4];
        let mut scrypt_key = [0x00; 64];

        scrypt::scrypt(
            pass.nfc().collect::<String>().as_bytes(),
            checksum,
            &Params::new(14, 8, 8).map_err(|_| Error::ScryptParam)?,
            &mut scrypt_key
        ).map_err(|_| Error::ScryptFn)?;

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

        Ok(buffer.encode_base58ck())
    }
}

impl Generate for str {
    #[inline]
    fn generate(&self, compress: bool) -> Result<String, Error> {
        let mut owner_salt = [0x00; 8];
        let mut pass_factor = [0x00; 32];
        let mut seed_b = [0x00; 24];

        rand::thread_rng().fill_bytes(&mut owner_salt);

        scrypt::scrypt(
            self.nfc().collect::<String>().as_bytes(),
            &owner_salt,
            &Params::new(14, 8, 8).map_err(|_| Error::ScryptParam)?,
            &mut pass_factor
        ).map_err(|_| Error::ScryptFn)?;

        let pass_point = pass_factor.public(true)?;

        let mut pass_point_mul = PublicKey::from_slice(&pass_point).map_err(|_| Error::PubKey)?;

        rand::thread_rng().fill_bytes(&mut seed_b);

        let factor_b = seed_b.hash256();

        pass_point_mul.mul_assign(&Secp256k1::new(), &factor_b).map_err(|_| Error::EcMul)?;

        let pubk = if compress {
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
            &Params::new(10, 1, 1).map_err(|_| Error::ScryptParam)?,
            &mut seed_b_pass
        ).map_err(|_| Error::ScryptFn)?;

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

        Ok(result_bytes.encode_base58ck())
    }
}

impl PrivateKeyManipulation for [u8; 32] {
    #[inline]
    fn public(&self, compress: bool) -> Result<Vec<u8>, Error> {
        let secp_pub = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(self).map_err(|_| Error::PrvKey)?
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
        } else {
            Err(Error::Checksum)
        }
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
            &Params::new(14, 8, 8).map_err(|_| Error::ScryptParam)?,
            &mut pre_factor
        ).map_err(|_| Error::ScryptFn)?;

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
            &Params::new(10, 1, 1).map_err(|_| Error::ScryptParam)?,
            &mut seed_b_pass
        ).map_err(|_| Error::ScryptFn)?;

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
            .map_err(|_| Error::PrvKey)?;

        prv.mul_assign(&factor_b).map_err(|_| Error::PrvKey)?;

        let mut result = [0x00; 32];
        result[..].copy_from_slice(&prv[..]);

        let address = result.public(compress)?.p2wpkh()?;
        let checksum = &address.as_bytes().hash256()[..4];

        if checksum != address_hash { return Err(Error::Pass) }

        Ok((result, compress))
    }

    #[inline]
    fn decrypt_non_ec(&self, pass: &str) -> Result<([u8; 32], bool), Error> {
        let eprvk = self.decode_base58ck()?;
        if eprvk[..2] != PRE_NON_EC { return Err(Error::EncKey); }
        let compress = (eprvk[2] & 0x20) == 0x20;
        let mut scrypt_key = [0x00; 64];

        scrypt::scrypt(
            pass.nfc().collect::<String>().as_bytes(),
            &eprvk[3..7], // 16384 log2 = 14
            &Params::new(14, 8, 8).map_err(|_| Error::ScryptParam)?,
            &mut scrypt_key
        ).map_err(|_| Error::ScryptFn)?;

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

        if checksum != &eprvk[3..7] { return Err(Error::Pass) }

        Ok((prvk, compress))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Encrypted secret keys obtained on test vectors of bip-0038.
    const TV_ENCRYPTED: [&str; 9] = [
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
    const TV_KEY: [[u8; 32]; 9] = [
        [
            0xcb, 0xf4, 0xb9, 0xf7, 0x04, 0x70, 0x85, 0x6b, 0xb4, 0xf4, 0x0f, 0x80, 0xb8, 0x7e,
            0xdb, 0x90, 0x86, 0x59, 0x97, 0xff, 0xee, 0x6d, 0xf3, 0x15, 0xab, 0x16, 0x6d, 0x71,
            0x3a, 0xf4, 0x33, 0xa5
        ],
        [
            0x09, 0xc2, 0x68, 0x68, 0x80, 0x09, 0x5b, 0x1a, 0x4c, 0x24, 0x9e, 0xe3, 0xac, 0x4e,
            0xea, 0x8a, 0x01, 0x4f, 0x11, 0xe6, 0xf9, 0x86, 0xd0, 0xb5, 0x02, 0x5a, 0xc1, 0xf3,
            0x9a, 0xfb, 0xd9, 0xae
        ],
        [
            0x64, 0xee, 0xab, 0x5f, 0x9b, 0xe2, 0xa0, 0x1a, 0x83, 0x65, 0xa5, 0x79, 0x51, 0x1e,
            0xb3, 0x37, 0x3c, 0x87, 0xc4, 0x0d, 0xa6, 0xd2, 0xa2, 0x5f, 0x05, 0xbd, 0xa6, 0x8f,
            0xe0, 0x77, 0xb6, 0x6e
        ],
        [
            0xcb, 0xf4, 0xb9, 0xf7, 0x04, 0x70, 0x85, 0x6b, 0xb4, 0xf4, 0x0f, 0x80, 0xb8, 0x7e,
            0xdb, 0x90, 0x86, 0x59, 0x97, 0xff, 0xee, 0x6d, 0xf3, 0x15, 0xab, 0x16, 0x6d, 0x71,
            0x3a, 0xf4, 0x33, 0xa5
        ],
        [
            0x09, 0xc2, 0x68, 0x68, 0x80, 0x09, 0x5b, 0x1a, 0x4c, 0x24, 0x9e, 0xe3, 0xac, 0x4e,
            0xea, 0x8a, 0x01, 0x4f, 0x11, 0xe6, 0xf9, 0x86, 0xd0, 0xb5, 0x02, 0x5a, 0xc1, 0xf3,
            0x9a, 0xfb, 0xd9, 0xae
        ],
        [
            0xa4, 0x3a, 0x94, 0x05, 0x77, 0xf4, 0xe9, 0x7f, 0x5c, 0x4d, 0x39, 0xeb, 0x14, 0xff,
            0x08, 0x3a, 0x98, 0x18, 0x7c, 0x64, 0xea, 0x7c, 0x99, 0xef, 0x7c, 0xe4, 0x60, 0x83,
            0x39, 0x59, 0xa5, 0x19
        ],
        [
            0xc2, 0xc8, 0x03, 0x6d, 0xf2, 0x68, 0xf4, 0x98, 0x09, 0x93, 0x50, 0x71, 0x8c, 0x4a,
            0x3e, 0xf3, 0x98, 0x4d, 0x2b, 0xe8, 0x46, 0x18, 0xc2, 0x65, 0x0f, 0x51, 0x71, 0xdc,
            0xc5, 0xeb, 0x66, 0x0a
        ],
        [
            0x44, 0xea, 0x95, 0xaf, 0xbf, 0x13, 0x83, 0x56, 0xa0, 0x5e, 0xa3, 0x21, 0x10, 0xdf,
            0xd6, 0x27, 0x23, 0x2d, 0x0f, 0x29, 0x91, 0xad, 0x22, 0x11, 0x87, 0xbe, 0x35, 0x6f,
            0x19, 0xfa, 0x81, 0x90
        ],
        [
            0xca, 0x27, 0x59, 0xaa, 0x4a, 0xdb, 0x0f, 0x96, 0xc4, 0x14, 0xf3, 0x6a, 0xbe, 0xb8,
            0xdb, 0x59, 0x34, 0x29, 0x85, 0xbe, 0x9f, 0xa5, 0x0f, 0xaa, 0xc2, 0x28, 0xc8, 0xe7,
            0xd9, 0x0e, 0x30, 0x06
        ]
    ];

    /// Passphrases obtained on test vectors of bip-0038.
    const TV_PASS: [&str; 9] = [
        "TestingOneTwoThree",
        "Satoshi",
        "\u{03d2}\u{0301}\u{0000}\u{010400}\u{01f4a9}",
        "TestingOneTwoThree",
        "Satoshi",
        "TestingOneTwoThree",
        "Satoshi",
        "MOLON LABE",
        "ΜΟΛΩΝ ΛΑΒΕ"
    ];

    #[test]
    fn test_decrypt() {
        let mut compress = false;
        for (idx, ekey) in TV_ENCRYPTED.iter().enumerate() {
            if idx > 2 { compress = true }
            if idx > 4 { compress = false }
            assert_eq!(ekey.decrypt(TV_PASS[idx]), Ok((TV_KEY[idx], compress)));
        }
        assert!(TV_ENCRYPTED[1].decrypt("Satoshi").is_ok());
        assert_eq!(TV_ENCRYPTED[1].decrypt("wrong"), Err(Error::Pass));
        assert_eq!(TV_ENCRYPTED[1].replace("X", "x").decrypt("Satoshi"), Err(Error::Checksum));
        assert_eq!(TV_ENCRYPTED[1][1..].decrypt("Satoshi"), Err(Error::EncKey));
    }

    #[test]
    fn test_encode_base58ck() {
        assert_eq!("a".as_bytes().encode_base58ck(), "C2dGTwc");
        assert_eq!("abc".as_bytes().encode_base58ck(), "4h3c6RH52R");
    }

    #[test]
    fn test_encrypt() {
        let mut compress = false;
        for (idx, key) in TV_KEY[..5].iter().enumerate() { // the last four are ec-multiply
            if idx > 2 { compress = true }
            assert_eq!(key.encrypt(TV_PASS[idx], compress).unwrap(), TV_ENCRYPTED[idx]);
        }
    }

    #[test]
    fn test_generate() {
        assert!("バンドメイド".generate(true).unwrap().decrypt("バンドメイド").is_ok());
        assert!("くるっぽー！".generate(false).unwrap() .decrypt("くるっぽー！").is_ok());
        assert_eq!(
            "something_really_dumb".generate(true).unwrap().decrypt("rocket_science"),
            Err(Error::Pass)
        );
        assert_eq!("a".generate(false).unwrap().decrypt("b"), Err(Error::Pass));
    }

    #[test]
    fn test_hash160() {
        assert_eq!(
            "a".as_bytes().hash160(),
            [
                0x99, 0x43, 0x55, 0x19, 0x9e, 0x51, 0x6f, 0xf7, 0x6c, 0x4f, 0xa4, 0xaa, 0xb3, 0x93,
                0x37, 0xb9, 0xd8, 0x4c, 0xf1, 0x2b
            ]
        );
    }

    #[test]
    fn test_hash256() {
        assert_eq!(
            "a".as_bytes().hash256(),
            [
                0xbf, 0x5d, 0x3a, 0xff, 0xb7, 0x3e, 0xfd, 0x2e, 0xc6, 0xc3, 0x6a, 0xd3, 0x11, 0x2d,
                0xd9, 0x33, 0xef, 0xed, 0x63, 0xc4, 0xe1, 0xcb, 0xff, 0xcf, 0xa8, 0x8e, 0x27, 0x59,
                0xc1, 0x44, 0xf2, 0xd8
            ]
        );
    }

    #[test]
    fn test_p2wpkh() {
        assert_eq!(
            [
                0x03, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9,
                0x61, 0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7,
                0x04, 0x07, 0x58, 0x71, 0xaa
            ].p2wpkh().unwrap(),
            "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9"
        );
        assert_eq!(
            [
                0x02, 0x66, 0x6b, 0xdf, 0x20, 0x25, 0xe3, 0x2f, 0x41, 0x08, 0x88, 0x99, 0xf2, 0xbc,
                0xb4, 0xbf, 0x69, 0x83, 0x18, 0x7f, 0x38, 0x0e, 0x72, 0xfc, 0x7d, 0xee, 0x11, 0x5b,
                0x1f, 0x99, 0x57, 0xcc, 0x72
            ].p2wpkh().unwrap(),
            "1N7qxowv8SnfdBYhmvpxZxyjsYQDPd88ES"
        );
        assert_eq!(
            [
                0x04, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9,
                0x61, 0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7,
                0x04, 0x07, 0x58, 0x71, 0xaa, 0x38, 0x5b, 0x6b, 0x1b, 0x8e, 0xad, 0x80, 0x9c, 0xa6,
                0x74, 0x54, 0xd9, 0x68, 0x3f, 0xcf, 0x2b, 0xa0, 0x34, 0x56, 0xd6, 0xfe, 0x2c, 0x4a,
                0xbe, 0x2b, 0x07, 0xf0, 0xfb, 0xdb, 0xb2, 0xf1, 0xc1
            ].p2wpkh().unwrap(),
            "1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a"
        );
        assert_eq!(
            [
                0x04, 0x66, 0x6b, 0xdf, 0x20, 0x25, 0xe3, 0x2f, 0x41, 0x08, 0x88, 0x99, 0xf2, 0xbc,
                0xb4, 0xbf, 0x69, 0x83, 0x18, 0x7f, 0x38, 0x0e, 0x72, 0xfc, 0x7d, 0xee, 0x11, 0x5b,
                0x1f, 0x99, 0x57, 0xcc, 0x72, 0x9d, 0xd9, 0x76, 0x13, 0x1c, 0x4c, 0x8e, 0x12, 0xab,
                0x10, 0x83, 0xca, 0x06, 0x54, 0xca, 0x5f, 0xdb, 0xca, 0xc8, 0xd3, 0x19, 0x8d, 0xaf,
                0x90, 0xf5, 0x81, 0xb5, 0x91, 0xd5, 0x63, 0x79, 0xca
            ].p2wpkh().unwrap(),
            "17iS4e5ib2t2Bj2UFjPbxSDdmecHNnCAwy"
        );
    }

    #[test]
    fn test_public() {
        assert_eq!(
            [0x11; 32].public(true).unwrap(),
            [
                0x03, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9,
                0x61, 0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7,
                0x04, 0x07, 0x58, 0x71, 0xaa
            ]
        );
        assert_eq!(
            [0x69; 32].public(true).unwrap(),
            [
                0x02, 0x66, 0x6b, 0xdf, 0x20, 0x25, 0xe3, 0x2f, 0x41, 0x08, 0x88, 0x99, 0xf2, 0xbc,
                0xb4, 0xbf, 0x69, 0x83, 0x18, 0x7f, 0x38, 0x0e, 0x72, 0xfc, 0x7d, 0xee, 0x11, 0x5b,
                0x1f, 0x99, 0x57, 0xcc, 0x72
            ]
        );
        assert_eq!(
            [0x11; 32].public(false).unwrap(),
            [
                0x04, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9,
                0x61, 0x5d, 0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7,
                0x04, 0x07, 0x58, 0x71, 0xaa, 0x38, 0x5b, 0x6b, 0x1b, 0x8e, 0xad, 0x80, 0x9c, 0xa6,
                0x74, 0x54, 0xd9, 0x68, 0x3f, 0xcf, 0x2b, 0xa0, 0x34, 0x56, 0xd6, 0xfe, 0x2c, 0x4a,
                0xbe, 0x2b, 0x07, 0xf0, 0xfb, 0xdb, 0xb2, 0xf1, 0xc1
            ]
        );
        assert_eq!(
            [0x69; 32].public(false).unwrap(),
            [
                0x04, 0x66, 0x6b, 0xdf, 0x20, 0x25, 0xe3, 0x2f, 0x41, 0x08, 0x88, 0x99, 0xf2, 0xbc,
                0xb4, 0xbf, 0x69, 0x83, 0x18, 0x7f, 0x38, 0x0e, 0x72, 0xfc, 0x7d, 0xee, 0x11, 0x5b,
                0x1f, 0x99, 0x57, 0xcc, 0x72, 0x9d, 0xd9, 0x76, 0x13, 0x1c, 0x4c, 0x8e, 0x12, 0xab,
                0x10, 0x83, 0xca, 0x06, 0x54, 0xca, 0x5f, 0xdb, 0xca, 0xc8, 0xd3, 0x19, 0x8d, 0xaf,
                0x90, 0xf5, 0x81, 0xb5, 0x91, 0xd5, 0x63, 0x79, 0xca
            ]
        );
    }
}
