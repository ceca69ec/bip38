bip38
=====

**Rust implementation of [bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) to be used as a dependency (crate).**

## Functionalities

Encrypt and decrypt bitcoin private keys with [bip-0038](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard.

This crate treat bitcoin private as raw 32 bytes (`[u8; 32]`). Hexadecimal, wif or any other representation (excepting the resulting encrypted private keys) are out of scope of this implementation.

## Basic examples

Encryption:
```rust
use bip38::{Encrypt, Error};

// true => compress
assert_eq!(
    [0x11; 32].encrypt("strong_pass", true).unwrap(),
    "6PYMgbeR64ypE4g8ZQhGo7ScudV5BLz1vMFUCs49AWpW3jVNWfH6cAdTi2"
);

// false => uncompress
assert_eq!(
    [0x11; 32].encrypt("strong_pass", false).unwrap(),
    "6PRVo8whLAhpRwSM5tJfmbAbZ9mCxjyZExaTXt6EMSXw3f5QJxMDFQQND2"
);

// [0x00; 32] is an invalid private key and cannot generate a valid bitcoin address
assert_eq!([0x00; 32].encrypt("strong_pass", true), Err(Error::PrvKey));
assert_eq!([0x00; 32].encrypt("strong_pass", false), Err(Error::PrvKey));
```

Decryption:
```rust
use bip38::{Decrypt, Error};

assert_eq!(
    "6PYMgbeR64ypE4g8ZQhGo7ScudV5BLz1vMFUCs49AWpW3jVNWfH6cAdTi2".decrypt("strong_pass"),
    Ok(([0x11; 32], true)) // compress
);

assert_eq!(
    "6PRVo8whLAhpRwSM5tJfmbAbZ9mCxjyZExaTXt6EMSXw3f5QJxMDFQQND2".decrypt("strong_pass"),
    Ok(([0x11; 32], false)) // uncompress
);

assert_eq!(
    "6PRVo8whLAhpRwSM5tJfmbAbZ9mCxjyZExaTXt6EMSXw3f5QJxMDFQQND2".decrypt("wrong_pass"),
    Err(Error::Pass)
);
```

Generation (elliptic curve multiplication method, not deterministic):
```rust
use bip38::{Decrypt, Generate};

// true => compress
assert!("passphrase".generate(true).unwrap().decrypt("passphrase").is_ok());

// false => uncompress
assert!("passphrase".generate(false).unwrap().decrypt("passphrase").is_ok());
```

## Normalization

This crate handle the normalization (`nfc`) of the passphrase as specified on `bip-0038`.
```
use bip38::{Decrypt, Encrypt};

assert_eq!(
    [0xba; 32].encrypt("バンドメイド", true).unwrap().decrypt("バンドメイド").unwrap(),
    ([0xba; 32], true)
);
```

## Testing

Please always run `cargo test --release`. The encryption algorithm is, by design, heavy on cpu. Without the optimizations of a release build running tests can consume long time.

## Usage

You can use this crate in your project by adding the following to your `Cargo.toml`:

```toml
[dependencies]
bip38 = "1.0.0"
```

For more details and examples please see the [documentation](https://docs.rs/bip38)
