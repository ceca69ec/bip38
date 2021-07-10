//! Encrypt and decrypt bitcoin private keys with bip-0038 standard.

// TODO: make non-ec de/encryption works; test working functions

/// Functions to manipulate private keys (32 bytes).
pub trait PrivateKeyManipulation {
    /// Encrypt private key.
    /// TODO: example tests
    pub fn encrypt(
        &self,
        pass: &str,
        compress: bool
    ) -> Result<(String, Vec<u8>), Error>;
}

/// Functions to manipulate strings.
pub trait StringManipulation {
    /// Decrypt an encrypted private key.
    /// TODO: example tests
    pub fn decrypt(&self, pass: &str) -> Result<([u8; 32], bool), Error>;
}

impl PrivateKeyManipulation for [u8; 32] {
    #[inline]
    pub fn encrypt(
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

impl StringManipulation for str {
    #[inline]
    pub fn decrypt(&self, pass: &str) -> Result<([u8; 32], bool), Error> {
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

#[cfg(test)]
mod tests {
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
}
