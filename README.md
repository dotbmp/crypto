# crypto
A crypto library for the Odin language

#
## Hash algorithms:

- [x] [BLAKE / BLAKE2](https://en.wikipedia.org/wiki/BLAKE_(hash_function))
- [x] [GOST](https://en.wikipedia.org/wiki/GOST_(hash_function)) 
- [x] [Grøstl](https://en.wikipedia.org/wiki/Gr%C3%B8stl)
- [x] [HAVAL](https://en.wikipedia.org/wiki/HAVAL)
- [x] [MD2](https://en.wikipedia.org/wiki/MD2_(hash_function))
- [x] [MD4](https://en.wikipedia.org/wiki/MD4)
- [x] [MD5](https://en.wikipedia.org/wiki/MD5)
- [ ] [MD6](https://en.wikipedia.org/wiki/MD6)
- [x] [JH](https://en.wikipedia.org/wiki/JH_(hash_function))
- [x] [RIPEMD](https://en.wikipedia.org/wiki/RIPEMD)
- [x] [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
- [x] [SHA-2](https://en.wikipedia.org/wiki/SHA-2)
- [x] [SHA-3 (Keccak)](https://en.wikipedia.org/wiki/SHA-3)
- [ ] [Skein](https://en.wikipedia.org/wiki/Skein_(hash_function))
- [x] [Streebog](https://en.wikipedia.org/wiki/Streebog)
- [x] [Tiger / Tiger2](https://en.wikipedia.org/wiki/Tiger_(hash_function))
- [x] [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool)
- [x] [BCrypt](https://en.wikipedia.org/wiki/Bcrypt)
#
## Encryption algorithms:

- [x] [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher))
- [x] [Twofish](https://en.wikipedia.org/wiki/Twofish)
- [x] [Threefish](https://en.wikipedia.org/wiki/Threefish)
- [x] [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
- [x] [AES (Rijndael)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [x] [RC2](https://en.wikipedia.org/wiki/RC2)
- [x] [RC4](https://en.wikipedia.org/wiki/RC4)
- [x] [RC5](https://en.wikipedia.org/wiki/RC5)
- [x] [RC6](https://en.wikipedia.org/wiki/RC6)
- [ ] [MARS](https://en.wikipedia.org/wiki/MARS_(cipher))
- [x] [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher))
- [ ] [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [x] [Camellia](https://en.wikipedia.org/wiki/Camellia_(cipher))
- [ ] [Salsa20](https://en.wikipedia.org/wiki/Salsa20)
- [ ] [ChaCha](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant)
- [x] [IDEA](https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm)
#
## Message authentication codes:

- [ ] [Poly1305](https://en.wikipedia.org/wiki/Poly1305)
- [x] [HMAC](https://en.wikipedia.org/wiki/HMAC) ([MD5](https://en.wikipedia.org/wiki/MD5), [SHA-1](https://en.wikipedia.org/wiki/SHA-1), [SHA-2](https://en.wikipedia.org/wiki/SHA-2))
#
## Key derivation functions:

- [ ] [scrypt](https://en.wikipedia.org/wiki/scrypt)
- [ ] [Argon2](https://en.wikipedia.org/wiki/Argon2)
- [ ] [Catena]()
- [ ] [Lyra2]()
- [ ] [Makwa]()
- [ ] [yescrypt]()
- [X] [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)
#
## Key exchange algorithms:

- [ ] [SRP](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)
- [ ] [DH (Diffie-Hellman)](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [ ] [PSK](https://en.wikipedia.org/wiki/Pre-shared_key)


#
## Example useage

```odin
package main

import "crypto/md4"
import "crypto/haval"

main :: proc() {
    md4_hash   := md4.hash(transmute([]byte)("foo")); // MD4 only has a single output size
    haval_hash := haval.hash_3_256(transmute([]byte)("bar")); // 3 rounds with output size of 256 bits
}
```
#
## API

The API follows a couple simple ideas.
We try to have one call for each thing where possible. The idea behind it is to make using it very easy and simple, without needing to set up a lot or calling 3 procs just to get a hash.
Having said that, you can still call the procs however you want.

For the hash algorithms, the proc is almost always* called hash.
If there are different sizes of hashes, it is just hash followed by the size (e.g. hash_256, hash_512).
If the algorithm has additional parameters, like number of rounds that is added to the proc name as well.
(e.g. hash_3_256)

*One algorithm that does not follow this is the HMAC implementation, where the proc names are just the hash names themselves, since there is more than one HMAC implementation. Another example of this is BCrypt.

For the encryption algorithms the corresponding procs are called encrypt and decrypt, if there are various sizes or modes of operation the modes are added to the proc name. (e.g. encrypt_ecb, encrypt_cbc, triple_encrypt/decrypt in the case of Triple-DES)

API design regarding salting and file hashing is not yet done.
Ideally we want to have a single call for both and then just deal with whatever is put in accordingly and call the correct proc.

#
## Disclaimer

The algorithms were ported out of curiosity and due to interest in the field.
We have not had any of the code verified by a third party or tested/fuzzed by any automatic means.
Whereever we were able to find official test vectors, those were used to verify the implementation.
We do not recommend using them in a production environment, without any additional testing and/or verification

#
## Contributing

We welcome contributions in the form of implementations to not yet added algorithms, improvements to existing ones and of their respective test cases. Please adhere to the provided API design where possible.