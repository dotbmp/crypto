# crypto
A crypto library for the Odin language

## Implemented cryptographic hash algorithms:

- [x] [BLAKE / BLAKE2](https://en.wikipedia.org/wiki/BLAKE_(hash_function))
- [x] [GOST](https://en.wikipedia.org/wiki/GOST_(hash_function)) 
- [x] [Grøstl](https://en.wikipedia.org/wiki/Gr%C3%B8stl)
- [x] [HAVAL](https://en.wikipedia.org/wiki/HAVAL)
- [ ] [KangarooTwelve](https://en.wikipedia.org/wiki/SHA-3#KangarooTwelve)
- [x] [MD2](https://en.wikipedia.org/wiki/MD2_(hash_function))
- [x] [MD4](https://en.wikipedia.org/wiki/MD4)
- [x] [MD5](https://en.wikipedia.org/wiki/MD5)
- [ ] [MD6](https://en.wikipedia.org/wiki/MD6)
- [x] [JH](https://en.wikipedia.org/wiki/JH_(hash_function))
- [x] [RIPEMD](https://en.wikipedia.org/wiki/RIPEMD)
- [x] [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
- [ ] [SHA-2](https://en.wikipedia.org/wiki/SHA-2)
- [x] [SHA-3 (Keccak)](https://en.wikipedia.org/wiki/SHA-3)
- [ ] [Skein](https://en.wikipedia.org/wiki/Skein_(hash_function))
- [x] [Streebog](https://en.wikipedia.org/wiki/Streebog)
- [x] [Tiger / Tiger2](https://en.wikipedia.org/wiki/Tiger_(hash_function))
- [x] [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool)
- [x] [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
#
## Implemented cryptographic encryption algorithms:

- [x] [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher))
- [ ] [Twofish](https://en.wikipedia.org/wiki/Twofish)
- [ ] [Threefish](https://en.wikipedia.org/wiki/Threefish)
- [ ] [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
- [ ] [AES / Rijndael ](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [x] [RC2](https://en.wikipedia.org/wiki/RC2)
- [x] [RC4](https://en.wikipedia.org/wiki/RC4)
- [x] [RC5](https://en.wikipedia.org/wiki/RC5)
- [x] [RC6](https://en.wikipedia.org/wiki/RC6)
- [ ] [MARS](https://en.wikipedia.org/wiki/MARS_(cipher))
- [x] [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher))

#
## Example useage

```go
package main

import "shared:crypto/md4"
import "shared:crypto/haval"

main :: proc() {
    md4_hash   := md4.hash(([]byte)("foo")); // MD4 only has a single output size
    haval_hash := haval.hash_3_256(([]byte)("bar")); // 3 rounds with output size of 256 bits
}
```
#
## API documentation


#
## Disclaimer