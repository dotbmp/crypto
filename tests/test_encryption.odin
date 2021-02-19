package test_encryption

import "core:fmt"
import "../crypto/blowfish"
import "../crypto/twofish"
import "../crypto/threefish"
import "../crypto/rc2"
import "../crypto/rc4"
import "../crypto/rc5"
import "../crypto/rc6"
import "../crypto/serpent"
import "../crypto/bcrypt"
import "../crypto/des"
import "../crypto/camellia"
import "../crypto/idea"
import "../crypto/aes"

u64_le :: inline proc "contextless"(b: []byte) -> u64 {
	return u64(b[0]) | u64(b[1]) << 8 | u64(b[2]) << 16 | u64(b[3]) << 24 |
	       u64(b[4]) << 32 | u64(b[5]) << 40 | u64(b[6]) << 48 | u64(b[7]) << 56;
}

put_u64_le :: inline proc "contextless"(b: []byte, v: u64) {
    b[0] = byte(v);
    b[1] = byte(v >> 8);
    b[2] = byte(v >> 16);
    b[3] = byte(v >> 24);
    b[4] = byte(v >> 32);
    b[5] = byte(v >> 40);
    b[6] = byte(v >> 48);
    b[7] = byte(v >> 56);
}

hex_string :: proc(bytes: []byte, allocator := context.temp_allocator) -> string {
    lut: [16]byte = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    buf := make([]byte, len(bytes)*2, allocator);
    for i: i32 = 0; i < i32(len(bytes)); i += 1 {
        buf[i*2+0] = lut[bytes[i] >> 4 & 0xF];
        buf[i*2+1] = lut[bytes[i]      & 0xF];
    }
    return string(buf);
}

hex_bytes :: proc(str: string, allocator := context.temp_allocator) -> []byte {
    buf := make([]byte, len(str)/2, allocator);
    for i: i32 = 0; i < i32(len(buf)); i += 1 {
        c1 := str[i*2+0];
        c2 := str[i*2+1];
        switch {
        case c1 >= '0' && c1 <= '9': buf[i] = c1 - '0';
        case c1 >= 'A' && c1 <= 'F': buf[i] = c1 - 'A' + 10;
        case c1 >= 'a' && c1 <= 'f': buf[i] = c1 - 'a' + 10;
        }
        buf[i] <<= 4;
        switch {
        case c2 >= '0' && c2 <= '9': buf[i] |= c2 - '0';
        case c2 >= 'A' && c2 <= 'F': buf[i] |= c2 - 'A' + 10;
        case c2 >= 'a' && c2 <= 'f': buf[i] |= c2 - 'a' + 10;
        }
    }
    return buf;
}

main :: proc() {
    test_aes_ecb();
    test_aes_cbc();
    test_blowfish();
    test_twofish();
    test_threefish();
    test_rc2();
    test_rc4();
    test_rc5();
    test_rc6();
    test_serpent();
    test_des();
    test_3des();
    test_camellia();
    test_bcrypt();
    test_idea();
}

print_test_result :: proc(algo: string, passed: bool) {
    if passed do fmt.printf(" === Tests for %s passed ===\n", algo);
    else      do fmt.printf(" === Tests for %s failed ===\n", algo);   
}

test_aes_ecb :: proc() {
    ctx: aes.Aes256;

    plaintext  := [16]byte{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    ciphertext := [16]byte{0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8};
    key        := [32]byte{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};

    cipher := aes.encrypt_ecb(&ctx, key[:], plaintext[:]);
    clear  := aes.decrypt_ecb(&ctx, cipher[:]);
    
    for v, i in cipher {
        if v != ciphertext[i] {
            print_test_result("AES ECB", false);
            return;
        }
    }
    for v, i in clear {
        if v != plaintext[i] {
            print_test_result("AES ECB", false);
            return;
        }
    }
    print_test_result("AES ECB", true);
}

test_aes_cbc :: proc() {
    ctx: aes.Aes256;

    plaintext  := [32]byte{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    ciphertext := [32]byte{0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d};
    key        := [32]byte{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    iv         := [16]byte{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

    cipher := aes.encrypt_cbc(&ctx, key[:], plaintext[:], iv[:]);
    clear  := aes.decrypt_cbc(&ctx, cipher[:], iv[:]);

    for i := 0; i < len(cipher); i += 1 {
        if cipher[i] != ciphertext[i] {
            print_test_result("AES CBC", false);
            return;
        }
    }
    for i := 0; i < len(clear); i += 1 {
        if clear[i] != plaintext[i] {
            print_test_result("AES CBC", false);
            return;
        }
    }
    print_test_result("AES CBC", true);
}

test_blowfish :: proc() {
    ctx: blowfish.Ctx;
    input: [8]byte = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    key: [8]byte = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    cipher := blowfish.encrypt_ecb(&ctx, input[:], key[:]);
    clear: [8]byte;
    blowfish.decrypt_ecb(&ctx, clear[:], cipher[:]);
    if hex_string(cipher[:]) == "4ef997456198dd78" && hex_string(clear[:]) == "0000000000000000" {
        print_test_result("Blowfish", true);
    } 
    else {
        print_test_result("Blowfish", false);
    }
}

test_rc2 :: proc() {
    key := hex_bytes("88bca90e90875a7f0f79c384627bafb2");
    plaintext := hex_bytes("0000000000000000");
    expected_cipher := "2269552ab0f85ca6";

    cipherbytes := rc2.encrypt(key, plaintext);
    ciphertext := hex_string(cipherbytes[:]);

    if !(expected_cipher == ciphertext) {
        print_test_result("RC2", false);
        return;
    }

    plain := rc2.decrypt(key, hex_bytes(ciphertext));

    if hex_string(plain[:]) != hex_string(plaintext) {
        print_test_result("RC2", false);
        return;
    }

    print_test_result("RC2", true);
}

test_rc4 :: proc() {
    key := "123456";
    plaintext := "hello";
    expected_cipher: [5]byte = {0x68, 0x9d, 0x12, 0xb, 0x4b};

    ciphertext := rc4.encrypt(transmute([]byte)(key), transmute([]byte)(plaintext));

    for i := 0; i < len(plaintext); i += 1 {
        if !(expected_cipher[i] == ciphertext[i]) {
            print_test_result("RC4", false);
            return;
        }
    }

    plain := rc4.decrypt(transmute([]byte)(key), transmute([]byte)(ciphertext));

    if string(plain) != plaintext {
        print_test_result("RC4", false);
        return;
    }

    print_test_result("RC4", true);
}

test_rc5 :: proc() {
    key: [16]byte = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    plaintext: [8]byte = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    expected_cipher: [8]byte = {0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E};

    ciphertext := rc5.encrypt(key[:], plaintext[:]);

    for i := 0; i < len(plaintext); i += 1 {
        if !(expected_cipher[i] == ciphertext[i]) {
            print_test_result("RC5", false);
            return;
        }
    }

    plain := rc5.decrypt(key[:], ciphertext);

    for i := 0; i < len(ciphertext); i += 1 {
        if !(plaintext[i] == plain[i]) {
            print_test_result("RC5", false);
            return;
        }
    }

    print_test_result("RC5", true);
}

test_rc6 :: proc() {
    key: [16]byte = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    plaintext: [16]byte = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    expected_cipher: [16]byte = {0x09, 0xC2, 0x61, 0x43, 0xB4, 0x7B, 0x1A, 0x22, 0xEC, 0x2D, 0x9C, 0xD8, 0xB8, 0xA4, 0xE5, 0x73};

    ciphertext := rc6.encrypt(key[:], plaintext[:]);

    for i := 0; i < len(plaintext); i += 1 {
        if !(expected_cipher[i] == ciphertext[i]) {
            print_test_result("RC6", false);
            return;
        }
    }

    plain := rc6.decrypt(key[:], ciphertext);

    for i := 0; i < len(ciphertext); i += 1 {
        if !(plaintext[i] == plain[i]) {
            print_test_result("RC6", false);
            return;
        }
    }

    print_test_result("RC6", true);
}

TestVector :: struct {
    key: string,
    plaintext: string,
    ciphertext: string,
}

test_serpent :: proc() {
    // NOTE(zh): Official test vectors for serpent from:
    // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors
    // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors
    // http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors

    test_vectors := [?]TestVector {
        TestVector{"80000000000000000000000000000000", "00000000000000000000000000000000", "264e5481eff42a4606abda06c0bfda3d"},
        TestVector{"40000000000000000000000000000000", "00000000000000000000000000000000", "4a231b3bc727993407ac6ec8350e8524"},
        TestVector{"800000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "9e274ead9b737bb21efcfca548602689"},
        TestVector{"100000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "bec1e37824cf721e5d87f6cb4ebfb9be"},
        TestVector{"0101010101010101010101010101010101010101010101010101010101010101", "01010101010101010101010101010101", "ec9723b15b2a6489f84c4524fffc2748"},
        TestVector{"0202020202020202020202020202020202020202020202020202020202020202", "02020202020202020202020202020202", "1187f485538514476184e567da0421c7"},
    };

    for v in test_vectors {
        cipher := serpent.encrypt(hex_bytes(v.key), hex_bytes(v.plaintext));

        if v.ciphertext != hex_string(cipher) {
            print_test_result("Serpent", false);
            return;
        }

        plain := serpent.decrypt(hex_bytes(v.key), cipher);

        if v.plaintext != hex_string(plain) {
            print_test_result("Serpent", false);
            return;
        }
    }

    print_test_result("Serpent", true);
}

test_bcrypt :: proc() {
    wanted   := "$2a$12$z9uZoru19BABKmM/gniuTe3dMJshKgrpMyeL/U277cMuGYO/q/MFi";
    salt     := "$2a$12$z9uZoru19BABKmM/gniuTe";
    password := "123";
    hash     := bcrypt.hash_pw(password, salt);
    
    passed   := true;

    if wanted != hash do passed = false;
    if !bcrypt.check_pw(wanted, password) do passed = false;
    
    print_test_result("BCrypt", passed);
}

test_des :: proc() {
    key := [8]byte {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
	schedule : [16][6]byte;
	plaintext := [8]byte {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xE7};
	expected_cipher := [8]byte {0xc9,0x57,0x44,0x25,0x6a,0x5e,0xd3,0x1d};

	ciphertext := des.encrypt(plaintext[:], key[:], schedule[:]);
    defer delete(ciphertext);

    for i := 0; i < len(plaintext); i += 1 {
        if !(expected_cipher[i] == ciphertext[i]) {
            print_test_result("DES", false);
            return;
        }
    }

    plain := des.decrypt(ciphertext[:], key[:], schedule[:]);
    defer delete(plain);

    for i := 0; i < len(ciphertext); i += 1 {
        if !(plaintext[i] == plain[i]) {
            print_test_result("DES", false);
            return;
        }
    }

    print_test_result("DES", true);
}

test_3des :: proc() {
    key3 := [24]byte {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
	                  0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
	                  0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    schedule3 : [3][16][6]byte;
    plaintext := [8]byte {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xE7};
    expected_cipher := [8]byte {0xc9,0x57,0x44,0x25,0x6a,0x5e,0xd3,0x1d};
	
	ciphertext := des.triple_encrypt(plaintext[:], key3[:], schedule3[:]);
    defer delete(ciphertext);

    for i := 0; i < len(plaintext); i += 1 {
        if !(expected_cipher[i] == ciphertext[i]) {
            print_test_result("3DES", false);
            return;
        }
    }

    plain := des.triple_decrypt(ciphertext[:], key3[:], schedule3[:]);
    defer delete(plain);

    for i := 0; i < len(ciphertext); i += 1 {
        if !(plaintext[i] == plain[i]) {
            print_test_result("3DES", false);
            return;
        }
    }

    print_test_result("3DES", true);
}

test_twofish :: proc() {
    TestTwoFish :: struct {
        key: []byte,
        dec: []byte,
        enc: []byte,
    };

    test_vectors := [?]TestTwoFish {
        {
            []byte{0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A},
            []byte{0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E, 0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19},
            []byte{0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85, 0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3},
        },
        {
            []byte{0x88, 0xB2, 0xB2, 0x70, 0x6B, 0x10, 0x5E, 0x36, 0xB4, 0x46, 0xBB, 0x6D, 0x73, 0x1A, 0x1E, 0x88,
                0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44},
            []byte{0x39, 0xDA, 0x69, 0xD6, 0xBA, 0x49, 0x97, 0xD5, 0x85, 0xB6, 0xDC, 0x07, 0x3C, 0xA3, 0x41, 0xB2},
            []byte{0x18, 0x2B, 0x02, 0xD8, 0x14, 0x97, 0xEA, 0x45, 0xF9, 0xDA, 0xAC, 0xDC, 0x29, 0x19, 0x3A, 0x65},
        },
        {
            []byte{0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46, 0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
                0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B, 0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F},
            []byte{0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F, 0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6},
            []byte{0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97, 0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA},
        },
        {
            []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            []byte{0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            },
            []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            []byte{0xCF, 0xD1, 0xD2, 0xE5, 0xA9, 0xBE, 0x9C, 0xDF, 0x50, 0x1F, 0x13, 0xB8, 0x92, 0xBD, 0x22, 0x48},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            },
            []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            []byte{0x37, 0x52, 0x7B, 0xE0, 0x05, 0x23, 0x34, 0xB8, 0x9F, 0x0C, 0xFC, 0xCA, 0xE8, 0x7C, 0xFA, 0x20},
        },
    };

    for v in test_vectors {
        ciphertext := twofish.encrypt(v.key[:], v.dec[:]);
        plaintext := twofish.decrypt(v.key[:], ciphertext[:]);

        for w, i in ciphertext {
            if w != v.enc[i] {
                print_test_result("Twofish", false);
                return;
            }
        }

        for w, i in plaintext {
            if w != v.dec[i] {
                print_test_result("Twofish", false);
                return;
            }
        }
    }

    print_test_result("Twofish", true);
}

test_threefish :: proc() {
    // ########## 256 ##########
    data256 := [?]u64{0, 0, 0, 0};
    key256 := [?]u64{0, 0, 0, 0};
    tweak256 := [?]u64{0, 0};
    res256 :=  [?]u64{0x94EEEA8B1F2ADA84, 0xADF103313EAE6670,
    0x952419A1F4B16D53, 0xD83F13E63C9F6B11};

    databytes256 := make([]byte, 32);
    keybytes256 := make([]byte, 32);
    resbytes256 := make([]byte, 32);

    for i in 0..<4 {
        put_u64_le(keybytes256[i*8:i*8+8], key256[i]);
        put_u64_le(databytes256[i*8:i*8+8], data256[i]);
        put_u64_le(resbytes256[i*8:i*8+8], res256[i]);
    }

    enc256 := threefish.encrypt_256(databytes256[:], keybytes256[:], tweak256[:]);
    dec256 := threefish.decrypt_256(enc256[:], keybytes256[:], tweak256[:]);

    for i := 0; i < len(enc256); i += 1 {
        if enc256[i] != resbytes256[i] || dec256[i] != databytes256[i] {
            print_test_result("Threefish256", false);
            return;
        }
    }

    // ########## 512 ##########
    data512 := [?]u64{0, 0, 0, 0, 0, 0, 0, 0};
    key512 := [?]u64{0, 0, 0, 0, 0, 0, 0, 0};
    tweak512 := [?]u64{0, 0};
    res512 :=  [?]u64{0xBC2560EFC6BBA2B1, 0xE3361F162238EB40,
    0xFB8631EE0ABBD175, 0x7B9479D4C5479ED1, 0xCFF0356E58F8C27B,
    0xB1B7B08430F0E7F7, 0xE9A380A56139ABF1, 0xBE7B6D4AA11EB47E};

    databytes512 := make([]byte, 64);
    keybytes512 := make([]byte, 64);
    resbytes512 := make([]byte, 64);

    for i in 0..<8 {
        put_u64_le(keybytes512[i*8:i*8+8], key512[i]);
        put_u64_le(databytes512[i*8:i*8+8], data512[i]);
        put_u64_le(resbytes512[i*8:i*8+8], res512[i]);
    }

    enc512 := threefish.encrypt_512(databytes512[:], keybytes512[:], tweak512[:]);
    dec512 := threefish.decrypt_512(enc512[:], keybytes512[:], tweak512[:]);

    for i := 0; i < len(enc512); i += 1 {
        if enc512[i] != resbytes512[i] || dec512[i] != databytes512[i] {
            print_test_result("Threefish512", false);
            return;
        }
    }

    // ########## 1024 ##########
    data1024 := [?]u64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    key1024 := [?]u64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    tweak1024 := [?]u64{0, 0};
    res1024 :=  [?]u64{0x04B3053D0A3D5CF0, 0x0136E0D1C7DD85F7,
    0x067B212F6EA78A5C, 0x0DA9C10B4C54E1C6, 0x0F4EC27394CBACF0,
    0x32437F0568EA4FD5, 0xCFF56D1D7654B49C, 0xA2D5FB14369B2E7B,
    0x540306B460472E0B, 0x71C18254BCEA820D, 0xC36B4068BEAF32C8,
    0xFA4329597A360095, 0xC4A36C28434A5B9A, 0xD54331444B1046CF,
    0xDF11834830B2A460, 0x1E39E8DFE1F7EE4F};

    databytes1024 := make([]byte, 128);
    keybytes1024 := make([]byte, 128);
    resbytes1024 := make([]byte, 128);

    for i in 0..<16 {
        put_u64_le(keybytes1024[i*8:i*8+8], key1024[i]);
        put_u64_le(databytes1024[i*8:i*8+8], data1024[i]);
        put_u64_le(resbytes1024[i*8:i*8+8], res1024[i]);
    }

    enc1024 := threefish.encrypt_1024(databytes1024[:], keybytes1024[:], tweak1024[:]);
    dec1024 := threefish.decrypt_1024(enc1024[:], keybytes1024[:], tweak1024[:]);

    for i := 0; i < len(enc1024); i += 1 {
        if enc1024[i] != resbytes1024[i] || dec1024[i] != databytes1024[i] {
            print_test_result("Threefish1024", false);
            return;
        }
    }

    print_test_result("Threefish", true);
}

test_camellia :: proc() {
    test_vectors := [?]TestVector {
        TestVector{"0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"},
        TestVector{"0123456789abcdeffedcba98765432100011223344556677", "0123456789abcdeffedcba9876543210", "b4993401b3e996f84ee5cee7d79b09b9"},
        TestVector{"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "0123456789abcdeffedcba9876543210", "9acc237dff16d76c20ef7c919e3a7509"},
    };
	
	for v in test_vectors {
        cipher := camellia.encrypt(hex_bytes(v.key), hex_bytes(v.plaintext));
        if v.ciphertext != hex_string(cipher) {
            print_test_result("Camellia", false);
            return;
        }
        
        plain := camellia.decrypt(hex_bytes(v.key), cipher);

        if v.plaintext != hex_string(plain) {
            print_test_result("Camellia", false);
            return;
        }

        delete(cipher);
    }

    print_test_result("Camellia", true);
}

test_idea :: proc() {
    TestIdea :: struct {
        key: [16]byte,
        plaintext: [8]byte,
        ciphertext: [8]byte,
    };
    key1 := [?]byte{0x72, 0x9a, 0x27, 0xed, 0x8f, 0x5c, 0x3e, 0x8b, 0xaf, 0x16, 0x56, 0x0d, 0x14, 0xc9, 0x0b, 0x43};
    key2 := [?]byte{0x00, 0x00, 0x27, 0xed, 0x8f, 0x5c, 0x3e, 0x8b, 0xaf, 0x16, 0x56, 0x0d, 0x14, 0xc9, 0x0b, 0x43};

    tests := [?]TestIdea {
        TestIdea{key1, {0xD5, 0x3F, 0xAB, 0xBF, 0x94, 0xFF, 0x8B, 0x5F}, {0x1d, 0x0c, 0xb2, 0xaf, 0x16, 0x54, 0x82, 0x0a}},
        TestIdea{key1, {0x84, 0x8F, 0x83, 0x67, 0x80, 0x93, 0x81, 0x69}, {0xD7, 0xE0, 0x46, 0x82, 0x26, 0xD0, 0xFC, 0x56}},
        TestIdea{key1, {0x81, 0x94, 0x40, 0xCA, 0x20, 0x65, 0xD1, 0x12}, {0x26, 0x4A, 0x8B, 0xBA, 0x66, 0x95, 0x90, 0x75}},
        TestIdea{key1, {0x68, 0x89, 0xF5, 0x64, 0x7A, 0xB2, 0x3D, 0x59}, {0xF9, 0x63, 0x46, 0x8B, 0x52, 0xF4, 0x5D, 0x4D}},
        TestIdea{key1, {0xDF, 0x8C, 0x6F, 0xC6, 0x37, 0xE3, 0xDA, 0xD1}, {0x29, 0x35, 0x8C, 0xC6, 0xC8, 0x38, 0x28, 0xAE}},
        TestIdea{key1, {0xAC, 0x48, 0x56, 0x24, 0x2B, 0x12, 0x15, 0x89}, {0x95, 0xCD, 0x92, 0xF4, 0x4B, 0xAC, 0xB7, 0x2D}},
        TestIdea{key1, {0xCB, 0xE4, 0x65, 0xF2, 0x32, 0xF9, 0xD8, 0x5C}, {0xBC, 0xE2, 0x4D, 0xC8, 0xD0, 0x96, 0x1C, 0x44}},
        TestIdea{key1, {0x6C, 0x2E, 0x36, 0x17, 0xDA, 0x2B, 0xAC, 0x35}, {0x15, 0x69, 0xE0, 0x62, 0x70, 0x07, 0xB1, 0x2E}},

        TestIdea{key2, {0xD5, 0x3F, 0xAB, 0xBF, 0x94, 0xFF, 0x8B, 0x5F}, {0x13, 0x20, 0xF9, 0x9B, 0xFE, 0x05, 0x28, 0x04}},
        TestIdea{key2, {0x84, 0x8F, 0x83, 0x67, 0x80, 0x93, 0x81, 0x69}, {0x48, 0x21, 0xB9, 0x9F, 0x61, 0xAC, 0xEB, 0xB7}},
        TestIdea{key2, {0x81, 0x94, 0x40, 0xCA, 0x20, 0x65, 0xD1, 0x12}, {0xC8, 0x86, 0x00, 0x09, 0x3B, 0x34, 0x85, 0x75}},
        TestIdea{key2, {0x68, 0x89, 0xF5, 0x64, 0x7A, 0xB2, 0x3D, 0x59}, {0x61, 0xD5, 0x39, 0x70, 0x46, 0xF9, 0x96, 0x37}},
        TestIdea{key2, {0xDF, 0x8C, 0x6F, 0xC6, 0x37, 0xE3, 0xDA, 0xD1}, {0xEF, 0x48, 0x99, 0xB4, 0x8D, 0xE5, 0x90, 0x7C}},
        TestIdea{key2, {0xAC, 0x48, 0x56, 0x24, 0x2B, 0x12, 0x15, 0x89}, {0x85, 0xC6, 0xB2, 0x32, 0x29, 0x4C, 0x2F, 0x27}},
        TestIdea{key2, {0xCB, 0xE4, 0x65, 0xF2, 0x32, 0xF9, 0xD8, 0x5C}, {0xB6, 0x7A, 0xC7, 0x67, 0xC0, 0xC0, 0x6A, 0x55}},
        TestIdea{key2, {0x6C, 0x2E, 0x36, 0x17, 0xDA, 0x2B, 0xAC, 0x35}, {0xB2, 0x22, 0x90, 0x67, 0x63, 0x0F, 0x70, 0x45}},
    };

    for v in &tests {
        cipher := idea.encrypt(v.key[:], v.plaintext[:]);
        if hex_string(cipher[:]) != hex_string(v.ciphertext[:]) {
            print_test_result("IDEA", false);
            return;
        }
        plain := idea.decrypt(v.key[:], cipher[:]);
        if hex_string(plain[:]) != hex_string(v.plaintext[:]) {
            print_test_result("IDEA", false);
            return;
        }
    }

    print_test_result("IDEA", true);
}