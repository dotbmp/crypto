package test_encryption

import "core:fmt"
using import "../crypto"
import "../crypto/blowfish"
import "../crypto/rc2"
import "../crypto/rc4"
import "../crypto/rc5"
import "../crypto/rc6"



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
    test_blowfish_ecb();
    //test_blowfish_cbc();
    test_rc2();
    test_rc4();
    test_rc5();
    test_rc6();
}

test_blowfish_ecb :: proc() {
    ctx: blowfish.Ctx;
    input: [8]byte = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    key: [8]byte = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    cipher := blowfish.encrypt_ecb(&ctx, input[:], key[:]);
    clear: [8]byte;
    blowfish.decrypt_ecb(&ctx, clear[:], cipher[:]);
    if hex_string(cipher[:]) == "4ef997456198dd78" && hex_string(clear[:]) == "0000000000000000" {
        fmt.println("Blowfish test for ECB passed");
    } 
    else {
        fmt.println("Blowfish test for ECB failed");
    }
}

test_blowfish_cbc :: proc() {
    ctx: blowfish.Ctx;

    input := "4567 123 woNt sit eh emi";
    key: [16]byte = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87};
    iv: [8]byte = {0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76};

    cipher := blowfish.encrypt_cbc(&ctx, ([]byte)(input), key[:], iv[:]);
    fmt.println(cipher);
}

test_rc2 :: proc() {
    key := hex_bytes("88bca90e90875a7f0f79c384627bafb2");
    plaintext := hex_bytes("0000000000000000");
    expected_cipher := "2269552ab0f85ca6";

    cipherbytes := rc2.encrypt(key, plaintext);
    ciphertext := hex_string(cipherbytes[:]);

    if !(expected_cipher == ciphertext) {
        fmt.println("RC2 encryption test failed");
        return;
    }

    plain := rc2.decrypt(key, hex_bytes(ciphertext));

    if hex_string(plain[:]) != hex_string(plaintext) {
        fmt.println("RC2 decryption test failed");
        return;
    }

    fmt.println("RC2 test passed");
}

test_rc4 :: proc() {
    key := "123456";
    plaintext := "hello";
    expected_cipher: [5]byte = {0x68, 0x9d, 0x12, 0xb, 0x4b};

    ciphertext := rc4.encrypt(([]byte)(key), ([]byte)(plaintext));

    for i := 0; i < len(plaintext); i += 1 {
        if !(expected_cipher[i] == ciphertext[i]) {
            fmt.println("RC4 encryption test failed");
            return;
        }
    }

    plain := rc4.decrypt(([]byte)(key), ([]byte)(ciphertext));

    if string(plain) != plaintext {
        fmt.println("RC4 decryption test failed");
        return;
    }

    fmt.println("RC4 test passed");
}

test_rc5 :: proc() {
    key: [16]byte = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    plaintext: [8]byte = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    expected_cipher: [8]byte = {0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E};

    ciphertext := rc5.encrypt(key[:], plaintext[:]);

    for i := 0; i < len(plaintext); i += 1 {
        if !(expected_cipher[i] == ciphertext[i]) {
            fmt.println("RC5 encryption test failed");
            return;
        }
    }

    plain := rc5.decrypt(key[:], ciphertext);

    for i := 0; i < len(ciphertext); i += 1 {
        if !(plaintext[i] == plain[i]) {
            fmt.println("RC5 decryption test failed");
            return;
        }
    }

    fmt.println("RC5 test passed");
}

test_rc6 :: proc() {
    key: [16]byte = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    plaintext: [16]byte = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    expected_cipher: [16]byte = {0x09, 0xC2, 0x61, 0x43, 0xB4, 0x7B, 0x1A, 0x22, 0xEC, 0x2D, 0x9C, 0xD8, 0xB8, 0xA4, 0xE5, 0x73};

    ciphertext := rc6.encrypt(key[:], plaintext[:]);

    for i := 0; i < len(plaintext); i += 1 {
        if !(expected_cipher[i] == ciphertext[i]) {
            fmt.println("RC6 encryption test failed");
            return;
        }
    }

    plain := rc6.decrypt(key[:], ciphertext);

    for i := 0; i < len(ciphertext); i += 1 {
        if !(plaintext[i] == plain[i]) {
            fmt.println("RC6 decryption test failed");
            return;
        }
    }

    fmt.println("RC6 test passed");
}