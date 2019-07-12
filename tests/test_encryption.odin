package test_encryption

import "core:fmt"
import "../crypto/blowfish"
import "../crypto/rc4"
using import "../crypto"

hex_string :: proc(bytes: []byte, allocator := context.temp_allocator) -> string {
    lut: [16]byte = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    buf := make([]byte, len(bytes)*2, allocator);
    for i: i32 = 0; i < i32(len(bytes)); i += 1 {
        buf[i*2+0] = lut[bytes[i] >> 4 & 0xF];
        buf[i*2+1] = lut[bytes[i]      & 0xF];
    }
    return string(buf);
}

main :: proc() {
    test_blowfish_ecb();
    //test_blowfish_cbc();
    test_rc4();
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