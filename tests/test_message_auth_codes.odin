package test_message_auth_codes

import "core:fmt"
import "../crypto/hmac"

TestMac :: struct {
    mac: string,
    str: string,
    key: string,
};

hex_string :: proc(bytes: []byte, allocator := context.temp_allocator) -> string {
    lut: [16]byte = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    buf := make([]byte, len(bytes)*2, allocator);
    for i: i32 = 0; i < i32(len(bytes)); i += 1 {
        buf[i*2+0] = lut[bytes[i] >> 4 & 0xF];
        buf[i*2+1] = lut[bytes[i]      & 0xF];
    }
    return string(buf);
}

check_mac :: proc(computed: []byte, mac, msg, algo: string) -> bool{
    outStr := hex_string(computed[:]);
    if(outStr != mac) {
        fmt.printf("%s :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", algo, mac, msg, outStr);
        return false;
    }
    return true;
}

test :: proc(testVectors: []TestMac, algo: string) {
    for s, _ in testVectors {
        switch algo {

            // SHA1
            case "HMAC-SHA1":
                out:= hmac.sha1(transmute([]byte)(s.str), transmute([]byte)(s.key));
                if !check_mac(out[:], s.mac, s.str, algo) do return;

            // SHA2
            case "HMAC-SHA-224":
                out:= hmac.sha224(transmute([]byte)(s.str), transmute([]byte)(s.key));
                if !check_mac(out[:], s.mac, s.str, algo) do return;
            case "HMAC-SHA-256":
                out:= hmac.sha256(transmute([]byte)(s.str), transmute([]byte)(s.key));
                if !check_mac(out[:], s.mac, s.str, algo) do return;
            case "HMAC-SHA-384":
                out:= hmac.sha384(transmute([]byte)(s.str), transmute([]byte)(s.key));
                if !check_mac(out[:], s.mac, s.str, algo) do return;
            case "HMAC-SHA-512":
                out:= hmac.sha512(transmute([]byte)(s.str), transmute([]byte)(s.key));
                if !check_mac(out[:], s.mac, s.str, algo) do return;

            // MD5
            case "HMAC-MD5":
                out:= hmac.md5(transmute([]byte)(s.str), transmute([]byte)(s.key));
                if !check_mac(out[:], s.mac, s.str, algo) do return;

            // Unsupported
            case: 
                fmt.printf(" --- %s not supported yet ---\n", algo);
                return;
        }
    }
    fmt.printf(" === Tests for %s passed ===\n", algo);
}

main :: proc() {
    // =================== //
    // HMAC                //
    // SHA1                //
    hmacSha1TestVectors := [?]TestMac {
        TestMac{"de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", "The quick brown fox jumps over the lazy dog", "key"},
    };
    test(hmacSha1TestVectors[:], "HMAC-SHA1");
    // =================== //
    // HMAC                //
    // SHA2                //
    hmacSha224TestVectors := [?]TestMac {
        TestMac{"a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44", "what do ya want for nothing?", "Jefe"},
    };
    //test(hmacSha224TestVectors[:], "HMAC-SHA-224");
    hmacSha256TestVectors := [?]TestMac {
        TestMac{"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "what do ya want for nothing?", "Jefe"},
        TestMac{"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", "The quick brown fox jumps over the lazy dog", "key"},
    };
    //test(hmacSha256TestVectors[:], "HMAC-SHA-256");
    hmacSha384TestVectors := [?]TestMac {
        TestMac{"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649", "what do ya want for nothing?", "Jefe"},
    };
    //test(hmacSha384TestVectors[:], "HMAC-SHA-384");
    hmacSha512TestVectors := [?]TestMac {
        TestMac{"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", "what do ya want for nothing?", "Jefe"},
    };
    test(hmacSha512TestVectors[:], "HMAC-SHA-512");
    // =================== //
    // HMAC                //
    // MD5                 //
    hmacMd5TestVectors := [?]TestMac {
        TestMac{"80070713463e7749b90c2dc24911e275", "The quick brown fox jumps over the lazy dog", "key"},
    };
    test(hmacMd5TestVectors[:], "HMAC-MD5");
}