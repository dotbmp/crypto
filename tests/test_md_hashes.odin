package main

import "core:fmt"
import "shared:hex";
import "hashes/crypto"

TestHash :: struct {
    hash: string,
    str: string,
}

test_md2 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [16]byte;
    outStr : string;
    hash : string;

    // Taken from the RFC at https://tools.ietf.org/html/rfc1319
    md2TestVectors := [7]TestHash {
        TestHash{"8350e5a3e24c153df2275c9f80692773", ""},
        TestHash{"32ec01ec4a6dac72c0ab96fb34c0b5d1", "a"},
        TestHash{"da853b0d3f88d99b30283a69e6ded6bb", "abc"},
        TestHash{"ab4f496bfb2a530b219ff33031fe06b0", "message digest"},
        TestHash{"4e8ddff3650292ab5a4108c3aa47940b", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"da33def2a42df13975352846c30338cd", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        TestHash{"d5976f79d83d3a0dc9806c3c66f3efd8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"}
    };

    for i := 0; i < 7; i += 1 {
        
        msg = md2TestVectors[i].str;
        hash = md2TestVectors[i].hash;
        out = crypto.md2(([]byte)(msg));
        outStr = hex.hex_string(out[:]);

        if(outStr != hash) {
            passedTest = false;
            fmt.printf("MD2 :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", hash, msg, outStr);
            break;
        }
    }

    return passedTest;
}

test_md4 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [16]byte;
    outStr : string;
    hash : string;

    // Taken from the RFC at https://tools.ietf.org/html/rfc1320
    md4TestVectors := [7]TestHash {
        TestHash{"31d6cfe0d16ae931b73c59d7e0c089c0", ""},
        TestHash{"bde52cb31de33e46245e05fbdbd6fb24", "a"},
        TestHash{"a448017aaf21d8525fc10ae87aa6729d", "abc"},
        TestHash{"d9130a8164549fe818874806e1c7014b", "message digest"},
        TestHash{"d79e1c308aa5bbcdeea8ed63df412da9", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"043f8582f241db351ce627e153e7f0e4", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        TestHash{"e33b4ddc9c38f2199c3e7b164fcc0536", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"}
    };

    for i := 0; i < 7; i += 1 {
        
        msg = md4TestVectors[i].str;
        hash = md4TestVectors[i].hash;
        out = crypto.md4(([]byte)(msg));
        outStr = hex.hex_string(out[:]);

        if(outStr != hash) {
            passedTest = false;
            fmt.printf("MD4 :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", hash, msg, outStr);
            break;
        }
    }

    return passedTest;
}

test_md5 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [16]byte;
    outStr : string;
    hash : string;

    // Taken from the RFC at https://tools.ietf.org/html/rfc1321
    md5TestVectors := [7]TestHash {
        TestHash{"d41d8cd98f00b204e9800998ecf8427e", ""},
        TestHash{"0cc175b9c0f1b6a831c399e269772661", "a"},
        TestHash{"900150983cd24fb0d6963f7d28e17f72", "abc"},
        TestHash{"f96b697d7cb7938d525a2f31aaf161d0", "message digest"},
        TestHash{"c3fcd3d76192e4007dfb496cca67e13b", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"d174ab98d277d9f5a5611c2c9f419d9f", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        TestHash{"57edf4a22be3c955ac49da2e2107b67a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"}
    };

    for i := 0; i < 7; i += 1 {
        
        msg = md5TestVectors[i].str;
        hash = md5TestVectors[i].hash;
        out = crypto.md5(([]byte)(msg));
        outStr = hex.hex_string(out[:]);

        if(outStr != hash) {
            passedTest = false;
            fmt.printf("MD5 :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", hash, msg, outStr);
            break;
        }
    }

    return passedTest;
}

test_md6 :: proc() -> bool {

    msg := "Hellope";
    // Taken from https://www.easycalculation.com/other/md6.php
    hash := "d6fe71197b4dfc5ca5c2b741a83f3239aeca7fd5b7157827544370234a3ea9bd0fe6c96ba4062719c8a85df229fef90dd602cd05312d293a1439768bac45c37f";
    out := crypto.md6_512(([]byte)(msg));
    outStr := hex.hex_string(out[:]);

    fmt.printf("Hash: %s", outStr);

    return hash == outStr;
}

main :: proc() {

    if(test_md2()) {
        fmt.println("Tests for MD2 passed.");
    }

    if(test_md4()) {
        fmt.println("Tests for MD4 passed.");
    }

    if(test_md5()) {
        fmt.println("Tests for MD5 passed.");
    }

    if(test_md6()) {
        fmt.println("Tests for MD5 passed.");
    }
}