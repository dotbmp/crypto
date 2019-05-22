package main

import "core:fmt"
import "shared:encodings/hex";
import ".."

TestHash :: struct {
    hash: string,
    str: string,
}

test_sha1 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [20]byte;
    outStr : string;
    hash : string;

    // Taken from the RFC at http://www.faqs.org/rfcs/rfc3174.html
    sha1TestVectors := [5]TestHash {
        TestHash{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
        TestHash{"f9537c23893d2014f365adf8ffe33b8eb0297ed1", "abcdbcdecdefdefgefghfghighijhi"},
        TestHash{"346fb528a24b48f563cb061470bcfd23740427ad", "jkijkljklmklmnlmnomnopnopq"},
        TestHash{"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a"},
        TestHash{"c729c8996ee0a6f74f4f3248e8957edf704fb624", "01234567012345670123456701234567"},
    };

    for i := 0; i < 5; i += 1 {
        
        msg = sha1TestVectors[i].str;
        hash = sha1TestVectors[i].hash;
        out = crypto.sha1(([]byte)(msg));
        outStr = hex.encode(out[:]);

        if(outStr != hash) {
            passedTest = false;
            fmt.printf("SHA1 :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", hash, msg, outStr);
            break;
        }
    }

    return passedTest;
}

main :: proc() {

    if(test_sha1()) {
        fmt.println("Tests for SHA1 passed.");
    }

}