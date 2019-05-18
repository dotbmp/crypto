package main

import "core:fmt"
import "shared:hex";
import "hashes/crypto"

TestHash :: struct {
    hash: string,
    str: string,
}

test_blake1_256 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [32]byte;
    outStr : string;
    hash : string;

    // Test hashes taken from https://github.com/ouzklcn/blake
    
    blake1256TestVectors := [4]TestHash {
        TestHash{"e802fe2a73fbe5853408f051d040aeb3a76a4d7a0fc5c3415d1af090f76a2c81", "ube"},
        TestHash{"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6", "BLAKE"},
        TestHash{"716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a", ""},
        TestHash{"61742eadc04f3911d7ee5c4213a9fe1f0816d4ebdab5d4ba406b7b6469cf0ed7", "Golang"},
    };

    for i := 0; i < 4; i += 1 {
        
        msg = blake1256TestVectors[i].str;
        hash = blake1256TestVectors[i].hash;
        out = crypto.blake1_256(([]byte)(msg));
        outStr = hex.hex_string(out[:]);

        if(outStr != hash) {
            passedTest = false;
            fmt.printf("BLAKE1-256 :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", hash, msg, outStr);
            break;
        }
    }

    return passedTest;
}

test_blake1_512 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [64]byte;
    outStr : string;
    hash : string;
    
    blake1512TestVectors := [1]TestHash {
        TestHash{"a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8", ""},
    };

    for i := 0; i < 1; i += 1 {
        
        msg = blake1512TestVectors[i].str;
        hash = blake1512TestVectors[i].hash;
        out = crypto.blake1_512(([]byte)(msg));
        outStr = hex.hex_string(out[:]);

        if(outStr != hash) {
            passedTest = false;
            fmt.printf("BLAKE1-512 :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", hash, msg, outStr);
            break;
        }
    }

    return passedTest;
}

main :: proc() {

    if(test_blake1_256()) {
        fmt.println("Tests for BLAKE1-256 passed.");
    }
}