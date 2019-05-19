package main

import "core:fmt"
import "shared:hex";
import "hashes/crypto"

TestHash :: struct {
    hash: string,
    str: string,
}

test_blake1_224 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [28]byte;
    outStr : string;
    hash : string;
    
    blake1224TestVectors := [4]TestHash {
        TestHash{"7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed", ""},
        TestHash{"304c27fdbf308aea06955e331adc6814223a21fccd24c09fde9eda7b", "ube"},
        TestHash{"cfb6848add73e1cb47994c4765df33b8f973702705a30a71fe4747a3", "BLAKE"},
        TestHash{"8bd036c145222cd5401f36bcc79628b8d577f5e815910a71b92cb2be", "Golang"},
    };

    for i := 0; i < 4; i += 1 {
        
        msg = blake1224TestVectors[i].str;
        hash = blake1224TestVectors[i].hash;
        out = crypto.blake1_224(([]byte)(msg));
        outStr = hex.hex_string(out[:]);

        if(outStr != hash) {
            passedTest = false;
            fmt.printf("BLAKE1-224 :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", hash, msg, outStr);
            break;
        }
    }

    return passedTest;
}

test_blake1_256 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [32]byte;
    outStr : string;
    hash : string;
    
    blake1256TestVectors := [4]TestHash {
        TestHash{"716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a", ""},
        TestHash{"e802fe2a73fbe5853408f051d040aeb3a76a4d7a0fc5c3415d1af090f76a2c81", "ube"},
        TestHash{"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6", "BLAKE"},
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

test_blake1_384 :: proc() -> bool {

    passedTest := true;
    msg : string;
    out : [48]byte;
    outStr : string;
    hash : string;

    blake1384TestVectors := [4]TestHash {
        TestHash{"c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706", ""},
        TestHash{"8f22f120b2b99dd4fd32b98c8c83bd87abd6413f7317be936b1997511247fc68ae781c6f42113224ccbc1567b0e88593", "ube"},
        TestHash{"f28742f7243990875d07e6afcff962edabdf7e9d19ddea6eae31d094c7fa6d9b00c8213a02ddf1e2d9894f3162345d85", "BLAKE"},
        TestHash{"c8cb1692a7521667e3c613b7c3e10a8859e0f103f211db4f3842fff7fa4b86fac80910d24537f19f40f5a8051391d439", "Golang"},
    };

    for i := 0; i < 4; i += 1 {
        
        msg = blake1384TestVectors[i].str;
        hash = blake1384TestVectors[i].hash;
        out = crypto.blake1_384(([]byte)(msg));
        outStr = hex.hex_string(out[:]);

        if(outStr != hash) {
            passedTest = false;
            fmt.printf("BLAKE1-384 :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", hash, msg, outStr);
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

    blake1512TestVectors := [4]TestHash {
        TestHash{"a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8", ""},
        TestHash{"49a24ca8f230936f938c19484d46b58f13ea4448ddadafecdf01419b1e1dd922680be2de84069187973ab61b10574da2ee50cbeaade68ea9391c8ec041b76be0", "ube"},
        TestHash{"7bf805d0d8de36802b882e65d0515aa7682a2be97a9d9ec1399f4be2eff7de07684d7099124c8ac81c1c7c200d24ba68c6222e75062e04feb0e9dd589aa6e3b7", "BLAKE"},
        TestHash{"cc6d779ca76673932e2f93681d502a1c6fd82932b48632c2a2f3c599e7bf016e7280a2e74da8a6fe76d5a36dd412ef7d67778acc1a458856f1181e9fe0a0c25c", "Golang"},
    };

    for i := 0; i < 4; i += 1 {
        
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

    if(test_blake1_224()) {
        fmt.println("Tests for BLAKE1-224 passed.");
    }

    if(test_blake1_256()) {
        fmt.println("Tests for BLAKE1-256 passed.");
    }

    if(test_blake1_384()) {
        fmt.println("Tests for BLAKE1-384 passed.");
    }

    if(test_blake1_512()) {
        fmt.println("Tests for BLAKE1-512 passed.");
    }
}