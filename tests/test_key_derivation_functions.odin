package test_key_derivation_functions

import "core:fmt"
import "../crypto/pbkdf2"

TestKdf :: struct {
    password: string,
    salt:     string,
    rounds:   int,
    key_len:  int,
    key:      string,
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

check_kdf :: proc(computed: []byte, key, algo: string) -> bool{
    outStr := hex_string(computed[:]);
    if(outStr != key) {
        fmt.printf("%s :: Test failed :: Expected %s, but got %s instead\n", algo, key, outStr);
        return false;
    }
    return true;
}

test :: proc(test_vectors: []TestKdf, algo: string) {
    for s, _ in test_vectors {
        switch algo {
            // PBKDF2 SHA1
            case "PBKDF2-SHA1":
                out:= pbkdf2.sha1(transmute([]byte)(s.password), transmute([]byte)(s.salt), s.rounds, s.key_len);
                if !check_kdf(out[:], s.key, algo) do return;

            // PBKDF2 SHA2
            case "PBKDF2-SHA-256":
                out:= pbkdf2.sha256(transmute([]byte)(s.password), transmute([]byte)(s.salt), s.rounds, s.key_len);
                if !check_kdf(out[:], s.key, algo) do return;
            case "PBKDF2-SHA-512":
                out:= pbkdf2.sha512(transmute([]byte)(s.password), transmute([]byte)(s.salt), s.rounds, s.key_len);
                if !check_kdf(out[:], s.key, algo) do return;

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
    // PBKDF2              //
    // SHA1                //
    pbkdf2Sha1TestVectors := [?]TestKdf {
        // RFC 6070
        {"password",                 "salt",                                 1,        20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
        {"password",                 "salt",                                 2,        20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
        {"password",                 "salt",                                 4096,     20, "4b007901b765489abead49d926f721d065a429c1"},
        // @note(zh): Commented because it takes ages (on purpose)
        // {"password",                 "salt",                                 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"},
        {"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,     25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
        {"pass\x00word",              "sa\x00lt",                             4096,     16, "56fa6aa75548099dcc37d7f03425e0c3"},
    };
    test(pbkdf2Sha1TestVectors[:], "PBKDF2-SHA1");
    // =================== //
    // PBKDF2              //
    // SHA2                //
    pbkdf2Sha256TestVectors := [?]TestKdf {
        // RFC 6070
        {"password"                 , "salt"                                 ,1,        32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
        {"password"                 , "salt"                                 ,2,        32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
        {"password"                 , "salt"                                 ,4096,     32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
        // @note(zh): Commented because it takes ages (on purpose)
        // {"password"                 , "salt"                                 , 16777216, 32, "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46"},
        {"passwordPASSWORDpassword" , "saltSALTsaltSALTsaltSALTsaltSALTsalt" ,4096,     40, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"},
        {"pass\x00word"             , "sa\x00lt"                             ,4096,     16, "89b69d0516f829893c696226650a8687"},
        // RFC 7914
        {"passwd"                   , "salt"                                 ,1,        64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
        {"Password"                 , "NaCl"                                 ,80000,    64, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
    };
    test(pbkdf2Sha256TestVectors[:], "PBKDF2-SHA-256");
    pbkdfSha512TestVectors := [?]TestKdf {
        // RFC 6070
        {"password"                , "salt"                                , 1,    64, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"},
        {"password"                , "salt"                                , 2,    64, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"},
        {"password"                , "salt"                                , 4096, 64, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"},
        {"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 64, "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8"},
    };
    test(pbkdfSha512TestVectors[:], "PBKDF2-SHA-512");
}