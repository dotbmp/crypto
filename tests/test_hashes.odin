package main

import "core:fmt"
import ".."

TestHash :: struct {
    hash: string,
    str: string,
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

check_hash :: proc(computed: []byte, hash, msg, algo: string) -> bool{
    outStr := hex_string(computed[:]);
    if(outStr != hash) {
        fmt.printf("%s :: Test failed :: Expected %s for input of \"%s\", but got %s instead\n", algo, hash, msg, outStr);
        return false;
    }
    return true;
}

test :: proc(testVectors: []TestHash, algo: string) {
    for s, _ in testVectors {
        switch algo {
            // MD
            case "MD2": 
                out:= crypto.md2(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "MD4":
                out:= crypto.md4(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "MD5":
                out:= crypto.md5(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // SHA
            case "SHA1":
                out:= crypto.sha1(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // BLAKE
            case "BLAKE-224":
                out:= crypto.blake224(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "BLAKE-256":
                out:= crypto.blake256(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "BLAKE-384":
                out:= crypto.blake384(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "BLAKE-512":
                out:= crypto.blake512(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            
            // BLAKE2
            case "BLAKE2S-256":
                out:= crypto.blake2s_256(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "BLAKE2B-512":
                out:= crypto.blake2b_512(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            
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
    // MD Series           //
    // MD2                 //
    md2TestVectors := [7]TestHash {
        TestHash{"8350e5a3e24c153df2275c9f80692773", ""},
        TestHash{"32ec01ec4a6dac72c0ab96fb34c0b5d1", "a"},
        TestHash{"da853b0d3f88d99b30283a69e6ded6bb", "abc"},
        TestHash{"ab4f496bfb2a530b219ff33031fe06b0", "message digest"},
        TestHash{"4e8ddff3650292ab5a4108c3aa47940b", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"da33def2a42df13975352846c30338cd", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        TestHash{"d5976f79d83d3a0dc9806c3c66f3efd8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"}
    };
    test(md2TestVectors[:], "MD2");
    // MD4                 //
    md4TestVectors := [7]TestHash {
        TestHash{"31d6cfe0d16ae931b73c59d7e0c089c0", ""},
        TestHash{"bde52cb31de33e46245e05fbdbd6fb24", "a"},
        TestHash{"a448017aaf21d8525fc10ae87aa6729d", "abc"},
        TestHash{"d9130a8164549fe818874806e1c7014b", "message digest"},
        TestHash{"d79e1c308aa5bbcdeea8ed63df412da9", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"043f8582f241db351ce627e153e7f0e4", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        TestHash{"e33b4ddc9c38f2199c3e7b164fcc0536", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"}
    };
    test(md4TestVectors[:], "MD4");
    // MD5                 //
    md5TestVectors := [7]TestHash {
        TestHash{"d41d8cd98f00b204e9800998ecf8427e", ""},
        TestHash{"0cc175b9c0f1b6a831c399e269772661", "a"},
        TestHash{"900150983cd24fb0d6963f7d28e17f72", "abc"},
        TestHash{"f96b697d7cb7938d525a2f31aaf161d0", "message digest"},
        TestHash{"c3fcd3d76192e4007dfb496cca67e13b", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"d174ab98d277d9f5a5611c2c9f419d9f", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        TestHash{"57edf4a22be3c955ac49da2e2107b67a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"}
    };
    test(md5TestVectors[:], "MD5");
    // =================== //
    // SHA Series          //
    // SHA1                //
    sha1TestVectors := [5]TestHash {
        TestHash{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
        TestHash{"f9537c23893d2014f365adf8ffe33b8eb0297ed1", "abcdbcdecdefdefgefghfghighijhi"},
        TestHash{"346fb528a24b48f563cb061470bcfd23740427ad", "jkijkljklmklmnlmnomnopnopq"},
        TestHash{"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a"},
        TestHash{"c729c8996ee0a6f74f4f3248e8957edf704fb624", "01234567012345670123456701234567"},
    };
    test(sha1TestVectors[:], "SHA1");
    // =================== //
    // BLAKE Series       //
    // BLAKE-224          //
    blake224TestVectors := [4]TestHash {
        TestHash{"7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed", ""},
        TestHash{"304c27fdbf308aea06955e331adc6814223a21fccd24c09fde9eda7b", "ube"},
        TestHash{"cfb6848add73e1cb47994c4765df33b8f973702705a30a71fe4747a3", "BLAKE"},
        TestHash{"8bd036c145222cd5401f36bcc79628b8d577f5e815910a71b92cb2be", "Golang"},
    };
    test(blake224TestVectors[:], "BLAKE-224");
    // BLAKE-256          //
    blake256TestVectors := [4]TestHash {
        TestHash{"716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a", ""},
        TestHash{"e802fe2a73fbe5853408f051d040aeb3a76a4d7a0fc5c3415d1af090f76a2c81", "ube"},
        TestHash{"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6", "BLAKE"},
        TestHash{"61742eadc04f3911d7ee5c4213a9fe1f0816d4ebdab5d4ba406b7b6469cf0ed7", "Golang"},
    };
    test(blake256TestVectors[:], "BLAKE-256");
    // BLAKE-384           //
    blake384TestVectors := [4]TestHash {
        TestHash{"c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706", ""},
        TestHash{"8f22f120b2b99dd4fd32b98c8c83bd87abd6413f7317be936b1997511247fc68ae781c6f42113224ccbc1567b0e88593", "ube"},
        TestHash{"f28742f7243990875d07e6afcff962edabdf7e9d19ddea6eae31d094c7fa6d9b00c8213a02ddf1e2d9894f3162345d85", "BLAKE"},
        TestHash{"c8cb1692a7521667e3c613b7c3e10a8859e0f103f211db4f3842fff7fa4b86fac80910d24537f19f40f5a8051391d439", "Golang"},
    };
    test(blake384TestVectors[:], "BLAKE-384");
    // BLAKE-512          //
    blake512TestVectors := [4]TestHash {
        TestHash{"a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8", ""},
        TestHash{"49a24ca8f230936f938c19484d46b58f13ea4448ddadafecdf01419b1e1dd922680be2de84069187973ab61b10574da2ee50cbeaade68ea9391c8ec041b76be0", "ube"},
        TestHash{"7bf805d0d8de36802b882e65d0515aa7682a2be97a9d9ec1399f4be2eff7de07684d7099124c8ac81c1c7c200d24ba68c6222e75062e04feb0e9dd589aa6e3b7", "BLAKE"},
        TestHash{"cc6d779ca76673932e2f93681d502a1c6fd82932b48632c2a2f3c599e7bf016e7280a2e74da8a6fe76d5a36dd412ef7d67778acc1a458856f1181e9fe0a0c25c", "Golang"},
    };
    test(blake512TestVectors[:], "BLAKE-512");
    // =================== //
    // BLAKE2 Series       //
    // BLAKE2S-256         //
    blake2s256TestVectors := [2]TestHash {
        TestHash{"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", ""},
        TestHash{"606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812", "The quick brown fox jumps over the lazy dog"},
    };
    test(blake2s256TestVectors[:], "BLAKE2S-256");
    // BLAKE2B-512         //
    blake2b512TestVectors := [2]TestHash {
        TestHash{"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", ""},
        TestHash{"a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918", "The quick brown fox jumps over the lazy dog"},
    };
    test(blake2b512TestVectors[:], "BLAKE2B-512");
    // =================== //
}