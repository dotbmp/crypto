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

            // SHA3
            case "SHA3-224":
                out := crypto.sha3_224(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA3-256":
                out := crypto.sha3_256(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA3-384":
                out := crypto.sha3_384(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA3-512":
                out := crypto.sha3_512(([]byte)(s.str));
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
            
            // RIPEMD
            case "RIPEMD-128":
                out:= crypto.ripemd_128(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "RIPEMD-160":
                out:= crypto.ripemd_160(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "RIPEMD-256":
                out:= crypto.ripemd_256(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "RIPEMD-320":
                out:= crypto.ripemd_320(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // HAVAL
            case "HAVAL-3-128":
                out:= crypto.haval_3_128(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-3-160":
                out:= crypto.haval_3_160(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-3-192":
                out:= crypto.haval_3_192(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-3-224":
                out:= crypto.haval_3_224(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-3-256":
                out:= crypto.haval_3_256(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-128":
                out:= crypto.haval_4_128(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-160":
                out:= crypto.haval_4_160(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-192":
                out:= crypto.haval_4_192(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-224":
                out:= crypto.haval_4_224(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-256":
                out:= crypto.haval_4_256(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-128":
                out:= crypto.haval_5_128(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-160":
                out:= crypto.haval_5_160(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-192":
                out:= crypto.haval_5_192(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-224":
                out:= crypto.haval_5_224(([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-256":
                out:= crypto.haval_5_256(([]byte)(s.str));
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
    md2TestVectors := [?]TestHash {
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
    md4TestVectors := [?]TestHash {
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
    md5TestVectors := [?]TestHash {
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
    sha1TestVectors := [?]TestHash {
        TestHash{"da39a3ee5e6b4b0d3255bfef95601890afd80709", ""},
        TestHash{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
        TestHash{"f9537c23893d2014f365adf8ffe33b8eb0297ed1", "abcdbcdecdefdefgefghfghighijhi"},
        TestHash{"346fb528a24b48f563cb061470bcfd23740427ad", "jkijkljklmklmnlmnomnopnopq"},
        TestHash{"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a"},
        TestHash{"c729c8996ee0a6f74f4f3248e8957edf704fb624", "01234567012345670123456701234567"},
    };
    test(sha1TestVectors[:], "SHA1");
    // SHA3-224             //
    sha3224TestVectors := [?]TestHash {
        TestHash{"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", ""},
        TestHash{"e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", "abc"},
        TestHash{"10241ac5187380bd501192e4e56b5280908727dd8fe0d10d4e5ad91e", "abcdbcdecdefdefgefghfghighijhi"},
        TestHash{"fd645fe07d814c397e85e85f92fe58b949f55efa4d3468b2468da45a", "jkijkljklmklmnlmnomnopnopq"},
        TestHash{"9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b", "a"},
        TestHash{"6961f694b2ff3ed6f0c830d2c66da0c5e7ca9445f7c0dca679171112", "01234567012345670123456701234567"},
    };
    test(sha3224TestVectors[:], "SHA3-224");
    // SHA3-256             //
    sha3256TestVectors := [?]TestHash {
        TestHash{"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", ""},
        TestHash{"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "abc"},
        TestHash{"565ada1ced21278cfaffdde00dea0107964121ac25e4e978abc59412be74550a", "abcdbcdecdefdefgefghfghighijhi"},
        TestHash{"8cc1709d520f495ce972ece48b0d2e1f74ec80d53bc5c47457142158fae15d98", "jkijkljklmklmnlmnomnopnopq"},
        TestHash{"80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b", "a"},
        TestHash{"e4786de5f88f7d374b7288f225ea9f2f7654da200bab5d417e1fb52d49202767", "01234567012345670123456701234567"},
    };
    test(sha3256TestVectors[:], "SHA3-256");
    // SHA3-384             //
    sha3384TestVectors := [?]TestHash {
        TestHash{"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004", ""},
        TestHash{"ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25", "abc"},
        TestHash{"9aa92dbb716ebb573def0d5e3cdd28d6add38ada310b602b8916e690a3257b7144e5ddd3d0dbbc559c48480d34d57a9a", "abcdbcdecdefdefgefghfghighijhi"},
        TestHash{"77c90323d7392bcdee8a3e7f74f19f47b7d1b1a825ac6a2d8d882a72317879cc26597035f1fc24fe65090b125a691282", "jkijkljklmklmnlmnomnopnopq"},
        TestHash{"1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9", "a"},
        TestHash{"51072590ad4c51b27ff8265590d74f92de7cc55284168e414ca960087c693285b08a283c6b19d77632994cb9eb93f1be", "01234567012345670123456701234567"},
    };
    test(sha3384TestVectors[:], "SHA3-384");
    // SHA3-512             //
    sha3512TestVectors := [?]TestHash {
        TestHash{"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26", ""},
        TestHash{"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", "abc"},
        TestHash{"9f9a327944a35988d67effc4fa748b3c07744f736ac70b479d8e12a3d10d6884d00a7ef593690305462e9e9030a67c51636fd346fd8fa0ee28a5ac2aee103d2e", "abcdbcdecdefdefgefghfghighijhi"},
        TestHash{"dbb124a0deda966eb4d199d0844fa0beb0770ea1ccddabcd335a7939a931ac6fb4fa6aebc6573f462ced2e4e7178277803be0d24d8bc2864626d9603109b7891", "jkijkljklmklmnlmnomnopnopq"},
        TestHash{"697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a", "a"},
        TestHash{"5679e353bc8eeea3e801ca60448b249bcfd3ac4a6c3abe429a807bcbd4c9cd12da87a5a9dc74fde64c0d44718632cae966b078397c6f9ec155c6a238f2347cf1", "01234567012345670123456701234567"},
    };
    test(sha3512TestVectors[:], "SHA3-512");
    // =================== //
    // BLAKE Series       //
    // BLAKE-224          //
    blake224TestVectors := [?]TestHash {
        TestHash{"7dc5313b1c04512a174bd6503b89607aecbee0903d40a8a569c94eed", ""},
        TestHash{"304c27fdbf308aea06955e331adc6814223a21fccd24c09fde9eda7b", "ube"},
        TestHash{"cfb6848add73e1cb47994c4765df33b8f973702705a30a71fe4747a3", "BLAKE"},
        TestHash{"8bd036c145222cd5401f36bcc79628b8d577f5e815910a71b92cb2be", "Golang"},
    };
    test(blake224TestVectors[:], "BLAKE-224");
    // BLAKE-256          //
    blake256TestVectors := [?]TestHash {
        TestHash{"716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a", ""},
        TestHash{"e802fe2a73fbe5853408f051d040aeb3a76a4d7a0fc5c3415d1af090f76a2c81", "ube"},
        TestHash{"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6", "BLAKE"},
        TestHash{"61742eadc04f3911d7ee5c4213a9fe1f0816d4ebdab5d4ba406b7b6469cf0ed7", "Golang"},
    };
    test(blake256TestVectors[:], "BLAKE-256");
    // BLAKE-384           //
    blake384TestVectors := [?]TestHash {
        TestHash{"c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706", ""},
        TestHash{"8f22f120b2b99dd4fd32b98c8c83bd87abd6413f7317be936b1997511247fc68ae781c6f42113224ccbc1567b0e88593", "ube"},
        TestHash{"f28742f7243990875d07e6afcff962edabdf7e9d19ddea6eae31d094c7fa6d9b00c8213a02ddf1e2d9894f3162345d85", "BLAKE"},
        TestHash{"c8cb1692a7521667e3c613b7c3e10a8859e0f103f211db4f3842fff7fa4b86fac80910d24537f19f40f5a8051391d439", "Golang"},
    };
    test(blake384TestVectors[:], "BLAKE-384");
    // BLAKE-512          //
    blake512TestVectors := [?]TestHash {
        TestHash{"a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8", ""},
        TestHash{"49a24ca8f230936f938c19484d46b58f13ea4448ddadafecdf01419b1e1dd922680be2de84069187973ab61b10574da2ee50cbeaade68ea9391c8ec041b76be0", "ube"},
        TestHash{"7bf805d0d8de36802b882e65d0515aa7682a2be97a9d9ec1399f4be2eff7de07684d7099124c8ac81c1c7c200d24ba68c6222e75062e04feb0e9dd589aa6e3b7", "BLAKE"},
        TestHash{"cc6d779ca76673932e2f93681d502a1c6fd82932b48632c2a2f3c599e7bf016e7280a2e74da8a6fe76d5a36dd412ef7d67778acc1a458856f1181e9fe0a0c25c", "Golang"},
    };
    test(blake512TestVectors[:], "BLAKE-512");
    // =================== //
    // BLAKE2 Series       //
    // BLAKE2S-256         //
    blake2s256TestVectors := [?]TestHash {
        TestHash{"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", ""},
        TestHash{"606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812", "The quick brown fox jumps over the lazy dog"},
    };
    test(blake2s256TestVectors[:], "BLAKE2S-256");
    // BLAKE2B-512         //
    blake2b512TestVectors := [?]TestHash {
        TestHash{"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", ""},
        TestHash{"a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918", "The quick brown fox jumps over the lazy dog"},
    };
    test(blake2b512TestVectors[:], "BLAKE2B-512");
    // =================== //
    // RIPEMD Series       //
    // RIPEMD-128          //
    ripemd128TestVectors := [?]TestHash {
        TestHash{"cdf26213a150dc3ecb610f18f6b38b46", ""},
		TestHash{"86be7afa339d0fc7cfc785e72f578d33", "a"},
		TestHash{"c14a12199c66e4ba84636b0f69144c77", "abc"},
		TestHash{"9e327b3d6e523062afc1132d7df9d1b8", "message digest"},
		TestHash{"fd2aa607f71dc8f510714922b371834e", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"a1aa0689d0fafa2ddc22e88b49133a06", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"d1e959eb179c911faea4624c60c5c702", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
    };
    test(ripemd128TestVectors[:], "RIPEMD-128");
    // RIPEMD-160          //
    ripemd160TestVectors := [?]TestHash {
        TestHash{"9c1185a5c5e9fc54612808977ee8f548b2258d31", ""},
		TestHash{"0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "a"},
		TestHash{"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "abc"},
		TestHash{"5d0689ef49d2fae572b881b123a85ffa21595f36", "message digest"},
		TestHash{"f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"12a053384a9c0c88e405a06c27dcf49ada62eb2b", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"b0e20b6e3116640286ed3a87a5713079b21f5189", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
    };
    test(ripemd160TestVectors[:], "RIPEMD-160");
    // RIPEMD-256          //
    ripemd256TestVectors := [?]TestHash {
        TestHash{"02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d", ""},
		TestHash{"f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925", "a"},
		TestHash{"afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65", "abc"},
		TestHash{"87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e", "message digest"},
		TestHash{"649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},   
    };
    test(ripemd256TestVectors[:], "RIPEMD-256");
    // RIPEMD-320          //
    ripemd320TestVectors := [?]TestHash {
        TestHash{"22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8", ""},
		TestHash{"ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d", "a"},
		TestHash{"de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d", "abc"},
		TestHash{"3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197", "message digest"},
		TestHash{"cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},   
    };
    test(ripemd320TestVectors[:], "RIPEMD-320");
    // =================== //
    // HAVAL Series       //
    // HAVAL-3-128        //
    // @note(bp): Haval needs more test strings!
    haval_3_128TestVectors := [?]TestHash {
        TestHash{"c68f39913f901f3ddf44c707357a7d70", ""},
		TestHash{"0cd40739683e15f01ca5dbceef4059f1", "a"},
		TestHash{"9e40ed883fb63e985d299b40cda2b8f2", "abc"},
		TestHash{"3caf4a79e81adcd6d1716bcc1cef4573", "message digest"},
		TestHash{"dc502247fb3eb8376109eda32d361d82", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"44068770868768964d1f2c3bff4aa3d8", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"de5eb3f7d9eb08fae7a07d68e3047ec6", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},  
    };
    test(haval_3_128TestVectors[:], "HAVAL-3-128");
    // HAVAL-3-160       //
    haval_3_160TestVectors := [?]TestHash {
        TestHash{"d353c3ae22a25401d257643836d7231a9a95f953", ""},
		TestHash{"4da08f514a7275dbc4cece4a347385983983a830", "a"},
        TestHash{"b21e876c4d391e2a897661149d83576b5530a089", "abc"},
		TestHash{"43a47f6f1c016207f08be8115c0977bf155346da", "message digest"},
		TestHash{"eba9fa6050f24c07c29d1834a60900ea4e32e61b", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"c30bce448cf8cfe957c141e90c0a063497cdfeeb", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"97dc988d97caae757be7523c4e8d4ea63007a4b9", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"}, 
    };
    test(haval_3_160TestVectors[:], "HAVAL-3-160");
    // HAVAL-3-192       //
    haval_3_192TestVectors := [?]TestHash {
        TestHash{"e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e", ""},
		TestHash{"b359c8835647f5697472431c142731ff6e2cddcacc4f6e08", "a"},
    };
    test(haval_3_192TestVectors[:], "HAVAL-3-192");
    // HAVAL-3-224       //
    haval_3_224TestVectors := [?]TestHash {
        TestHash{"c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d", ""},
		TestHash{"731814ba5605c59b673e4caae4ad28eeb515b3abc2b198336794e17b", "a"},
    };
    test(haval_3_224TestVectors[:], "HAVAL-3-224");
    // HAVAL-3-256       //
    haval_3_256TestVectors := [?]TestHash {
        TestHash{"4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17", ""},
		TestHash{"47c838fbb4081d9525a0ff9b1e2c05a98f625714e72db289010374e27db021d8", "a"},
    };
    test(haval_3_256TestVectors[:], "HAVAL-3-256");
    // HAVAL-4-128        //
    haval_4_128TestVectors := [?]TestHash {
        TestHash{"ee6bbf4d6a46a679b3a856c88538bb98", ""},
		TestHash{"5cd07f03330c3b5020b29ba75911e17d", "a"},
    };
    test(haval_4_128TestVectors[:], "HAVAL-4-128");
    // HAVAL-4-160       //
    haval_4_160TestVectors := [?]TestHash {
        TestHash{"1d33aae1be4146dbaaca0b6e70d7a11f10801525", ""},
		TestHash{"e0a5be29627332034d4dd8a910a1a0e6fe04084d", "a"},
    };
    test(haval_4_160TestVectors[:], "HAVAL-4-160");
    // HAVAL-4-192       //
    haval_4_192TestVectors := [?]TestHash {
        TestHash{"4a8372945afa55c7dead800311272523ca19d42ea47b72da", ""},
		TestHash{"856c19f86214ea9a8a2f0c4b758b973cce72a2d8ff55505c", "a"},
    };
    test(haval_4_192TestVectors[:], "HAVAL-4-192");
    // HAVAL-4-224       //
    haval_4_224TestVectors := [?]TestHash {
        TestHash{"3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e", ""},
		TestHash{"742f1dbeeaf17f74960558b44f08aa98bdc7d967e6c0ab8f799b3ac1", "a"},
    };
    test(haval_4_224TestVectors[:], "HAVAL-4-224");
    // HAVAL-4-256       //
    haval_4_256TestVectors := [?]TestHash {
        TestHash{"c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b", ""},
		TestHash{"e686d2394a49b44d306ece295cf9021553221db132b36cc0ff5b593d39295899", "a"},
    };
    test(haval_4_256TestVectors[:], "HAVAL-4-256");
    // HAVAL-5-128        //
    haval_5_128TestVectors := [?]TestHash {
        TestHash{"184b8482a0c050dca54b59c7f05bf5dd", ""},
		TestHash{"f23fbe704be8494bfa7a7fb4f8ab09e5", "a"},
    };
    test(haval_5_128TestVectors[:], "HAVAL-5-128");
    // HAVAL-5-160       //
    haval_5_160TestVectors := [?]TestHash {
        TestHash{"255158cfc1eed1a7be7c55ddd64d9790415b933b", ""},
		TestHash{"f5147df7abc5e3c81b031268927c2b5761b5a2b5", "a"},
    };
    test(haval_5_160TestVectors[:], "HAVAL-5-160");
    // HAVAL-5-192       //
    haval_5_192TestVectors := [?]TestHash {
        TestHash{"4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85", ""},
		TestHash{"5ffa3b3548a6e2cfc06b7908ceb5263595df67cf9c4b9341", "a"},
    };
    test(haval_5_192TestVectors[:], "HAVAL-5-192");
    // HAVAL-5-224       //
    haval_5_224TestVectors := [?]TestHash {
        TestHash{"4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e", ""},
		TestHash{"67b3cb8d4068e3641fa4f156e03b52978b421947328bfb9168c7655d", "a"},
    };
    test(haval_5_224TestVectors[:], "HAVAL-5-224");
    // HAVAL-5-256       //
    haval_5_256TestVectors := [?]TestHash {
        TestHash{"be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330", ""},
		TestHash{"de8fd5ee72a5e4265af0a756f4e1a1f65c9b2b2f47cf17ecf0d1b88679a3e22f", "a"},
    };
    test(haval_5_256TestVectors[:], "HAVAL-5-256");
    // =================== //
}