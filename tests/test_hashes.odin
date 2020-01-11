package test_hashes

import "core:fmt"
import "../crypto/md2"
import "../crypto/md4"
import "../crypto/md5"
//import "../crypto/md6"
import "../crypto/sha1"
import "../crypto/sha2"
import "../crypto/sha3"
import "../crypto/blake"
import "../crypto/blake2s"
import "../crypto/blake2b"
import "../crypto/ripemd"
import "../crypto/haval"
import "../crypto/gost"
import "../crypto/streebog"
import "../crypto/whirlpool"
import "../crypto/tiger"
import "../crypto/tiger2"
import "../crypto/jh"
import "../crypto/groestl"
import "../crypto/skein"

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
                out:= md2.hash(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "MD4":
                out:= md4.hash(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "MD5":
                out:= md5.hash(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
           /* case "MD6-128":
                out:= md6.hash_128(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "MD6-256":
                out:= md6.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "MD6-512":
                out:= md6.hash_512(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;*/

            // SHA
            case "SHA1":
                out:= sha1.hash(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // SHA2
            /*case "SHA-224":
                out:= sha2.hash_224(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA-256":
                out:= sha2.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA-384":
                out:= sha2.hash_384(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA-512":
                out:= sha2.hash_512(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;*/
            
            // SHA3
            case "SHA3-224":
                out := sha3.hash_224(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA3-256":
                out := sha3.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA3-384":
                out := sha3.hash_384(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "SHA3-512":
                out := sha3.hash_512(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // BLAKE
            case "BLAKE-224":
                out:= blake.hash_224(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "BLAKE-256":
                out:= blake.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "BLAKE-384":
                out:= blake.hash_384(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "BLAKE-512":
                out:= blake.hash_512(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            
            // BLAKE2
            case "BLAKE2S-256":
                out:= blake2s.hash(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "BLAKE2B-512":
                out:= blake2b.hash(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            
            // RIPEMD
            case "RIPEMD-128":
                out:= ripemd.hash_128(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "RIPEMD-160":
                out:= ripemd.hash_160(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "RIPEMD-256":
                out:= ripemd.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "RIPEMD-320":
                out:= ripemd.hash_320(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // HAVAL
            case "HAVAL-3-128":
                out:= haval.hash_3_128(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-3-160":
                out:= haval.hash_3_160(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-3-192":
                out:= haval.hash_3_192(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-3-224":
                out:= haval.hash_3_224(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-3-256":
                out:= haval.hash_3_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-128":
                out:= haval.hash_4_128(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-160":
                out:= haval.hash_4_160(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-192":
                out:= haval.hash_4_192(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-224":
                out:= haval.hash_4_224(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-4-256":
                out:= haval.hash_4_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-128":
                out:= haval.hash_5_128(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-160":
                out:= haval.hash_5_160(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-192":
                out:= haval.hash_5_192(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-224":
                out:= haval.hash_5_224(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "HAVAL-5-256":
                out:= haval.hash_5_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // GOST
            case "GOST":
                out:= gost.hash(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // STREEBOG
            case "STREEBOG-256":
                out:= streebog.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "STREEBOG-512":
                out:= streebog.hash_512(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // WHIRLPOOL
            case "WHIRLPOOL":
                out:= whirlpool.hash(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            
            // Tiger
            case "TIGER-128":
                out:= tiger.hash_128(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "TIGER-160":
                out:= tiger.hash_160(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return; 
            case "TIGER-192":
                out:= tiger.hash_192(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "TIGER2-128":
                out:= tiger2.hash_128(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "TIGER2-160":
                out:= tiger2.hash_160(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return; 
            case "TIGER2-192":
                out:= tiger2.hash_192(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            
            // JH
            case "JH-224":
                out:= jh.hash_224(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "JH-256":
                out:= jh.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "JH-384":
                out:= jh.hash_384(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "JH-512":
                out:= jh.hash_512(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // GROESTL
            case "GROESTL-224":
                out:= groestl.hash_224(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "GROESTL-256":
                out:= groestl.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "GROESTL-384":
                out:= groestl.hash_384(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "GROESTL-512":
                out:= groestl.hash_512(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;

            // Skein
            case "Skein-256":
                out:= skein.hash_256(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "Skein-512":
                out:= skein.hash_512(transmute([]byte)(s.str));
                if !check_hash(out[:], s.hash, s.str, algo) do return;
            case "Skein-1024":
                out:= skein.hash_1024(transmute([]byte)(s.str));
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
   /* // MD6-256             //
    md6_256TestVectors := [?]TestHash {
        TestHash{"bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca", ""},
        TestHash{"2b0a697a081c21269514640aab4d74ffafeb3c0212df68ce92922087c69b0a77", "a"},
    };
    test(md6_256TestVectors[:], "MD6-256");*/
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
    // SHA-224              //
    sha224TestVectors := [?]TestHash {
        TestHash{"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", ""},
        TestHash{"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "abc"},
    };
    test(sha224TestVectors[:], "SHA-224");
    // SHA-256              //
    sha256TestVectors := [?]TestHash {
        TestHash{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
        TestHash{"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc"},
    };
    test(sha256TestVectors[:], "SHA-256");
    // SHA-384              //
    sha384TestVectors := [?]TestHash {
        TestHash{"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", ""},
        TestHash{"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "abc"},
    };
    test(sha384TestVectors[:], "SHA-384");
    // SHA-512              //
    sha512TestVectors := [?]TestHash {
        TestHash{"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
        TestHash{"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "abc"},
    };
    test(sha512TestVectors[:], "SHA-512");
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
    // STREEBOG            //
    // STREEBOG-256        //
    streebog_256TestVectors := [?]TestHash {
        TestHash{"3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb", ""},
        TestHash{"3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4", "The quick brown fox jumps over the lazy dog"},
        TestHash{"36816a824dcbe7d6171aa58500741f2ea2757ae2e1784ab72c5c3c6c198d71da", "The quick brown fox jumps over the lazy dog."},
    };
    test(streebog_256TestVectors[:], "STREEBOG-256");
    // STREEBOG-512        //
    streebog_512TestVectors := [?]TestHash {
        TestHash{"8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a", ""},
        TestHash{"d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe", "The quick brown fox jumps over the lazy dog"},
        TestHash{"fe0c42f267d921f940faa72bd9fcf84f9f1bd7e9d055e9816e4c2ace1ec83be82d2957cd59b86e123d8f5adee80b3ca08a017599a9fc1a14d940cf87c77df070", "The quick brown fox jumps over the lazy dog."},
    };
    test(streebog_512TestVectors[:], "STREEBOG-512");
    // =================== //
    // WHIRLPOOL           //
    whirlpoolTestVectors := [?]TestHash {
        TestHash{"19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3", ""},
        TestHash{"8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a", "a"},
        TestHash{"33e24e6cbebf168016942df8a7174048f9cebc45cbd829c3b94b401a498acb11c5abcca7f2a1238aaf534371e87a4e4b19758965d5a35a7cad87cf5517043d97", "ab"},
        TestHash{"4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5", "abc"},
        TestHash{"bda164f0b930c43a1bacb5df880b205d15ac847add35145bf25d991ae74f0b72b1ac794f8aacda5fcb3c47038c954742b1857b5856519de4d1e54bfa2fa4eac5", "abcd"},
        TestHash{"5d745e26ccb20fe655d39c9e7f69455758fbae541cb892b3581e4869244ab35b4fd6078f5d28b1f1a217452a67d9801033d92724a221255a5e377fe9e9e5f0b2", "abcde"},
        TestHash{"a73e425459567308ba5f9eb2ae23570d0d0575eb1357ecf6ac88d4e0358b0ac3ea2371261f5d4c070211784b525911b9eec0ad968429bb7c7891d341cff4e811", "abcdef"},
        TestHash{"08b388f68fd3eb51906ac3d3c699b8e9c3ac65d7ceb49d2e34f8a482cbc3082bc401cead90e85a97b8647c948bf35e448740b79659f3bee42145f0bd653d1f25", "abcdefg"},
        TestHash{"1f1a84d30612820243afe2022712f9dac6d07c4c8bb41b40eacab0184c8d82275da5bcadbb35c7ca1960ff21c90acbae8c14e48d9309e4819027900e882c7ad9", "abcdefgh"},
        TestHash{"11882bc9a31ac1cf1c41dcd9fd6fdd3ccdb9b017fc7f4582680134f314d7bb49af4c71f5a920bc0a6a3c1ff9a00021bf361d9867fe636b0bc1da1552e4237de4", "abcdefghi"},
        TestHash{"717163de24809ffcf7ff6d5aba72b8d67c2129721953c252a4ddfb107614be857cbd76a9d5927de14633d6bdc9ddf335160b919db5c6f12cb2e6549181912eef", "abcdefghij"},
        TestHash{"b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35", "The quick brown fox jumps over the lazy dog"},
        TestHash{"c27ba124205f72e6847f3e19834f925cc666d0974167af915bb462420ed40cc50900d85a1f923219d832357750492d5c143011a76988344c2635e69d06f2d38c", "The quick brown fox jumps over the lazy eog"},
    };
    test(whirlpoolTestVectors[:], "WHIRLPOOL");
    // =================== //
    // GOST                //
    gostTestVectors := [?]TestHash {
        TestHash{"ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d", ""},
        TestHash{"d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd", "a"},
        TestHash{"ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d", "message digest"},
    };
    test(gostTestVectors[:], "GOST");
    // =================== //
    // TIGER               //
    // TIGER-128           //
    tiger128TestVectors := [?]TestHash {
        TestHash{"3293ac630c13f0245f92bbb1766e1616", ""},
        TestHash{"77befbef2e7ef8ab2ec8f93bf587a7fc", "a"},
	    TestHash{"2aab1484e8c158f2bfb8c5ff41b57a52", "abc"},
        TestHash{"d981f8cb78201a950dcf3048751e441c", "message digest"},
        TestHash{"1714a472eee57d30040412bfcc55032a", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"0f7bf9a19b9c58f2b7610df7e84f0ac3", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"8dcea680a17583ee502ba38a3c368651", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        TestHash{"1c14795529fd9f207a958f84c52f11e8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
        TestHash{"6d12a41e72e644f017b6f0e2f7b44c62", "The quick brown fox jumps over the lazy dog"},
    };
    test(tiger128TestVectors[:], "TIGER-128");
    // TIGER-160           //
    tiger160TestVectors := [?]TestHash {
        TestHash{"3293ac630c13f0245f92bbb1766e16167a4e5849", ""},
        TestHash{"77befbef2e7ef8ab2ec8f93bf587a7fc613e247f", "a"},
	    TestHash{"2aab1484e8c158f2bfb8c5ff41b57a525129131c", "abc"},
        TestHash{"d981f8cb78201a950dcf3048751e441c517fca1a", "message digest"},
        TestHash{"1714a472eee57d30040412bfcc55032a0b11602f", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"8dcea680a17583ee502ba38a3c368651890ffbcc", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        //TestHash{"1c14795529fd9f207a958f84c52f11e887fa0cab", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
        TestHash{"6d12a41e72e644f017b6f0e2f7b44c6285f06dd5", "The quick brown fox jumps over the lazy dog"},
    };
    test(tiger160TestVectors[:], "TIGER-160");
    // TIGER-192             //
    tiger192TestVectors := [?]TestHash {
        TestHash{"3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3", ""},
        TestHash{"77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809", "a"},
	    TestHash{"2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93", "abc"},
        TestHash{"d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6", "message digest"},
        TestHash{"1714a472eee57d30040412bfcc55032a0b11602ff37beee9", "abcdefghijklmnopqrstuvwxyz"},
        TestHash{"0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
        TestHash{"8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
        TestHash{"1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
        TestHash{"6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075", "The quick brown fox jumps over the lazy dog"},
    };
    test(tiger192TestVectors[:], "TIGER-192");
    // TIGER2-128             //
    tiger2128TestVectors := [?]TestHash {
        TestHash{"4441be75f6018773c206c22745374b92", ""},
        TestHash{"976abff8062a2e9dcea3a1ace966ed9c", "The quick brown fox jumps over the lazy dog"},
        TestHash{"09c11330283a27efb51930aa7dc1ec62", "The quick brown fox jumps over the lazy cog"},
    };
    test(tiger2128TestVectors[:], "TIGER2-128");
    // TIGER2-160             //
    tiger2160TestVectors := [?]TestHash {
        TestHash{"4441be75f6018773c206c22745374b924aa8313f", ""},
        TestHash{"976abff8062a2e9dcea3a1ace966ed9c19cb8555", "The quick brown fox jumps over the lazy dog"},
        TestHash{"09c11330283a27efb51930aa7dc1ec624ff738a8", "The quick brown fox jumps over the lazy cog"},
    };
    test(tiger2160TestVectors[:], "TIGER2-160");
    // TIGER2-192             //
    tiger2192TestVectors := [?]TestHash {
        TestHash{"4441be75f6018773c206c22745374b924aa8313fef919f41", ""},
        TestHash{"976abff8062a2e9dcea3a1ace966ed9c19cb85558b4976d8", "The quick brown fox jumps over the lazy dog"},
        TestHash{"09c11330283a27efb51930aa7dc1ec624ff738a8d9bdd3df", "The quick brown fox jumps over the lazy cog"},
    };
    test(tiger2192TestVectors[:], "TIGER2-192");
    // =================== //
    // JH                  //
    // JH-224              //
    jh224TestVectors := [?]TestHash {
        TestHash{"2c99df889b019309051c60fecc2bd285a774940e43175b76b2626630", ""},
        TestHash{"e715f969fb61b203a97e494aab92d91a9cec52f0933436b0d63bf722", "a"},
        TestHash{"c2b1967e635bd55b6a4d36f863ac4a877be302251d68692873007281", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };
    test(jh224TestVectors[:], "JH-224");
    // JH-256              //
    jh256TestVectors := [?]TestHash {
        TestHash{"46e64619c18bb0a92a5e87185a47eef83ca747b8fcc8e1412921357e326df434", ""},
        TestHash{"d52c0c130a1bc0ae5136375637a52773e150c71efe1c968df8956f6745b05386", "a"},
        TestHash{"fc4214867025a8af94c614353b3553b10e561ae749fc18c40e5fd44a7a4ecd1b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };
    test(jh256TestVectors[:], "JH-256");
    // JH-384              //
    jh384TestVectors := [?]TestHash {
        TestHash{"2fe5f71b1b3290d3c017fb3c1a4d02a5cbeb03a0476481e25082434a881994b0ff99e078d2c16b105ad069b569315328", ""},
        TestHash{"77de897ca4fd5dadfbcbd1d8d4ea3c3c1426855e38661325853e92b069f3fe156729f6bbb9a5892c7c18a77f1cb9d0bb", "a"},
        TestHash{"6f73d9b9b8ed362f8180fb26020725b40bd6ca75b3b947405f26c4c37a885ce028876dc42e379d2faf6146fed3ea0e42", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };
    test(jh384TestVectors[:], "JH-384");
    // JH-512              //
    jh512TestVectors := [?]TestHash {
        TestHash{"90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fabe69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f", ""},
        TestHash{"f12c87e986daff17c481c81a99a39b603ca6bafcd320c5735523b97cb9a26f7681bad62ffad9aad0e21160a05f773fb0d1434ca4cbcb0483f480a171ada1561b", "a"},
        TestHash{"bafb8e710b35eabeb1a48220c4b0987c2c985b6e73b7b31d164bfb9d67c94d99d7bc43b474a25e647cd6cc36334b6a00a5f2a85fae74907fd2885c6168132fe7", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };
    test(jh512TestVectors[:], "JH-512");
    // =================== //
    // GROESTL                  //
    // GROESTL-224              //
    groestl224TestVectors := [?]TestHash {
        TestHash{"f2e180fb5947be964cd584e22e496242c6a329c577fc4ce8c36d34c3", ""},
        TestHash{"2dfa5bd326c23c451b1202d99e6cee98a98c45927e1a31077f538712", "a"},
        TestHash{"c8a3e7274d599900ae673419683c3626a2e49ed57308ed2687508bef", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };
    test(groestl224TestVectors[:], "GROESTL-224");
    // GROESTL-256              //
    groestl256TestVectors := [?]TestHash {
        TestHash{"1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467", ""},
        TestHash{"3645c245bb31223ad93c80885b719aa40b4bed0a9d9d6e7c11fe99e59ca350b5", "a"},
        TestHash{"2679d98913bee62e57fdbdde97ddb328373548c6b24fc587cc3d08f2a02a529c", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };
    test(groestl256TestVectors[:], "GROESTL-256");
    // GROESTL-384              //
    groestl384TestVectors := [?]TestHash {
        TestHash{"ac353c1095ace21439251007862d6c62f829ddbe6de4f78e68d310a9205a736d8b11d99bffe448f57a1cfa2934f044a5", ""},
        TestHash{"13fce7bd9fc69b67cc12c77e765a0a97794c585f89df39fbff32408e060d7d9225c7e80fd87da647686888bda896c342", "a"},
        TestHash{"1c446cd70a6de52c9db386f5305aae029fe5a4120bc6230b7cd3a5e1ef1949cc8e6d2548c24cd7347b5ba512628a62f6", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };
    test(groestl384TestVectors[:], "GROESTL-384");
    // GROESTL-512              //
    groestl512TestVectors := [?]TestHash {
        TestHash{"6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8", ""},
        TestHash{"9ef345a835ee35d6d0d462ce45f722d84b5ca41fde9c81a98a22cfb4f7425720511b03a258cdc055bf8e9179dc9bdb5d88bed906c71125d4cf0cd39d3d7bebc7", "a"},
        TestHash{"862849fd911852cd54beefa88759db4cead0ef8e36aaf15398303c5c4cbc016d9b4c42b32081cbdcba710d2693e7663d244fae116ec29ffb40168baf44f944e7", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
    };
    test(groestl512TestVectors[:], "GROESTL-512");
    // =================== //
    // Skein               //
    // Skein-256           //
    skein256TestVectors := [?]TestHash {
        TestHash{"c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba", ""},
        //TestHash{"c0fbd7d779b20f0a4614a66697f9e41859eaf382f14bf857e8cdb210adb9b3fe", "The quick brown fox jumps over the lazy dog"},
    };
    test(skein256TestVectors[:], "Skein-256");
    /*// Skein-512           //
    skein512TestVectors := [?]TestHash {
        TestHash{"94c2ae036dba8783d0b3f7d6cc111ff810702f5c77707999be7e1c9486ff238a7044de734293147359b4ac7e1d09cd247c351d69826b78dcddd951f0ef912713", "The quick brown fox jumps over the lazy dog"},
    };
    test(skein512TestVectors[:], "Skein-512");
    // Skein-1024          //
    skein1024TestVectors := [?]TestHash {
        TestHash{"4cf6152f1a7e598098d28f04e13d7742ba39b7fadbbcf2167bda4e1615d551f3f6b4edbbb391ffa09e6cc0a4af1eb366b30b5f107b437e2ea5cb586afb0341bd97dabe7cc46e7be3a054aa605395e43b243654c01ffc14c8b5443488f35d80b504a612f3d29d767106d0d9249aaa4fd99b67a94fb8661a3520004501192d84fa", "The quick brown fox jumps over the lazy dog"},
    };
    test(skein1024TestVectors[:], "Skein-1024");*/
}