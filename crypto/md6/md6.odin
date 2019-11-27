package md6

import "core:fmt"
import "core:math"

MD6 :: struct {
    data: []byte,
    size: u32,
    key: [64]byte,
    levels: u32,
};

b :: 512;
c :: 256;

to_word :: inline proc "contextless"(input: []byte) -> []u32 {
    output: [dynamic]u32;
    for i := 0; i < len(input); i += 8 {
       /* append(&output, 
            u32(((input[i + 0] & 0xff) << 24) |
            ((input[i + 1] & 0xff) << 16) |
            ((input[i + 2] & 0xff) << 8)  |
            ((input[i + 3] & 0xff) << 0)));

        append(&output, 
            u32(((input[i + 4] & 0xff) << 24) |
            ((input[i + 5] & 0xff) << 16) |
            ((input[i + 6] & 0xff) << 8)  |
            ((input[i + 7] & 0xff) << 0)));*/

        append(&output, 
            u32(0 | 0 | 0 | 0));
        append(&output, 
           u32(0 | 0 | 0 | 0));
    }

    return output[:];
}

from_word :: inline proc "contextless"(input: [][]byte) -> []byte {
    output: [dynamic]byte;
    for i in 0..<len(input) {
        append(&output, (input[i][0] >> 24) & 0xff);
        append(&output, (input[i][0] >> 16) & 0xff);
        append(&output, (input[i][0] >> 8)  & 0xff);
        append(&output, (input[i][0] >> 0)  & 0xff);
        append(&output, (input[i][1] >> 24) & 0xff);
        append(&output, (input[i][1] >> 16) & 0xff);
        append(&output, (input[i][1] >> 8)  & 0xff);
        append(&output, (input[i][1] >> 0)  & 0xff);
    }
    return output[:];
}

seq :: inline proc(M: []byte) ->[]byte {
    length := len(M);
    i, l, p, z, P: int;
    B := [dynamic]byte;
    C := [16][2]byte = {{0x0, 0x0}, {0x0, 0x0}, {0x0, 0x0},
                        {0x0, 0x0}, {0x0, 0x0}, {0x0, 0x0},
                        {0x0, 0x0}, {0x0, 0x0}, {0x0, 0x0},
                        {0x0, 0x0}, {0x0, 0x0}, {0x0, 0x0},
                        {0x0, 0x0}, {0x0, 0x0}, {0x0, 0x0},
                        {0x0, 0x0}};

    for (length < 1) || ((length % (b - c)) > 0) {
        
    }

    return nil;
}

/*
function seq(M) {
                var i, l, p, z, P = 0,
                    B = [],
                    C = [
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0],
                        [0x0, 0x0]
                    ];

                while ((M.length < 1) || ((M.length % (b - c)) > 0)) {
                    M.push(0x00);
                    P += 8;
                }

                M = to_word(M);

                while (M.length > 0) {
                    B.push(M.slice(0, ((b - c) / 8)));
                    M = M.slice((b - c) / 8);
                }

                for (i = 0, p = 0, l = B.length; i < l; i += 1, p = 0) {
                    p = (i === (B.length - 1)) ? P : 0;
                    z = (i === (B.length - 1)) ? 1 : 0;
                    C = mid(B[i], C, i, p, z);
                }

                return from_word(C);
            }

 */

md6_hash :: proc(ctx: ^MD6) -> [32]byte {
    hash: [32]byte;

    n := 89;

    d := ctx.size;
    M := ctx.data;

    K := to_word(ctx.key[0:64]);

    r := max((len(K) > 0 ? 80 : 0), (40 + (d / 4)));
    L := ctx.levels;
    ell := 0;

    S0: [2]u32 = {0x01234567, 0x89abcdef};
    Sm: [2]u32 = {0x7311c281, 0x2425cfa0};

    Q: [15][2]u32 = {
        {0x7311c281, 0x2425cfa0},
        {0x64322864, 0x34aac8e7},
        {0xb60450e9, 0xef68b7c1},
        {0xe8fb2390, 0x8d9f06f1},
        {0xdd2e76cb, 0xa691e5bf},
        {0x0cd0d63b, 0x2c30bc41},
        {0x1f8ccf68, 0x23058f8a},
        {0x54e5ed5b, 0x88e3775d},
        {0x4ad12aae, 0x0a6d6031},
        {0x3e7f16bb, 0x88222e0d},
        {0x8af8671d, 0x3fb50c2c},
        {0x995ad117, 0x8bd25c31},
        {0xc878c1dd, 0x04c4b633},
        {0x3b72066c, 0x7a1552ac},
        {0x0d6f3522, 0x631effcb}
    };

    t: [6]u32 = {17, 18, 21, 31, 67, 89};
    rs: [16]u32 = {10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12};
    ls: [16]u32 = {11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9};

    ell += 1;
    M = ell > L ? seq(M) : par(M);
    for len(M) != c {
        ell += 1;
        M = ell > L ? seq(M) : par(M);
    }


    length := int(math.floor(f64(ctx.size + 7) / 8));
    remain := ctx.size % 8;
    if remain > 0 do hash[length - 1] &= (0xff << (8 -  remain)) & 0xff;

    return hash;
}

hash_256 :: proc(data: []byte) -> [32]byte {
    ctx: MD6;
    ctx.data = data;
    ctx.size = 256;
    hash := md6_hash(&ctx);

    return hash;
}

main :: proc() {

    data := "";

    h := hash_256(([]byte)(data));
    fmt.println(h);
}