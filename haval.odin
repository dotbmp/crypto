package crypto

import "core:mem"
import "core:fmt"

// @ref(bp): https://web.archive.org/web/20150111210116/http://labs.calyptix.com/haval.php
// HAVAL stub
// @question(bp): what license is HAVAL under?
// reference implementation:
// @ref(bp): ./refs/haval-1.1.tar.gz

HAVAL_VERSION :: 1;

HAVAL :: struct {
    count: [2]u32,
    fingerprint: [8]u32,
    block: [32]u32,
    remainder: [128]u8,
};

HAVAL_ROTR32 :: inline proc "contextless"(a, b : u32) -> u32 {
    return ((a >> b) | (a << (32-b)));
}

HAVAL_PADDING := [128]u8 {
0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

HAVAL_F_1 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32) -> u32 {
    return ((x1) & ((x0) ~ (x4)) ~ (x2) & (x5) ~ (x3) & (x6) ~ (x0));
}

HAVAL_F_2 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32) -> u32 {
    return ((x2) & ((x1) & ~(x3) ~ (x4) & (x5) ~ (x6) ~ (x0)) ~ (x4) & ((x1) ~ (x5)) ~ (x3) & (x5) ~ (x0));
}

HAVAL_F_3 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32) -> u32 {
    return ((x3) & ((x1) & (x2) ~ (x6) ~ (x0)) ~ (x1) & (x4) ~ (x2) & (x5) ~ (x0));
}

HAVAL_F_4 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32) -> u32 {
    return ((x4) & ((x5) & ~(x2) ~ (x3) & ~(x6) ~ (x1) ~ (x6) ~ (x0)) ~ (x3) & ((x1) & (x2) ~ (x5) ~ (x6)) ~ (x2) & (x6) ~ (x0));
}

HAVAL_F_5 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32) -> u32 {
    return ((x0) & ((x1) & (x2) & (x3) ~ ~(x5)) ~ (x1) & (x4) ~ (x2) & (x5) ~ (x3) & (x6));
}

HAVAL_FPHI_1 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0, rounds: u32) -> u32 {
    switch rounds {
        case 3: return HAVAL_F_1(x1, x0, x3, x5, x6, x2, x4);
        case 4: return HAVAL_F_1(x2, x6, x1, x4, x5, x3, x0);
        case 5: return HAVAL_F_1(x3, x4, x1, x0, x5, x2, x6);
        case: assert(rounds < 3 || rounds > 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FPHI_2 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0, rounds: u32) -> u32 {
    switch rounds {
        case 3: return HAVAL_F_2(x4, x2, x1, x0, x5, x3, x6);
        case 4: return HAVAL_F_2(x3, x5, x2, x0, x1, x6, x4);
        case 5: return HAVAL_F_2(x6, x2, x1, x0, x3, x4, x5);
        case: assert(rounds < 3 || rounds > 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FPHI_3 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0, rounds: u32) -> u32 {
    switch rounds {
        case 3: return HAVAL_F_3(x6, x1, x2, x3, x4, x5, x0);
        case 4: return HAVAL_F_3(x1, x4, x3, x6, x0, x2, x5);
        case 5: return HAVAL_F_3(x2, x6, x0, x4, x3, x1, x5);
        case: assert(rounds < 3 || rounds > 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FPHI_4 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0, rounds: u32) -> u32 {
    switch rounds {
        case 4: return HAVAL_F_5(x6, x4, x0, x5, x2, x1, x3);
        case 5: return HAVAL_F_5(x1, x5, x3, x2, x0, x4, x6);
        case: assert(rounds < 4 || rounds > 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FPHI_5 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0, rounds: u32) -> u32 {
    switch rounds {
        case 5: return HAVAL_F_5(x2, x5, x0, x6, x4, x3, x1);
        case: assert(rounds != 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FF_1 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, rounds: u32) -> u32 {
    tmp := HAVAL_FPHI_1(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w;
    return x7;
}

HAVAL_FF_2 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, c, rounds: u32) -> u32 {
    tmp := HAVAL_FPHI_2(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w + c;
    return x7;
}

HAVAL_FF_3 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, c, rounds: u32) -> u32 {
    tmp := HAVAL_FPHI_3(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w + c;
    return x7;
}

HAVAL_FF_4 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, c, rounds: u32) -> u32 {
    tmp := HAVAL_FPHI_4(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w + c;
    return x7;
}

HAVAL_FF_5 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, c, rounds: u32) -> u32 {
    tmp := HAVAL_FPHI_5(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w + c;
    return x7;
}

HAVAL_CH2UINT :: inline proc "contextless" (str: []u8, word: []u32) {
    for _, i in word[:32] {
        word[i] = u32(str[i*4+0]) << 0 | u32(str[i*4+1]) << 8 | u32(str[i*4+2]) << 16 | u32(str[i*4+3]) << 24;
    }
}

HAVAL_UINT2CH :: inline proc "contextless"(word: []u32, str: []u8, wlen: u32) {
    for _, i in word[:wlen] {
        str[i*4+0] = byte(word[i] >> 0) & 0xff;
        str[i*4+1] = byte(word[i] >> 8) & 0xff;
        str[i*4+2] = byte(word[i] >> 16) & 0xff;
        str[i*4+3] = byte(word[i] >> 24) & 0xff;
    }
}

haval_block :: proc(ctx: ^HAVAL, rounds: u32) {
    t0, t1, t2, t3 := ctx.fingerprint[0], ctx.fingerprint[1], ctx.fingerprint[2], ctx.fingerprint[3];
    t4, t5, t6, t7 := ctx.fingerprint[4], ctx.fingerprint[5], ctx.fingerprint[6], ctx.fingerprint[7]; 
    w := ctx.block;

    t7 = HAVAL_FF_1(t7, t6, t5, t4, t3, t2, t1, t0, w[ 0], rounds);
    t6 = HAVAL_FF_1(t6, t5, t4, t3, t2, t1, t0, t7, w[ 1], rounds);
    t5 = HAVAL_FF_1(t5, t4, t3, t2, t1, t0, t7, t6, w[ 2], rounds);
    t4 = HAVAL_FF_1(t4, t3, t2, t1, t0, t7, t6, t5, w[ 3], rounds);
    t3 = HAVAL_FF_1(t3, t2, t1, t0, t7, t6, t5, t4, w[ 4], rounds);
    t2 = HAVAL_FF_1(t2, t1, t0, t7, t6, t5, t4, t3, w[ 5], rounds);
    t1 = HAVAL_FF_1(t1, t0, t7, t6, t5, t4, t3, t2, w[ 6], rounds);
    t0 = HAVAL_FF_1(t0, t7, t6, t5, t4, t3, t2, t1, w[ 7], rounds);

    t7 = HAVAL_FF_1(t7, t6, t5, t4, t3, t2, t1, t0, w[ 8], rounds);
    t6 = HAVAL_FF_1(t6, t5, t4, t3, t2, t1, t0, t7, w[ 9], rounds);
    t5 = HAVAL_FF_1(t5, t4, t3, t2, t1, t0, t7, t6, w[10], rounds);
    t4 = HAVAL_FF_1(t4, t3, t2, t1, t0, t7, t6, t5, w[11], rounds);
    t3 = HAVAL_FF_1(t3, t2, t1, t0, t7, t6, t5, t4, w[12], rounds);
    t2 = HAVAL_FF_1(t2, t1, t0, t7, t6, t5, t4, t3, w[13], rounds);
    t1 = HAVAL_FF_1(t1, t0, t7, t6, t5, t4, t3, t2, w[14], rounds);
    t0 = HAVAL_FF_1(t0, t7, t6, t5, t4, t3, t2, t1, w[15], rounds);

    t7 = HAVAL_FF_1(t7, t6, t5, t4, t3, t2, t1, t0, w[16], rounds);
    t6 = HAVAL_FF_1(t6, t5, t4, t3, t2, t1, t0, t7, w[17], rounds);
    t5 = HAVAL_FF_1(t5, t4, t3, t2, t1, t0, t7, t6, w[18], rounds);
    t4 = HAVAL_FF_1(t4, t3, t2, t1, t0, t7, t6, t5, w[19], rounds);
    t3 = HAVAL_FF_1(t3, t2, t1, t0, t7, t6, t5, t4, w[20], rounds);
    t2 = HAVAL_FF_1(t2, t1, t0, t7, t6, t5, t4, t3, w[21], rounds);
    t1 = HAVAL_FF_1(t1, t0, t7, t6, t5, t4, t3, t2, w[22], rounds);
    t0 = HAVAL_FF_1(t0, t7, t6, t5, t4, t3, t2, t1, w[23], rounds);

    t7 = HAVAL_FF_1(t7, t6, t5, t4, t3, t2, t1, t0, w[24], rounds);
    t6 = HAVAL_FF_1(t6, t5, t4, t3, t2, t1, t0, t7, w[25], rounds);
    t5 = HAVAL_FF_1(t5, t4, t3, t2, t1, t0, t7, t6, w[26], rounds);
    t4 = HAVAL_FF_1(t4, t3, t2, t1, t0, t7, t6, t5, w[27], rounds);
    t3 = HAVAL_FF_1(t3, t2, t1, t0, t7, t6, t5, t4, w[28], rounds);
    t2 = HAVAL_FF_1(t2, t1, t0, t7, t6, t5, t4, t3, w[29], rounds);
    t1 = HAVAL_FF_1(t1, t0, t7, t6, t5, t4, t3, t2, w[30], rounds);
    t0 = HAVAL_FF_1(t0, t7, t6, t5, t4, t3, t2, t1, w[31], rounds);

    t7 = HAVAL_FF_2(t7, t6, t5, t4, t3, t2, t1, t0, w[ 5], 0x452821e6, rounds);
    t6 = HAVAL_FF_2(t6, t5, t4, t3, t2, t1, t0, t7, w[14], 0x38d01377, rounds);
    t5 = HAVAL_FF_2(t5, t4, t3, t2, t1, t0, t7, t6, w[26], 0xbe5466cf, rounds);
    t4 = HAVAL_FF_2(t4, t3, t2, t1, t0, t7, t6, t5, w[18], 0x34e90c6c, rounds);
    t3 = HAVAL_FF_2(t3, t2, t1, t0, t7, t6, t5, t4, w[11], 0xc0ac29b7, rounds);
    t2 = HAVAL_FF_2(t2, t1, t0, t7, t6, t5, t4, t3, w[28], 0xc97c50dd, rounds);
    t1 = HAVAL_FF_2(t1, t0, t7, t6, t5, t4, t3, t2, w[ 7], 0x3f84d5b5, rounds);
    t0 = HAVAL_FF_2(t0, t7, t6, t5, t4, t3, t2, t1, w[16], 0xb5470917, rounds);

    t7 = HAVAL_FF_2(t7, t6, t5, t4, t3, t2, t1, t0, w[ 0], 0x9216d5d9, rounds);
    t6 = HAVAL_FF_2(t6, t5, t4, t3, t2, t1, t0, t7, w[23], 0x8979fb1b, rounds);
    t5 = HAVAL_FF_2(t5, t4, t3, t2, t1, t0, t7, t6, w[20], 0xd1310ba6, rounds);
    t4 = HAVAL_FF_2(t4, t3, t2, t1, t0, t7, t6, t5, w[22], 0x98dfb5ac, rounds);
    t3 = HAVAL_FF_2(t3, t2, t1, t0, t7, t6, t5, t4, w[ 1], 0x2ffd72db, rounds);
    t2 = HAVAL_FF_2(t2, t1, t0, t7, t6, t5, t4, t3, w[10], 0xd01adfb7, rounds);
    t1 = HAVAL_FF_2(t1, t0, t7, t6, t5, t4, t3, t2, w[ 4], 0xb8e1afed, rounds);
    t0 = HAVAL_FF_2(t0, t7, t6, t5, t4, t3, t2, t1, w[ 8], 0x6a267e96, rounds);

    t7 = HAVAL_FF_2(t7, t6, t5, t4, t3, t2, t1, t0, w[30], 0xba7c9045, rounds);
    t6 = HAVAL_FF_2(t6, t5, t4, t3, t2, t1, t0, t7, w[ 3], 0xf12c7f99, rounds);
    t5 = HAVAL_FF_2(t5, t4, t3, t2, t1, t0, t7, t6, w[21], 0x24a19947, rounds);
    t4 = HAVAL_FF_2(t4, t3, t2, t1, t0, t7, t6, t5, w[ 9], 0xb3916cf7, rounds);
    t3 = HAVAL_FF_2(t3, t2, t1, t0, t7, t6, t5, t4, w[17], 0x0801f2e2, rounds);
    t2 = HAVAL_FF_2(t2, t1, t0, t7, t6, t5, t4, t3, w[24], 0x858efc16, rounds);
    t1 = HAVAL_FF_2(t1, t0, t7, t6, t5, t4, t3, t2, w[29], 0x636920d8, rounds);
    t0 = HAVAL_FF_2(t0, t7, t6, t5, t4, t3, t2, t1, w[ 6], 0x71574e69, rounds);

    t7 = HAVAL_FF_2(t7, t6, t5, t4, t3, t2, t1, t0, w[19], 0xa458fea3, rounds);
    t6 = HAVAL_FF_2(t6, t5, t4, t3, t2, t1, t0, t7, w[12], 0xf4933d7e, rounds);
    t5 = HAVAL_FF_2(t5, t4, t3, t2, t1, t0, t7, t6, w[15], 0x0d95748f, rounds);
    t4 = HAVAL_FF_2(t4, t3, t2, t1, t0, t7, t6, t5, w[13], 0x728eb658, rounds);
    t3 = HAVAL_FF_2(t3, t2, t1, t0, t7, t6, t5, t4, w[ 2], 0x718bcd58, rounds);
    t2 = HAVAL_FF_2(t2, t1, t0, t7, t6, t5, t4, t3, w[25], 0x82154aee, rounds);
    t1 = HAVAL_FF_2(t1, t0, t7, t6, t5, t4, t3, t2, w[31], 0x7b54a41d, rounds);
    t0 = HAVAL_FF_2(t0, t7, t6, t5, t4, t3, t2, t1, w[27], 0xc25a59b5, rounds);

    t7 = HAVAL_FF_3(t7, t6, t5, t4, t3, t2, t1, t0, w[19], 0x9c30d539, rounds);
    t6 = HAVAL_FF_3(t6, t5, t4, t3, t2, t1, t0, t7, w[ 9], 0x2af26013, rounds);
    t5 = HAVAL_FF_3(t5, t4, t3, t2, t1, t0, t7, t6, w[ 4], 0xc5d1b023, rounds);
    t4 = HAVAL_FF_3(t4, t3, t2, t1, t0, t7, t6, t5, w[20], 0x286085f0, rounds);
    t3 = HAVAL_FF_3(t3, t2, t1, t0, t7, t6, t5, t4, w[28], 0xca417918, rounds);
    t2 = HAVAL_FF_3(t2, t1, t0, t7, t6, t5, t4, t3, w[17], 0xb8db38ef, rounds);
    t1 = HAVAL_FF_3(t1, t0, t7, t6, t5, t4, t3, t2, w[ 8], 0x8e79dcb0, rounds);
    t0 = HAVAL_FF_3(t0, t7, t6, t5, t4, t3, t2, t1, w[22], 0x603a180e, rounds);

    t7 = HAVAL_FF_3(t7, t6, t5, t4, t3, t2, t1, t0, w[29], 0x6c9e0e8b, rounds);
    t6 = HAVAL_FF_3(t6, t5, t4, t3, t2, t1, t0, t7, w[14], 0xb01e8a3e, rounds);
    t5 = HAVAL_FF_3(t5, t4, t3, t2, t1, t0, t7, t6, w[25], 0xd71577c1, rounds);
    t4 = HAVAL_FF_3(t4, t3, t2, t1, t0, t7, t6, t5, w[12], 0xbd314b27, rounds);
    t3 = HAVAL_FF_3(t3, t2, t1, t0, t7, t6, t5, t4, w[24], 0x78af2fda, rounds);
    t2 = HAVAL_FF_3(t2, t1, t0, t7, t6, t5, t4, t3, w[30], 0x55605c60, rounds);
    t1 = HAVAL_FF_3(t1, t0, t7, t6, t5, t4, t3, t2, w[16], 0xe65525f3, rounds);
    t0 = HAVAL_FF_3(t0, t7, t6, t5, t4, t3, t2, t1, w[26], 0xaa55ab94, rounds);

    t7 = HAVAL_FF_3(t7, t6, t5, t4, t3, t2, t1, t0, w[31], 0x57489862, rounds);
    t6 = HAVAL_FF_3(t6, t5, t4, t3, t2, t1, t0, t7, w[15], 0x63e81440, rounds);
    t5 = HAVAL_FF_3(t5, t4, t3, t2, t1, t0, t7, t6, w[ 7], 0x55ca396a, rounds);
    t4 = HAVAL_FF_3(t4, t3, t2, t1, t0, t7, t6, t5, w[ 3], 0x2aab10b6, rounds);
    t3 = HAVAL_FF_3(t3, t2, t1, t0, t7, t6, t5, t4, w[ 1], 0xb4cc5c34, rounds);
    t2 = HAVAL_FF_3(t2, t1, t0, t7, t6, t5, t4, t3, w[ 0], 0x1141e8ce, rounds);
    t1 = HAVAL_FF_3(t1, t0, t7, t6, t5, t4, t3, t2, w[18], 0xa15486af, rounds);
    t0 = HAVAL_FF_3(t0, t7, t6, t5, t4, t3, t2, t1, w[27], 0x7c72e993, rounds);

    t7 = HAVAL_FF_3(t7, t6, t5, t4, t3, t2, t1, t0, w[13], 0xb3ee1411, rounds);
    t6 = HAVAL_FF_3(t6, t5, t4, t3, t2, t1, t0, t7, w[ 6], 0x636fbc2a, rounds);
    t5 = HAVAL_FF_3(t5, t4, t3, t2, t1, t0, t7, t6, w[21], 0x2ba9c55d, rounds);
    t4 = HAVAL_FF_3(t4, t3, t2, t1, t0, t7, t6, t5, w[10], 0x741831f6, rounds);
    t3 = HAVAL_FF_3(t3, t2, t1, t0, t7, t6, t5, t4, w[23], 0xce5c3e16, rounds);
    t2 = HAVAL_FF_3(t2, t1, t0, t7, t6, t5, t4, t3, w[11], 0x9b87931e, rounds);
    t1 = HAVAL_FF_3(t1, t0, t7, t6, t5, t4, t3, t2, w[ 5], 0xafd6ba33, rounds);
    t0 = HAVAL_FF_3(t0, t7, t6, t5, t4, t3, t2, t1, w[ 2], 0x6c24cf5c, rounds);

    if rounds >= 4 {
        t7 = HAVAL_FF_4(t7, t6, t5, t4, t3, t2, t1, t0, w[24], 0x7a325381, rounds);
        t6 = HAVAL_FF_4(t6, t5, t4, t3, t2, t1, t0, t7, w[ 4], 0x28958677, rounds);
        t5 = HAVAL_FF_4(t5, t4, t3, t2, t1, t0, t7, t6, w[ 0], 0x3b8f4898, rounds);
        t4 = HAVAL_FF_4(t4, t3, t2, t1, t0, t7, t6, t5, w[14], 0x6b4bb9af, rounds);
        t3 = HAVAL_FF_4(t3, t2, t1, t0, t7, t6, t5, t4, w[ 2], 0xc4bfe81b, rounds);
        t2 = HAVAL_FF_4(t2, t1, t0, t7, t6, t5, t4, t3, w[ 7], 0x66282193, rounds);
        t1 = HAVAL_FF_4(t1, t0, t7, t6, t5, t4, t3, t2, w[28], 0x61d809cc, rounds);
        t0 = HAVAL_FF_4(t0, t7, t6, t5, t4, t3, t2, t1, w[23], 0xfb21a991, rounds);

        t7 = HAVAL_FF_4(t7, t6, t5, t4, t3, t2, t1, t0, w[26], 0x487cac60, rounds);
        t6 = HAVAL_FF_4(t6, t5, t4, t3, t2, t1, t0, t7, w[ 6], 0x5dec8032, rounds);
        t5 = HAVAL_FF_4(t5, t4, t3, t2, t1, t0, t7, t6, w[30], 0xef845d5d, rounds);
        t4 = HAVAL_FF_4(t4, t3, t2, t1, t0, t7, t6, t5, w[20], 0xe98575b1, rounds);
        t3 = HAVAL_FF_4(t3, t2, t1, t0, t7, t6, t5, t4, w[18], 0xdc262302, rounds);
        t2 = HAVAL_FF_4(t2, t1, t0, t7, t6, t5, t4, t3, w[25], 0xeb651b88, rounds);
        t1 = HAVAL_FF_4(t1, t0, t7, t6, t5, t4, t3, t2, w[19], 0x23893e81, rounds);
        t0 = HAVAL_FF_4(t0, t7, t6, t5, t4, t3, t2, t1, w[ 3], 0xd396acc5, rounds);

        t7 = HAVAL_FF_4(t7, t6, t5, t4, t3, t2, t1, t0, w[22], 0x0f6d6ff3, rounds);
        t6 = HAVAL_FF_4(t6, t5, t4, t3, t2, t1, t0, t7, w[11], 0x83f44239, rounds);
        t5 = HAVAL_FF_4(t5, t4, t3, t2, t1, t0, t7, t6, w[31], 0x2e0b4482, rounds);
        t4 = HAVAL_FF_4(t4, t3, t2, t1, t0, t7, t6, t5, w[21], 0xa4842004, rounds);
        t3 = HAVAL_FF_4(t3, t2, t1, t0, t7, t6, t5, t4, w[ 8], 0x69c8f04a, rounds);
        t2 = HAVAL_FF_4(t2, t1, t0, t7, t6, t5, t4, t3, w[27], 0x9e1f9b5e, rounds);
        t1 = HAVAL_FF_4(t1, t0, t7, t6, t5, t4, t3, t2, w[12], 0x21c66842, rounds);
        t0 = HAVAL_FF_4(t0, t7, t6, t5, t4, t3, t2, t1, w[ 9], 0xf6e96c9a, rounds);

        t7 = HAVAL_FF_4(t7, t6, t5, t4, t3, t2, t1, t0, w[ 1], 0x670c9c61, rounds);
        t6 = HAVAL_FF_4(t6, t5, t4, t3, t2, t1, t0, t7, w[29], 0xabd388f0, rounds);
        t5 = HAVAL_FF_4(t5, t4, t3, t2, t1, t0, t7, t6, w[ 5], 0x6a51a0d2, rounds);
        t4 = HAVAL_FF_4(t4, t3, t2, t1, t0, t7, t6, t5, w[15], 0xd8542f68, rounds);
        t3 = HAVAL_FF_4(t3, t2, t1, t0, t7, t6, t5, t4, w[17], 0x960fa728, rounds);
        t2 = HAVAL_FF_4(t2, t1, t0, t7, t6, t5, t4, t3, w[10], 0xab5133a3, rounds);
        t1 = HAVAL_FF_4(t1, t0, t7, t6, t5, t4, t3, t2, w[16], 0x6eef0b6c, rounds);
        t0 = HAVAL_FF_4(t0, t7, t6, t5, t4, t3, t2, t1, w[13], 0x137a3be4, rounds);
    }

    if rounds == 5 {
        t7 = HAVAL_FF_5(t7, t6, t5, t4, t3, t2, t1, t0, w[27], 0xba3bf050, rounds);
        t6 = HAVAL_FF_5(t6, t5, t4, t3, t2, t1, t0, t7, w[ 3], 0x7efb2a98, rounds);
        t5 = HAVAL_FF_5(t5, t4, t3, t2, t1, t0, t7, t6, w[21], 0xa1f1651d, rounds);
        t4 = HAVAL_FF_5(t4, t3, t2, t1, t0, t7, t6, t5, w[26], 0x39af0176, rounds);
        t3 = HAVAL_FF_5(t3, t2, t1, t0, t7, t6, t5, t4, w[17], 0x66ca593e, rounds);
        t2 = HAVAL_FF_5(t2, t1, t0, t7, t6, t5, t4, t3, w[11], 0x82430e88, rounds);
        t1 = HAVAL_FF_5(t1, t0, t7, t6, t5, t4, t3, t2, w[20], 0x8cee8619, rounds);
        t0 = HAVAL_FF_5(t0, t7, t6, t5, t4, t3, t2, t1, w[29], 0x456f9fb4, rounds);

        t7 = HAVAL_FF_5(t7, t6, t5, t4, t3, t2, t1, t0, w[19], 0x7d84a5c3, rounds);
        t6 = HAVAL_FF_5(t6, t5, t4, t3, t2, t1, t0, t7, w[ 0], 0x3b8b5ebe, rounds);
        t5 = HAVAL_FF_5(t5, t4, t3, t2, t1, t0, t7, t6, w[12], 0xe06f75d8, rounds);
        t4 = HAVAL_FF_5(t4, t3, t2, t1, t0, t7, t6, t5, w[ 7], 0x85c12073, rounds);
        t3 = HAVAL_FF_5(t3, t2, t1, t0, t7, t6, t5, t4, w[13], 0x401a449f, rounds);
        t2 = HAVAL_FF_5(t2, t1, t0, t7, t6, t5, t4, t3, w[ 8], 0x56c16aa6, rounds);
        t1 = HAVAL_FF_5(t1, t0, t7, t6, t5, t4, t3, t2, w[31], 0x4ed3aa62, rounds);
        t0 = HAVAL_FF_5(t0, t7, t6, t5, t4, t3, t2, t1, w[10], 0x363f7706, rounds);

        t7 = HAVAL_FF_5(t7, t6, t5, t4, t3, t2, t1, t0, w[ 5], 0x1bfedf72, rounds);
        t6 = HAVAL_FF_5(t6, t5, t4, t3, t2, t1, t0, t7, w[ 9], 0x429b023d, rounds);
        t5 = HAVAL_FF_5(t5, t4, t3, t2, t1, t0, t7, t6, w[14], 0x37d0d724, rounds);
        t4 = HAVAL_FF_5(t4, t3, t2, t1, t0, t7, t6, t5, w[30], 0xd00a1248, rounds);
        t3 = HAVAL_FF_5(t3, t2, t1, t0, t7, t6, t5, t4, w[18], 0xdb0fead3, rounds);
        t2 = HAVAL_FF_5(t2, t1, t0, t7, t6, t5, t4, t3, w[ 6], 0x49f1c09b, rounds);
        t1 = HAVAL_FF_5(t1, t0, t7, t6, t5, t4, t3, t2, w[28], 0x075372c9, rounds);
        t0 = HAVAL_FF_5(t0, t7, t6, t5, t4, t3, t2, t1, w[24], 0x80991b7b, rounds);

        t7 = HAVAL_FF_5(t7, t6, t5, t4, t3, t2, t1, t0, w[ 2], 0x25d479d8, rounds);
        t6 = HAVAL_FF_5(t6, t5, t4, t3, t2, t1, t0, t7, w[23], 0xf6e8def7, rounds);
        t5 = HAVAL_FF_5(t5, t4, t3, t2, t1, t0, t7, t6, w[16], 0xe3fe501a, rounds);
        t4 = HAVAL_FF_5(t4, t3, t2, t1, t0, t7, t6, t5, w[22], 0xb6794c3b, rounds);
        t3 = HAVAL_FF_5(t3, t2, t1, t0, t7, t6, t5, t4, w[ 4], 0x976ce0bd, rounds);
        t2 = HAVAL_FF_5(t2, t1, t0, t7, t6, t5, t4, t3, w[ 1], 0x04c006ba, rounds);
        t1 = HAVAL_FF_5(t1, t0, t7, t6, t5, t4, t3, t2, w[25], 0xc1a94fb6, rounds);
        t0 = HAVAL_FF_5(t0, t7, t6, t5, t4, t3, t2, t1, w[15], 0x409f60c4, rounds);
    }

    ctx.fingerprint[0] += t0;
    ctx.fingerprint[1] += t1;
    ctx.fingerprint[2] += t2;
    ctx.fingerprint[3] += t3;
    ctx.fingerprint[4] += t4;
    ctx.fingerprint[5] += t5;
    ctx.fingerprint[6] += t6;
    ctx.fingerprint[7] += t7;
}

haval_init :: proc(ctx: ^HAVAL) {
    ctx.count[0], ctx.count[1] = 0, 0; 
    ctx.fingerprint[0] = 0x243f6a88;
    ctx.fingerprint[1] = 0x85a308d3;
    ctx.fingerprint[2] = 0x13198a2e;
    ctx.fingerprint[3] = 0x03707344;
    ctx.fingerprint[4] = 0xa4093822;
    ctx.fingerprint[5] = 0x299f31d0;
    ctx.fingerprint[6] = 0x082efa98;
    ctx.fingerprint[7] = 0xec4e6c89;
}

// @note(zh): This should be in core:mem
bytes_to_slice :: inline proc "contextless" ($T: typeid, bytes: []byte) -> []T {
    s := transmute(mem.Raw_Slice)bytes;
    s.len /= size_of(T);
    return transmute([]T)s;
}

// @note(zh): This should be in core:mem
slice_to_bytes :: inline proc "contextless" (slice: $E/[]$T) -> []byte {
    s := transmute(mem.Raw_Slice)slice;
    s.len *= size_of(T);
    return transmute([]byte)s;
}

haval_update :: proc(ctx: ^HAVAL, data: []byte, str_len, rounds: u32) {
    i : u32;
    rmd_len := u32((ctx.count[0] >> 3) & 0x7f);
    fill_len := 128 - rmd_len;

    ctx.count[0] += str_len << 3;
    if ctx.count[0] < (str_len << 3) do ctx.count[1] += 1;
    ctx.count[1] += str_len >> 29;

    when ODIN_ENDIAN == "little" {
        if rmd_len + str_len >= 128 {
            copy(slice_to_bytes(ctx.block[:])[rmd_len:], data[:fill_len]);
            haval_block(ctx, rounds);
            for i = fill_len; i + 127 < str_len; i += 128 {
                copy(slice_to_bytes(ctx.block[:]), data[i:128]);
                haval_block(ctx, rounds);
            }
            rmd_len = 0;
        } else {
            i = 0;
        }
        copy(slice_to_bytes(ctx.block[:])[rmd_len:], data[i:]);   
    } else {
        if rmd_len + str_len >= 128 {
            copy(ctx.remainder[rmd_len:], data[:fill_len]);
            HAVAL_CH2UINT(ctx.remainder[:], ctx.block[:]);
            haval_block(ctx, rounds);
            for i = fill_len; i + 127 < str_len; i += 128 {
                copy(ctx.remainder[:], data[i:128]);
                HAVAL_CH2UINT(ctx.remainder[:], ctx.block[:]);
                haval_block(ctx, rounds);
            }
            rmd_len = 0;
        } else {
            i = 0;
        }
        copy(ctx.remainder[rmd_len:], data[i:]);
    }
}

haval_tailor :: proc(ctx: ^HAVAL, size: u32) {
    temp: u32;
    switch size {
        case 128:
            temp = (ctx.fingerprint[7] & 0x000000ff) | 
                   (ctx.fingerprint[6] & 0xff000000) | 
                   (ctx.fingerprint[5] & 0x00ff0000) | 
                   (ctx.fingerprint[4] & 0x0000ff00);
            ctx.fingerprint[0] += HAVAL_ROTR32(temp, 8);

            temp = (ctx.fingerprint[7] & 0x0000ff00) | 
                   (ctx.fingerprint[6] & 0x000000ff) | 
                   (ctx.fingerprint[5] & 0xff000000) | 
                   (ctx.fingerprint[4] & 0x00ff0000);
            ctx.fingerprint[1] += HAVAL_ROTR32(temp, 16);

            temp = (ctx.fingerprint[7] & 0x00ff0000) | 
                   (ctx.fingerprint[6] & 0x0000ff00) | 
                   (ctx.fingerprint[5] & 0x000000ff) | 
                   (ctx.fingerprint[4] & 0xff000000);
            ctx.fingerprint[2] += HAVAL_ROTR32(temp, 24);

            temp = (ctx.fingerprint[7] & 0xff000000) | 
                   (ctx.fingerprint[6] & 0x00ff0000) | 
                   (ctx.fingerprint[5] & 0x0000ff00) | 
                   (ctx.fingerprint[4] & 0x000000ff);
            ctx.fingerprint[3] += temp;        
        case 160:
            temp = (ctx.fingerprint[7] & u32(0x3f)) | 
                   (ctx.fingerprint[6] & u32(0x7f << 25)) |  
                   (ctx.fingerprint[5] & u32(0x3f << 19));
            ctx.fingerprint[0] += HAVAL_ROTR32(temp, 19);

            temp = (ctx.fingerprint[7] & u32(0x3f <<  6)) | 
                   (ctx.fingerprint[6] & u32(0x3f)) |  
                   (ctx.fingerprint[5] & u32(0x7f << 25));
            ctx.fingerprint[1] += HAVAL_ROTR32(temp, 25);

            temp = (ctx.fingerprint[7] & u32(0x7f << 12)) | 
                   (ctx.fingerprint[6] & u32(0x3f <<  6)) |  
                   (ctx.fingerprint[5] & u32(0x3f));
            ctx.fingerprint[2] += temp;

            temp = (ctx.fingerprint[7] & u32(0x3f << 19)) | 
                   (ctx.fingerprint[6] & u32(0x7f << 12)) |  
                   (ctx.fingerprint[5] & u32(0x3f <<  6));
            ctx.fingerprint[3] += temp >> 6; 

            temp = (ctx.fingerprint[7] & u32(0x7f << 25)) | 
                   (ctx.fingerprint[6] & u32(0x3f << 19)) |  
                   (ctx.fingerprint[5] & u32(0x7f << 12));
            ctx.fingerprint[4] += temp >> 12;
        case 192:
            temp = (ctx.fingerprint[7] & u32(0x1f)) | 
                   (ctx.fingerprint[6] & u32(0x3f << 26));
            ctx.fingerprint[0] += HAVAL_ROTR32(temp, 26);

            temp = (ctx.fingerprint[7] & u32(0x1f <<  5)) | 
                   (ctx.fingerprint[6] & u32(0x1f));
            ctx.fingerprint[1] += temp;

            temp = (ctx.fingerprint[7] & u32(0x3f << 10)) | 
                   (ctx.fingerprint[6] & u32(0x1f <<  5));
            ctx.fingerprint[2] += temp >> 5;

            temp = (ctx.fingerprint[7] & u32(0x1f << 16)) | 
                   (ctx.fingerprint[6] & u32(0x3f << 10));
            ctx.fingerprint[3] += temp >> 10;

            temp = (ctx.fingerprint[7] & u32(0x1f << 21)) | 
                   (ctx.fingerprint[6] & u32(0x1f << 16));
            ctx.fingerprint[4] += temp >> 16;

            temp = (ctx.fingerprint[7] & u32(0x3f << 26)) | 
                   (ctx.fingerprint[6] & u32(0x1f << 21));
            ctx.fingerprint[5] += temp >> 21;
        case 224:
            ctx.fingerprint[0] += (ctx.fingerprint[7] >> 27) & 0x1f;
            ctx.fingerprint[1] += (ctx.fingerprint[7] >> 22) & 0x1f;
            ctx.fingerprint[2] += (ctx.fingerprint[7] >> 18) & 0x0f;
            ctx.fingerprint[3] += (ctx.fingerprint[7] >> 13) & 0x1f;
            ctx.fingerprint[4] += (ctx.fingerprint[7] >>  9) & 0x0f;
            ctx.fingerprint[5] += (ctx.fingerprint[7] >>  4) & 0x1f;
            ctx.fingerprint[6] +=  ctx.fingerprint[7]        & 0x0f;                
    }
}

haval_final :: proc(ctx: ^HAVAL, digest: []byte, rounds, size: u32) {
    pad_len: u32;
    tail : [10]u8;

    tail[0] = u8(size & 0x3) << 6 | u8(rounds & 0x7) << 3 | (HAVAL_VERSION & 0x7);
    tail[1] = u8(size >> 2) & 0xff;

    HAVAL_UINT2CH(ctx.count[:], slice_to_bytes(tail[2:]), 2);
    rmd_len := (ctx.count[0] >> 3) & 0x7f;
    if rmd_len < 118 {
        pad_len = 118 - rmd_len;
    } else {
        pad_len = 246 - rmd_len;
    }

    haval_update(ctx, HAVAL_PADDING[:], pad_len, rounds);    
    haval_update(ctx, tail[:], 10, rounds);
    haval_tailor(ctx, size);
    HAVAL_UINT2CH(ctx.fingerprint[:], digest, size >> 5);

    mem.set(&ctx, 0, size_of(ctx));
}

haval :: proc "contextless" (data: []byte, rounds, size: u32) -> []byte #no_bounds_check {
	hash := make([]byte, size);
    ctx : HAVAL;
    haval_init(&ctx);
    haval_update(&ctx, data, u32(len(data)), rounds);
    haval_final(&ctx, hash[:], rounds, size);

    return hash;
}

haval_3_128 :: proc "contextless" (data: []byte) -> [16]byte #no_bounds_check {
    hash : [16]byte;
    tmp := haval(data, 3, 128);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_4_128 :: proc "contextless" (data: []byte) -> [16]byte #no_bounds_check {
    hash : [16]byte;
    tmp := haval(data, 4, 128);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_5_128 :: proc "contextless" (data: []byte) -> [16]byte #no_bounds_check {
    hash : [16]byte;
    tmp := haval(data, 5, 128);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_3_160 :: proc "contextless" (data: []byte) -> [20]byte #no_bounds_check {
    hash : [20]byte;
    tmp := haval(data, 3, 160);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_4_160 :: proc "contextless" (data: []byte) -> [20]byte #no_bounds_check {
    hash : [20]byte;
    tmp := haval(data, 4, 160);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_5_160 :: proc "contextless" (data: []byte) -> [20]byte #no_bounds_check {
    hash : [20]byte;
    tmp := haval(data, 5, 160);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_3_192 :: proc "contextless" (data: []byte) -> [24]byte #no_bounds_check {
    hash : [24]byte;
    tmp := haval(data, 3, 192);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_4_192 :: proc "contextless" (data: []byte) -> [24]byte #no_bounds_check {
    hash : [24]byte;
    tmp := haval(data, 4, 192);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_5_192 :: proc "contextless" (data: []byte) -> [24]byte #no_bounds_check {
    hash : [24]byte;
    tmp := haval(data, 5, 192);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_3_224 :: proc "contextless" (data: []byte) -> [28]byte #no_bounds_check {
    hash : [28]byte;
    tmp := haval(data, 3, 224);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_4_224 :: proc "contextless" (data: []byte) -> [28]byte #no_bounds_check {
    hash : [28]byte;
    tmp := haval(data, 4, 224);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_5_224 :: proc "contextless" (data: []byte) -> [28]byte #no_bounds_check {
    hash : [28]byte;
    tmp := haval(data, 5, 224);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_3_256 :: proc "contextless" (data: []byte) -> [32]byte #no_bounds_check {
    hash : [32]byte;
    tmp := haval(data, 3, 256);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_4_256 :: proc "contextless" (data: []byte) -> [32]byte #no_bounds_check {
    hash : [32]byte;
    tmp := haval(data, 4, 256);
    copy(hash[:], tmp[:]);
    return hash;
}

haval_5_256 :: proc "contextless" (data: []byte) -> [32]byte #no_bounds_check {
    hash : [32]byte;
    tmp := haval(data, 5, 256);
    copy(hash[:], tmp[:]);
    return hash;
}