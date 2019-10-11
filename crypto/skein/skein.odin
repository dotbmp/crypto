package skein

// @ref(zh): http://www.skein-hash.info/sites/default/files/skein_NIST_CD_121508.zip

import "core:mem"
using import ".."

SKEIN_MODIFIER_WORDS :: 2;

SKEIN_256_STATE_WORDS :: 4;
SKEIN_512_STATE_WORDS :: 8;
SKEIN_1024_STATE_WORDS :: 16;
SKEIN_MAX_STATE_WORDS :: 16;

SKEIN_256_STATE_BYTES :: 32;
SKEIN_512_STATE_BYTES :: 64;
SKEIN_1024_STATE_BYTES :: 128;

SKEIN_256_STATE_BITS :: 256;
SKEIN_512_STATE_BITS :: 512;
SKEIN_1024_STATE_BITS :: 1024;

SKEIN_256_BLOCK_BYTES :: 32;
SKEIN_512_BLOCK_BYTES :: 64;
SKEIN_1024_BLOCK_BYTES :: 128;

SKEIN_256_ROUNDS_TOTAL :: 72;
SKEIN_512_ROUNDS_TOTAL :: 72;
SKEIN_1024_ROUNDS_TOTAL :: 80;

SKEIN_R_256 := [16]u64 {
     5, 56, 36, 28, 13, 46, 58, 44,
    26, 20, 53, 35, 11, 42, 59, 50,
};

SKEIN_R_512 := [32]u64 {
    38, 30, 50, 53, 48, 20, 43, 31,
    34, 14, 15, 27, 26, 12, 58,  7,
    33, 49,  8, 42, 39, 27, 41, 14,
    29, 26, 11,  9, 33, 51, 39, 35,
};

SKEIN_R_1024 := [64]u64 {
    55, 43, 37, 40, 16, 22, 38, 12,
    25, 25, 46, 13, 14, 13, 52, 57,
    33,  8, 18, 57, 21, 12, 32, 54,
    34, 43, 25, 60, 44,  9, 59, 34,
    28,  7, 47, 48, 51,  9, 35, 41,
    17,  6, 18, 25, 43, 42, 40, 15,
    58,  7, 32, 45, 19, 18,  2, 56,
    47, 49, 27, 58, 37, 48, 53, 56
};

SKEIN_INJECT_KEY :: inline proc "contextless"(r: int, WCNT: u64, X, ks, ts: []u64) {
    for i := u64(0); i < WCNT; i += 1 do X[i] += ks[(u64(r) + i) % (WCNT + 1)];
    X[WCNT - 3] += ts[(r + 0) % 3];
    X[WCNT - 2] += ts[(r + 1) % 3];
    X[WCNT - 1] += u64(r);
}

skein_get64_lsb_first :: inline proc "contextless"(dst: []u64 src: []byte, wCnt: u64) {
    for n := u64(0); n < 8 * wCnt; n += 8 {
        dst[n/8] =  (u64(src[n  ]))  +
                    (u64(src[n+1]) <<  8) +
                    (u64(src[n+2]) << 16) +
                    (u64(src[n+3]) << 24) +
                    (u64(src[n+4]) << 32) +
                    (u64(src[n+5]) << 40) +
                    (u64(src[n+6]) << 48) +
                    (u64(src[n+7]) << 56) ;
    }
}

skein_process_block :: inline proc "contextless"(ctx: ^$T, blkPtr: []u8, blkCnt, byteCntAdd: u64) {
    WCNT: u64;
    blkPtr, blkCnt := blkPtr, blkCnt;
    when T == SKEIN_256 do WCNT = u64(SKEIN_256_STATE_WORDS);
    else when T == SKEIN_512 do WCNT = u64(SKEIN_512_STATE_WORDS);
    else when T == SKEIN_1024 do WCNT = u64(SKEIN_1024_STATE_WORDS);

    ts: [3]u64;
    ks := make([]u64, WCNT + 1);
    X := make([]u64, WCNT);
    w := make([]u64, WCNT);
    defer delete(ks);
    defer delete(X);
    defer delete(w);

    for blkCnt != 0 {
        ctx.h.T[0] += byteCntAdd;
        sk1 := u64(0x55555555) << 32;
        ks[WCNT] = 0x55555555 + u64(i32(sk1));
        for i := u64(0); i < WCNT; i += 1 {
            ks[i] = ctx.X[i];
            ks[WCNT] ~= ctx.X[i];
        }

        ts[0] = ctx.h.T[0];
        ts[1] = ctx.h.T[1];
        ts[2] = ts[0] ~ ts[1];

        skein_get64_lsb_first(w[:], blkPtr, WCNT);

        for i := u64(0); i < WCNT; i += 1 do X[i] = w[i] + ks[i];

        X[WCNT - 3] += ts[0];
        X[WCNT - 2] += ts[1];

        when T == SKEIN_256 {
            for r := 1; r <= SKEIN_256_ROUNDS_TOTAL / 8; r += 1 {
                X[0] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_256[ 0]); X[1] ~= X[0];
                X[2] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_256[ 1]); X[3] ~= X[2];

                X[0] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_256[ 2]); X[3] ~= X[0];
                X[2] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_256[ 3]); X[1] ~= X[2];

                X[0] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_256[ 4]); X[1] ~= X[0];
                X[2] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_256[ 5]); X[3] ~= X[2];

                X[0] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_256[ 6]); X[3] ~= X[0];
                X[2] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_256[ 7]); X[1] ~= X[2];
                SKEIN_INJECT_KEY(2 * r - 1, WCNT, X[:], ks[:], ts[:]);

                X[0] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_256[ 8]); X[1] ~= X[0];
                X[2] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_256[ 9]); X[3] ~= X[2];

                X[0] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_256[10]); X[3] ~= X[0];
                X[2] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_256[11]); X[1] ~= X[2];

                X[0] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_256[12]); X[1] ~= X[0];
                X[2] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_256[13]); X[3] ~= X[2];

                X[0] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_256[14]); X[3] ~= X[0];
                X[2] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_256[15]); X[1] ~= X[2];
                SKEIN_INJECT_KEY(2 * r, WCNT, X[:], ks[:], ts[:]);
            }   
        } else when T == SKEIN_512 {
            for r := 1; r <= SKEIN_512_ROUNDS_TOTAL / 8; r += 1 {
                X[0] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_512[ 0]); X[1] ~= X[0];
                X[2] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_512[ 1]); X[3] ~= X[2];
                X[4] += X[5]; X[5] = ROTL64(X[5], SKEIN_R_512[ 2]); X[5] ~= X[4];
                X[6] += X[7]; X[7] = ROTL64(X[7], SKEIN_R_512[ 3]); X[7] ~= X[6];

                X[2] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_512[ 4]); X[1] ~= X[2];
                X[4] += X[7]; X[7] = ROTL64(X[7], SKEIN_R_512[ 5]); X[7] ~= X[4];
                X[6] += X[5]; X[5] = ROTL64(X[5], SKEIN_R_512[ 6]); X[5] ~= X[6];
                X[0] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_512[ 7]); X[3] ~= X[0];

                X[4] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_512[ 8]); X[1] ~= X[4];
                X[6] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_512[ 9]); X[3] ~= X[6];
                X[0] += X[5]; X[5] = ROTL64(X[5], SKEIN_R_512[10]); X[5] ~= X[0];
                X[2] += X[7]; X[7] = ROTL64(X[7], SKEIN_R_512[11]); X[7] ~= X[2];

                X[6] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_512[12]); X[1] ~= X[6];
                X[0] += X[7]; X[7] = ROTL64(X[7], SKEIN_R_512[13]); X[7] ~= X[0];
                X[2] += X[5]; X[5] = ROTL64(X[5], SKEIN_R_512[14]); X[5] ~= X[2];
                X[4] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_512[15]); X[3] ~= X[4];
                SKEIN_INJECT_KEY(2 * r - 1, WCNT, X[:], ks[:], ts[:]);

                X[0] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_512[16]); X[1] ~= X[0];
                X[2] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_512[17]); X[3] ~= X[2];
                X[4] += X[5]; X[5] = ROTL64(X[5], SKEIN_R_512[18]); X[5] ~= X[4];
                X[6] += X[7]; X[7] = ROTL64(X[7], SKEIN_R_512[19]); X[7] ~= X[6];

                X[2] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_512[20]); X[1] ~= X[2];
                X[4] += X[7]; X[7] = ROTL64(X[7], SKEIN_R_512[21]); X[7] ~= X[4];
                X[6] += X[5]; X[5] = ROTL64(X[5], SKEIN_R_512[22]); X[5] ~= X[6];
                X[0] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_512[23]); X[3] ~= X[0];

                X[4] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_512[24]); X[1] ~= X[4];
                X[6] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_512[25]); X[3] ~= X[6];
                X[0] += X[5]; X[5] = ROTL64(X[5], SKEIN_R_512[26]); X[5] ~= X[0];
                X[2] += X[7]; X[7] = ROTL64(X[7], SKEIN_R_512[27]); X[7] ~= X[2];

                X[6] += X[1]; X[1] = ROTL64(X[1], SKEIN_R_512[28]); X[1] ~= X[6];
                X[0] += X[7]; X[7] = ROTL64(X[7], SKEIN_R_512[29]); X[7] ~= X[0];
                X[2] += X[5]; X[5] = ROTL64(X[5], SKEIN_R_512[30]); X[5] ~= X[2];
                X[4] += X[3]; X[3] = ROTL64(X[3], SKEIN_R_512[31]); X[3] ~= X[4];
                SKEIN_INJECT_KEY(2 * r, WCNT, X[:], ks[:], ts[:]);
            }
        } else when T == SKEIN_1024 {
            for r := 1; r <= SKEIN_1024_ROUNDS_TOTAL / 8; r += 1 {
                X[ 0] += X[ 1]; X[ 1] = ROTL64(X[ 1], SKEIN_R_1024[ 0]); X[ 1] ~= X[ 0];
                X[ 2] += X[ 3]; X[ 3] = ROTL64(X[ 3], SKEIN_R_1024[ 1]); X[ 3] ~= X[ 2];
                X[ 4] += X[ 5]; X[ 5] = ROTL64(X[ 5], SKEIN_R_1024[ 2]); X[ 5] ~= X[ 4];
                X[ 6] += X[ 7]; X[ 7] = ROTL64(X[ 7], SKEIN_R_1024[ 3]); X[ 7] ~= X[ 6];
                X[ 8] += X[ 9]; X[ 9] = ROTL64(X[ 9], SKEIN_R_1024[ 4]); X[ 9] ~= X[ 8];
                X[10] += X[11]; X[11] = ROTL64(X[11], SKEIN_R_1024[ 5]); X[11] ~= X[10];
                X[12] += X[13]; X[13] = ROTL64(X[13], SKEIN_R_1024[ 6]); X[13] ~= X[12];
                X[14] += X[15]; X[15] = ROTL64(X[15], SKEIN_R_1024[ 7]); X[15] ~= X[14];

                X[ 0] += X[ 9]; X[ 9] = ROTL64(X[ 9], SKEIN_R_1024[ 8]); X[ 9] ~= X[ 0];
                X[ 2] += X[13]; X[13] = ROTL64(X[13], SKEIN_R_1024[ 9]); X[13] ~= X[ 2];
                X[ 6] += X[11]; X[11] = ROTL64(X[11], SKEIN_R_1024[10]); X[11] ~= X[ 6];
                X[ 4] += X[15]; X[15] = ROTL64(X[15], SKEIN_R_1024[11]); X[15] ~= X[ 4];
                X[10] += X[ 7]; X[ 7] = ROTL64(X[ 7], SKEIN_R_1024[12]); X[ 7] ~= X[10];
                X[12] += X[ 3]; X[ 3] = ROTL64(X[ 3], SKEIN_R_1024[13]); X[ 3] ~= X[12];
                X[14] += X[ 5]; X[ 5] = ROTL64(X[ 5], SKEIN_R_1024[14]); X[ 5] ~= X[14];
                X[ 8] += X[ 1]; X[ 1] = ROTL64(X[ 1], SKEIN_R_1024[15]); X[ 1] ~= X[ 8];

                X[ 0] += X[ 7]; X[ 7] = ROTL64(X[ 7], SKEIN_R_1024[16]); X[ 7] ~= X[ 0];
                X[ 2] += X[ 5]; X[ 5] = ROTL64(X[ 5], SKEIN_R_1024[17]); X[ 5] ~= X[ 2];
                X[ 4] += X[ 3]; X[ 3] = ROTL64(X[ 3], SKEIN_R_1024[18]); X[ 3] ~= X[ 4];
                X[ 6] += X[ 1]; X[ 1] = ROTL64(X[ 1], SKEIN_R_1024[19]); X[ 1] ~= X[ 6];
                X[12] += X[15]; X[15] = ROTL64(X[15], SKEIN_R_1024[20]); X[15] ~= X[12];
                X[14] += X[13]; X[13] = ROTL64(X[13], SKEIN_R_1024[21]); X[13] ~= X[14];
                X[ 8] += X[11]; X[11] = ROTL64(X[11], SKEIN_R_1024[22]); X[11] ~= X[ 8];
                X[10] += X[ 9]; X[ 9] = ROTL64(X[ 9], SKEIN_R_1024[23]); X[ 9] ~= X[10];
                                                                                
                X[ 0] += X[15]; X[15] = ROTL64(X[15], SKEIN_R_1024[24]); X[15] ~= X[ 0];
                X[ 2] += X[11]; X[11] = ROTL64(X[11], SKEIN_R_1024[25]); X[11] ~= X[ 2];
                X[ 6] += X[13]; X[13] = ROTL64(X[13], SKEIN_R_1024[26]); X[13] ~= X[ 6];
                X[ 4] += X[ 9]; X[ 9] = ROTL64(X[ 9], SKEIN_R_1024[27]); X[ 9] ~= X[ 4];
                X[14] += X[ 1]; X[ 1] = ROTL64(X[ 1], SKEIN_R_1024[28]); X[ 1] ~= X[14];
                X[ 8] += X[ 5]; X[ 5] = ROTL64(X[ 5], SKEIN_R_1024[29]); X[ 5] ~= X[ 8];
                X[10] += X[ 3]; X[ 3] = ROTL64(X[ 3], SKEIN_R_1024[30]); X[ 3] ~= X[10];
                X[12] += X[ 7]; X[ 7] = ROTL64(X[ 7], SKEIN_R_1024[31]); X[ 7] ~= X[12];
                SKEIN_INJECT_KEY(2 * r - 1, WCNT, X[:], ks[:], ts[:]);

                X[ 0] += X[ 1]; X[ 1] = ROTL64(X[ 1], SKEIN_R_1024[32]); X[ 1] ~= X[ 0];
                X[ 2] += X[ 3]; X[ 3] = ROTL64(X[ 3], SKEIN_R_1024[33]); X[ 3] ~= X[ 2];
                X[ 4] += X[ 5]; X[ 5] = ROTL64(X[ 5], SKEIN_R_1024[34]); X[ 5] ~= X[ 4];
                X[ 6] += X[ 7]; X[ 7] = ROTL64(X[ 7], SKEIN_R_1024[35]); X[ 7] ~= X[ 6];
                X[ 8] += X[ 9]; X[ 9] = ROTL64(X[ 9], SKEIN_R_1024[36]); X[ 9] ~= X[ 8];
                X[10] += X[11]; X[11] = ROTL64(X[11], SKEIN_R_1024[37]); X[11] ~= X[10];
                X[12] += X[13]; X[13] = ROTL64(X[13], SKEIN_R_1024[38]); X[13] ~= X[12];
                X[14] += X[15]; X[15] = ROTL64(X[15], SKEIN_R_1024[39]); X[15] ~= X[14];

                X[ 0] += X[ 9]; X[ 9] = ROTL64(X[ 9], SKEIN_R_1024[40]); X[ 9] ~= X[ 0];
                X[ 2] += X[13]; X[13] = ROTL64(X[13], SKEIN_R_1024[41]); X[13] ~= X[ 2];
                X[ 6] += X[11]; X[11] = ROTL64(X[11], SKEIN_R_1024[42]); X[11] ~= X[ 6];
                X[ 4] += X[15]; X[15] = ROTL64(X[15], SKEIN_R_1024[43]); X[15] ~= X[ 4];
                X[10] += X[ 7]; X[ 7] = ROTL64(X[ 7], SKEIN_R_1024[44]); X[ 7] ~= X[10];
                X[12] += X[ 3]; X[ 3] = ROTL64(X[ 3], SKEIN_R_1024[45]); X[ 3] ~= X[12];
                X[14] += X[ 5]; X[ 5] = ROTL64(X[ 5], SKEIN_R_1024[46]); X[ 5] ~= X[14];
                X[ 8] += X[ 1]; X[ 1] = ROTL64(X[ 1], SKEIN_R_1024[47]); X[ 1] ~= X[ 8];

                X[ 0] += X[ 7]; X[ 7] = ROTL64(X[ 7], SKEIN_R_1024[48]); X[ 7] ~= X[ 0];
                X[ 2] += X[ 5]; X[ 5] = ROTL64(X[ 5], SKEIN_R_1024[49]); X[ 5] ~= X[ 2];
                X[ 4] += X[ 3]; X[ 3] = ROTL64(X[ 3], SKEIN_R_1024[50]); X[ 3] ~= X[ 4];
                X[ 6] += X[ 1]; X[ 1] = ROTL64(X[ 1], SKEIN_R_1024[51]); X[ 1] ~= X[ 6];
                X[12] += X[15]; X[15] = ROTL64(X[15], SKEIN_R_1024[52]); X[15] ~= X[12];
                X[14] += X[13]; X[13] = ROTL64(X[13], SKEIN_R_1024[53]); X[13] ~= X[14];
                X[ 8] += X[11]; X[11] = ROTL64(X[11], SKEIN_R_1024[54]); X[11] ~= X[ 8];
                X[10] += X[ 9]; X[ 9] = ROTL64(X[ 9], SKEIN_R_1024[55]); X[ 9] ~= X[10];
                                                                                
                X[ 0] += X[15]; X[15] = ROTL64(X[15], SKEIN_R_1024[56]); X[15] ~= X[ 0];
                X[ 2] += X[11]; X[11] = ROTL64(X[11], SKEIN_R_1024[57]); X[11] ~= X[ 2];
                X[ 6] += X[13]; X[13] = ROTL64(X[13], SKEIN_R_1024[58]); X[13] ~= X[ 6];
                X[ 4] += X[ 9]; X[ 9] = ROTL64(X[ 9], SKEIN_R_1024[59]); X[ 9] ~= X[ 4];
                X[14] += X[ 1]; X[ 1] = ROTL64(X[ 1], SKEIN_R_1024[60]); X[ 1] ~= X[14];
                X[ 8] += X[ 5]; X[ 5] = ROTL64(X[ 5], SKEIN_R_1024[61]); X[ 5] ~= X[ 8];
                X[10] += X[ 3]; X[ 3] = ROTL64(X[ 3], SKEIN_R_1024[62]); X[ 3] ~= X[10];
                X[12] += X[ 7]; X[ 7] = ROTL64(X[ 7], SKEIN_R_1024[63]); X[ 7] ~= X[12];
                SKEIN_INJECT_KEY(2 * r, WCNT, X[:], ks[:], ts[:]);
            }
        }

        for i := u64(0); i < WCNT; i += 1 do ctx.X[i] = X[i] ~ w[i];

        SKEIN_CLEAR_FIRST_FLAG(ctx);
       
        blkPtr = blkPtr[SKEIN_256_BLOCK_BYTES:];

        blkCnt -= 1;
    }
}

SKEIN_HDR :: struct {
    hashBitLen: u64,
    bCnt: u64,
    T: [SKEIN_MODIFIER_WORDS]u64,
}

SKEIN_256 :: struct {
    h: SKEIN_HDR,
    X: [SKEIN_256_STATE_WORDS]u64,
    b: [SKEIN_256_STATE_BYTES]u8,
}

SKEIN_512 :: struct {
    h: SKEIN_HDR,
    X: [SKEIN_512_STATE_WORDS]u64,
    b: [SKEIN_512_STATE_BYTES]u8,
}

SKEIN_1024 :: struct {
    h: SKEIN_HDR,
    X: [SKEIN_1024_STATE_WORDS]u64,
    b: [SKEIN_1024_STATE_BYTES]u8,
}

SKEIN_CLEAR_FIRST_FLAG :: inline proc "contextless"(ctx: ^$T) {
    sk1: u64 = u64(1) << (126 - 64);
    ctx.h.T[1] &= ~u64(i32(sk1));
}

SKEIN_START_NEW_TYPE_CFG_FINAL :: inline proc "contextless"(ctx: ^$T) {
    ctx.h.T[0] = 0;
    sk1 : u64 = u64(1) << (126 - 64);
    sk2 : u64 = u64(4) << (120 - 64);
    sk3 : u64 = u64(1) << (127 - 64);
    ctx.h.T[1] = u64(i32(sk1)) | u64(i32(sk2)) | u64(i32(sk3));
    ctx.h.bCnt = 0;
}

SKEIN_START_NEW_TYPE_MSG :: inline proc "contextless"(ctx: ^$T) {
    ctx.h.T[0] = 0;
    sk1 : u64 = u64( 1) << (126 - 64);
    sk2 : u64 = u64(48) << (120 - 64);
    ctx.h.T[1] = u64(i32(sk1)) | u64(i32(sk2));
    ctx.h.bCnt = 0;
}

SKEIN_START_NEW_TYPE_OUT_FINAL :: inline proc "contextless"(ctx: ^$T) {
    ctx.h.T[0] = 0;
    sk1 : u64 = u64(1) << (126 - 64);
    sk2 : u64 = u64(63) << (120 - 64);
    sk3 : u64 = u64(1) << (127 - 64);
    ctx.h.T[1] = u64(i32(sk1)) | u64(i32(sk2)) | u64(i32(sk3));
    ctx.h.bCnt = 0;
}

skein_put64_lsb_first :: inline proc "contextless"(dst: []byte src: []u64, bCnt: u64) {
    for i := u64(0); i < bCnt; i += 1 do dst[i] = u8(src[i >> 3] >> (8 * (i & 7)));
}

skein_swap64 :: inline proc "contextless"(w64: u64) -> u64 {
    when ODIN_ENDIAN == "little" {
        return w64;
    } else {
        return  (( w64        & 0xff) << 56) |
                (((w64 >>  8) & 0xff) << 48) |
                (((w64 >> 16) & 0xff) << 40) |
                (((w64 >> 24) & 0xff) << 32) |
                (((w64 >> 32) & 0xff) << 24) |
                (((w64 >> 40) & 0xff) << 16) |
                (((w64 >> 48) & 0xff) <<  8) |
                (((w64 >> 56) & 0xff)      ) ;
    }
}

skein_init :: proc(ctx: ^$T, input: []byte, hashBitLen: u64) {
    when T == SKEIN_256 {
        cfg: struct #raw_union {
            b: [SKEIN_256_STATE_BYTES]u8,
            w: [SKEIN_256_STATE_WORDS]u64,
        };
    } else when T == SKEIN_512 {
        cfg: struct #raw_union {
            b: [SKEIN_512_STATE_BYTES]u8,
            w: [SKEIN_512_STATE_WORDS]u64,
        };
    } else when T == SKEIN_1024 {
        cfg: struct #raw_union {
            b: [SKEIN_1024_STATE_BYTES]u8,
            w: [SKEIN_1024_STATE_WORDS]u64,
        };
    }

    ctx.h.hashBitLen = hashBitLen;
    SKEIN_START_NEW_TYPE_CFG_FINAL(ctx);

    mem.set(&cfg.w, 0, size_of(cfg.w));  
    sk1 : u64 = u64(1) << 32;
    cfg.w[0] = skein_swap64(0x33414853 + u64(i32(sk1)));
    cfg.w[1] = skein_swap64(hashBitLen);
    cfg.w[2] = skein_swap64(0);

    skein_process_block(ctx, cfg.b[:], 1, 32);
    SKEIN_START_NEW_TYPE_MSG(ctx);
}

skein_update :: proc(ctx: ^$T, input: []byte) {
    msgByteCnt := u64(len(input));
    n: u64;
    input := input;
    when      T == SKEIN_256  do block_bytes := u64(32);
    else when T == SKEIN_512  do block_bytes := u64(64);
    else when T == SKEIN_1024 do block_bytes := u64(128);

    if msgByteCnt + ctx.h.bCnt > block_bytes {
        if ctx.h.bCnt != 0 {
            n = block_bytes - ctx.h.bCnt;
            if n != 0 {
                copy(ctx.b[ctx.h.bCnt:], input[:n]);
                msgByteCnt -= n;
                input = input[n:];
                ctx.h.bCnt += n;
            }
            skein_process_block(ctx, ctx.b[:], 1, block_bytes);
            ctx.h.bCnt = 0;
        }

        if msgByteCnt > block_bytes {
            n = (msgByteCnt - 1) / block_bytes;
            skein_process_block(ctx, input, n, block_bytes);
            msgByteCnt -= n * block_bytes;
            input = input[n * block_bytes:];
        }

        if msgByteCnt != 0 {
            copy(ctx.b[ctx.h.bCnt:], input[:msgByteCnt]);
            ctx.h.bCnt += msgByteCnt;
        }
    }
}

skein_final :: proc(ctx: ^$T, hashVal: []byte) {
    i, n, byteCnt: u64;

    when T == SKEIN_256 {
        block_bytes := u64(32);
        X: [SKEIN_256_STATE_WORDS]u64;
    } else when T == SKEIN_512 {
        block_bytes := u64(64);
        X: [SKEIN_512_STATE_WORDS]u64;
    } else when T == SKEIN_1024 {
        block_bytes := u64(128);
        X: [SKEIN_1024_STATE_WORDS]u64;
    }

    sk1: u64 = u64(1) << (127 - 64);
    ctx.h.T[1] |= u64(i32(sk1));
    if ctx.h.bCnt < block_bytes do mem.set(&ctx.b[ctx.h.bCnt], 0, int(block_bytes - ctx.h.bCnt));
    skein_process_block(ctx, ctx.b[:], 1, ctx.h.bCnt);
    byteCnt = (ctx.h.hashBitLen + 7) >> 3;

    mem.set(&ctx.b, 0, size_of(ctx.b));
    copy(X[:], ctx.X[:]);

    for i := u64(0); i * block_bytes < byteCnt; i += 1 {
        (^u64)(&ctx.b[0])^ = skein_swap64(u64(i));
        SKEIN_START_NEW_TYPE_OUT_FINAL(ctx);
        skein_process_block(ctx, ctx.b[:], 1, size_of(u64));
        n = byteCnt - i * block_bytes;
        if n >= block_bytes do n = block_bytes;
        skein_put64_lsb_first(hashVal[i * block_bytes:], ctx.X[:], n);
        copy(ctx.X[:], X[:]);
    }
}

hash_256 :: proc "contextless" (data: []byte) -> [SKEIN_256_BLOCK_BYTES]byte #no_bounds_check {
    hash: [SKEIN_256_BLOCK_BYTES]byte;
	ctx: SKEIN_256;
    skein_init(&ctx, data, 256);
    skein_update(&ctx, data);
    skein_final(&ctx, hash[:]);
    return hash;
}

hash_512 :: proc "contextless" (data: []byte) -> [SKEIN_512_BLOCK_BYTES]byte #no_bounds_check {
    hash: [SKEIN_512_BLOCK_BYTES]byte;
	ctx: SKEIN_512;
    skein_init(&ctx, data, 512);
    skein_update(&ctx, data);
    skein_final(&ctx, hash[:]);
    return hash;
}

hash_1024 :: proc "contextless" (data: []byte) -> [SKEIN_1024_BLOCK_BYTES]byte #no_bounds_check {
    hash: [SKEIN_1024_BLOCK_BYTES]byte;
	ctx: SKEIN_1024;
    skein_init(&ctx, data, 1024);
    skein_update(&ctx, data);
    skein_final(&ctx, hash[:]);
    return hash;
}