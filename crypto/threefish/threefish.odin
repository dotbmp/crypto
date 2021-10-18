package threefish

import "../util"

// @ref(zh): https://github.com/tildeleb/hashland/tree/master/threefish

KEY_SCHEDULE_CONST  :: u64(0x1bd11bdaa9fc1a22);
EXPANDED_TWEAK_SIZE :: 3;

CIPHER_SIZE_256       :: 256;
CIPHER_QWORDS_256     :: 4;
EXPANDED_KEY_SIZE_256 :: 5;
SIZE_256              :: 32;

Threefish256 :: struct {
    expandedTweak: [EXPANDED_TWEAK_SIZE]u64,
    expandedKey: [EXPANDED_KEY_SIZE_256]u64,
    tmpData1, tmpData2: [CIPHER_QWORDS_256]u64,
};

CIPHER_SIZE_512       :: 512;
CIPHER_QWORDS_512     :: 8;
EXPANDED_KEY_SIZE_512 :: 9;
SIZE_512              :: 64;

Threefish512 :: struct {
    expandedTweak: [EXPANDED_TWEAK_SIZE]u64,
    expandedKey: [EXPANDED_KEY_SIZE_512]u64,
    tmpData1, tmpData2: [CIPHER_QWORDS_512]u64,
};

CIPHER_SIZE_1024       :: 1024;
CIPHER_QWORDS_1024     :: 16;
EXPANDED_KEY_SIZE_1024 :: 17;
SIZE_1024              :: 128;

Threefish1024 :: struct {
    expandedTweak: [EXPANDED_TWEAK_SIZE]u64,
    expandedKey: [EXPANDED_KEY_SIZE_1024]u64,
    tmpData1, tmpData2: [CIPHER_QWORDS_1024]u64,
};

init :: proc(ctx: ^$T, key: []byte, tweak: []u64) {
    if len(tweak) > 0 {
        ctx.expandedTweak[0] = tweak[0];
        ctx.expandedTweak[1] = tweak[1];
        ctx.expandedTweak[2] = tweak[0] ~ tweak[1];
    }

    when      T == Threefish256  do ctx.expandedKey[EXPANDED_KEY_SIZE_256 - 1]  = KEY_SCHEDULE_CONST;
    else when T == Threefish512  do ctx.expandedKey[EXPANDED_KEY_SIZE_512 - 1]  = KEY_SCHEDULE_CONST;
    else when T == Threefish1024 do ctx.expandedKey[EXPANDED_KEY_SIZE_1024 - 1] = KEY_SCHEDULE_CONST;

    if len(key) > 0 {
        when        T == Threefish256 {
            tmp: [EXPANDED_KEY_SIZE_256]u64;
            for i in 0..<EXPANDED_KEY_SIZE_256 - 1 do tmp[i] = util.U64_LE(key[i * 8 : i * 8 + 8]);
        } else when T == Threefish512 {
            tmp: [EXPANDED_KEY_SIZE_512]u64;
            for i in 0..<EXPANDED_KEY_SIZE_512 - 1 do tmp[i] = util.U64_LE(key[i * 8 : i * 8 + 8]);
        } else when T == Threefish1024 {
            tmp: [EXPANDED_KEY_SIZE_1024]u64;
            for i in 0..<EXPANDED_KEY_SIZE_1024 - 1 do tmp[i] = util.U64_LE(key[i * 8 : i * 8 + 8]);
        } 

        parity := u64(KEY_SCHEDULE_CONST);
        j: int;
        for j = 0; j < len(ctx.expandedKey) - 1; j += 1 {
            ctx.expandedKey[j] = tmp[j];
            parity ~= tmp[j];
        }
        ctx.expandedKey[j] = parity;
    }
}

encrypt_256 :: proc(data, key: []byte, tweak: []u64) -> [SIZE_256]byte{
    ctx: Threefish256;
    init(&ctx, key, tweak);
    tmpIn, tmpOut := ctx.tmpData1, ctx.tmpData2;
    uintlen := CIPHER_SIZE_256 / 64;
    for i in 0..<uintlen {
        tmpIn[i] = util.U64_LE(data[i * 8 : i * 8 + 8]);
    }
    _encrypt_256(&ctx, tmpIn[:], tmpOut[:]);
    out: [SIZE_256]byte;
    for i in 0..<uintlen {
        util.PUT_U64_LE(out[i * 8 : i * 8 + 8], tmpOut[i]);
    }
    return out;
}

decrypt_256 :: proc(data, key: []byte, tweak: []u64) -> [SIZE_256]byte{
    ctx: Threefish256;
    init(&ctx, key, tweak);
    tmpIn, tmpOut := ctx.tmpData1, ctx.tmpData2;
    uintlen := CIPHER_SIZE_256 / 64;
    for i in 0..<uintlen {
        tmpIn[i] = util.U64_LE(data[i * 8 : i * 8 + 8]);
    }
    _decrypt_256(&ctx, tmpIn[:], tmpOut[:]);
    out: [SIZE_256]byte;
    for i in 0..<uintlen {
        util.PUT_U64_LE(out[i * 8 : i * 8 + 8], tmpOut[i]);
    }
    return out;
}

encrypt_512 :: proc(data, key: []byte, tweak: []u64) -> [SIZE_512]byte{
    ctx: Threefish512;
    init(&ctx, key, tweak);
    tmpIn, tmpOut := ctx.tmpData1, ctx.tmpData2;
    uintlen := CIPHER_SIZE_512 / 64;
    for i in 0..<uintlen {
        tmpIn[i] = util.U64_LE(data[i * 8 : i * 8 + 8]);
    }
    _encrypt_512(&ctx, tmpIn[:], tmpOut[:]);
    out: [SIZE_512]byte;
    for i in 0..<uintlen {
        util.PUT_U64_LE(out[i * 8 : i * 8 + 8], tmpOut[i]);
    }
    return out;
}

decrypt_512 :: proc(data, key: []byte, tweak: []u64) -> [SIZE_512]byte{
    ctx: Threefish512;
    init(&ctx, key, tweak);
    tmpIn, tmpOut := ctx.tmpData1, ctx.tmpData2;
    uintlen := CIPHER_SIZE_512 / 64;
    for i in 0..<uintlen {
        tmpIn[i] = util.U64_LE(data[i * 8 : i * 8 + 8]);
    }
    _decrypt_512(&ctx, tmpIn[:], tmpOut[:]);
    out: [SIZE_512]byte;
    for i in 0..<uintlen {
        util.PUT_U64_LE(out[i * 8 : i * 8 + 8], tmpOut[i]);
    }
    return out;
}

encrypt_1024 :: proc(data, key: []byte, tweak: []u64) -> [SIZE_1024]byte{
    ctx: Threefish1024;
    init(&ctx, key, tweak);
    tmpIn, tmpOut := ctx.tmpData1, ctx.tmpData2;
    uintlen := CIPHER_SIZE_1024 / 64;
    for i in 0..<uintlen {
        tmpIn[i] = util.U64_LE(data[i * 8 : i * 8 + 8]);
    }
    _encrypt_1024(&ctx, tmpIn[:], tmpOut[:]);
    out: [SIZE_1024]byte;
    for i in 0..<uintlen {
        util.PUT_U64_LE(out[i * 8 : i * 8 + 8], tmpOut[i]);
    }
    return out;
}

decrypt_1024 :: proc(data, key: []byte, tweak: []u64) -> [SIZE_1024]byte{
    ctx: Threefish1024;
    init(&ctx, key, tweak);
    tmpIn, tmpOut := ctx.tmpData1, ctx.tmpData2;
    uintlen := CIPHER_SIZE_1024 / 64;
    for i in 0..<uintlen {
        tmpIn[i] = util.U64_LE(data[i * 8 : i * 8 + 8]);
    }
    _decrypt_1024(&ctx, tmpIn[:], tmpOut[:]);
    out: [SIZE_1024]byte;
    for i in 0..<uintlen {
        util.PUT_U64_LE(out[i * 8 : i * 8 + 8], tmpOut[i]);
    }
    return out;
}