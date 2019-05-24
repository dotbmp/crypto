package crypto

import "core:mem"

// @ref(bp): https://web.archive.org/web/20150111210116/http://labs.calyptix.com/haval.php
// HAVAL stub
// @question(bp): what license is HAVAL under?
// reference implementation:
// @ref(bp): ./refs/haval-1.1.tar.gz

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

HAVAL_FPHI_1 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32, rounds: int) -> u32 {
    switch rounds {
        case 3: return HAVAL_F_1(x1, x0, x3, x5, x6, x2, x4);
        case 4: return HAVAL_F_1(x2, x6, x1, x4, x5, x3, x0);
        case 5: return HAVAL_F_1(x3, x4, x1, x0, x5, x2, x6);
        case: assert(rounds < 3 || rounds > 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FPHI_2 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32, rounds: int) -> u32 {
    switch rounds {
        case 3: return HAVAL_F_2(x4, x2, x1, x0, x5, x3, x6);
        case 4: return HAVAL_F_2(x3, x5, x2, x0, x1, x6, x4);
        case 5: return HAVAL_F_2(x6, x2, x1, x0, x3, x4, x5);
        case: assert(rounds < 3 || rounds > 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FPHI_3 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32, rounds: int) -> u32 {
    switch rounds {
        case 3: return HAVAL_F_3(x6, x1, x2, x3, x4, x5, x0);
        case 4: return HAVAL_F_3(x1, x4, x3, x6, x0, x2, x5);
        case 5: return HAVAL_F_3(x2, x6, x0, x4, x3, x1, x5);
        case: assert(rounds < 3 || rounds > 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FPHI_4 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32, rounds: int) -> u32 {
    switch rounds {
        case 4: return HAVAL_F_5(x6, x4, x0, x5, x2, x1, x3);
        case 5: return HAVAL_F_5(x1, x5, x3, x2, x0, x4, x6);
        case: assert(rounds < 4 || rounds > 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FPHI_5 :: inline proc "contextless"(x6, x5, x4, x3, x2, x1, x0: u32, rounds: int) -> u32 {
    switch rounds {
        case 5: return HAVAL_F_5(x2, x5, x0, x6, x4, x3, x1);
        case: assert(rounds != 5, "Rounds count not supported!");
    }
    return 0;
}

HAVAL_FF_1 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w: u32, rounds: int) -> u32 {
    tmp := HAVAL_FPHI_1(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w;
    return x7;
}

HAVAL_FF_2 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, c: u32, rounds: int) -> u32 {
    tmp := HAVAL_FPHI_2(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w + c;
    return x7;
}

HAVAL_FF_3 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, c: u32, rounds: int) -> u32 {
    tmp := HAVAL_FPHI_3(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w + c;
    return x7;
}

HAVAL_FF_4 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, c: u32, rounds: int) -> u32 {
    tmp := HAVAL_FPHI_4(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w + c;
    return x7;
}

HAVAL_FF_5 :: inline proc "contextless"(x7, x6, x5, x4, x3, x2, x1, x0, w, c: u32, rounds: int) -> u32 {
    tmp := HAVAL_FPHI_5(x6, x5, x4, x3, x2, x1, x0, rounds);
    x7 = HAVAL_ROTR32(tmp, 7) + HAVAL_ROTR32(x7, 11) + w + c;
    return x7;
}

haval_block :: proc(ctx: ^HAVAL) {

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

haval_update :: proc(ctx: ^HAVAL, data: []byte) {
    i : u32;
    data_len := u32(len(data));
    rmd_len := u32((ctx.count[0] >> 3) & 0x7f);
    fill_len := 128 - rmd_len;

    ctx.count[0] += data_len << 3;
    if ctx.count[0] < (data_len << 3) do ctx.count[1] += 1;
    ctx.count[1] += data_len >> 29;

    when ODIN_ENDIAN != "little" {
        if rmd_len + data_len >= 128 {
            mem.copy(&ctx.block[rmd_len], data, fill_len);
            // memcpy (((unsigned char *)state->block)+rmd_len, str, fill_len);
            haval_block(ctx);
            for i = fill_len; i + 127 < data_len; i += 128 {
                mem.copy(&ctx.block[0], data[i], 128);
                // memcpy ((unsigned char *)state->block, str+i, 128);
                haval_block(ctx);
            }
            rmd_len = 0;
        } else {
            i = 0;
        }
        mem.copy(&ctx.block[rmd_len], data[i], str_len - i);
        // memcpy (((unsigned char *)state->block)+rmd_len, str+i, str_len-i);
    } else {
        if rmd_len + data_len >= 128 {
            mem.copy(&ctx.block[rmd_len], &data, int(fill_len));
            // memcpy (((unsigned char *)state->block)+rmd_len, str, fill_len);
            // ch2uint(state->remainder, state->block, 128);
            haval_block(ctx);
            for i = fill_len; i + 127 < data_len; i += 128 {
                mem.copy(&ctx.block[0], &data[i], 128);
                // memcpy ((unsigned char *)state->block, str+i, 128);
                // ch2uint(state->remainder, state->block, 128);
                haval_block(ctx);
            }
            rmd_len = 0;
        } else {
            i = 0;
        }
        mem.copy(&ctx.block[rmd_len], &data[i], int(data_len - i));
        // memcpy (((unsigned char *)state->block)+rmd_len, str+i, str_len-i);
    }
}

haval_final :: proc(ctx: ^HAVAL, digest: []byte, rounds, size: int) {
    pad_len: u32;
    tail : [10]u32;

    tail[0] = (256 & 0x3) << 6 | (u32(rounds) & 0x7) << 3 | (1 & 0x7);
    tail[1] = (256 >> 2) & 0xff;
    // uint2ch (state->count, &tail[2], 2);
    rmd_len := (ctx.count[0] >> 3) & 0x7f;
    if rmd_len < 118 {
        pad_len = 118 - rmd_len;
    } else {
        pad_len = 246 - rmd_len;
    }
    haval_update(ctx, HAVAL_PADDING[:]);
    //haval_update(ctx, tail[:]);
    // haval_tailor(state);
    // uint2ch (state->fingerprint, final_fpt, FPTLEN >> 5);
    mem.set(&ctx, 0, size_of(ctx));
}

haval :: proc "contextless" (data: []byte, rounds, size: int) -> []byte #no_bounds_check {

	hash : []byte = ---;
    ctx : HAVAL;
    haval_init(&ctx);
    haval_update(&ctx, data);
    haval_final(&ctx, hash[:], rounds, size);

    return hash;
}

haval_128 :: proc "contextless" (data: []byte) -> [16]byte #no_bounds_check {
    hash : [16]byte;
    tmp := haval(data, 3, 128);
    return hash;
}

haval_160 :: proc "contextless" (data: []byte) -> []byte #no_bounds_check {
    hash : []byte;
    return hash;
}

haval_192 :: proc "contextless" (data: []byte) -> []byte #no_bounds_check {
    hash : []byte;
    return hash;
}

haval_224 :: proc "contextless" (data: []byte) -> []byte #no_bounds_check {
    hash : []byte;
    return hash;
}

haval_256 :: proc "contextless" (data: []byte) -> []byte #no_bounds_check {
    hash : []byte;
    return hash;
}