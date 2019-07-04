package jh

import "core:fmt"
import "core:strings"

// @ref(zh): http://www3.ntu.edu.sg/home/wuhj/research/jh/jh_ref.h

JH_ROUNDCONSTANT_ZERO := [64]byte {
    0x6,0xa,0x0,0x9,0xe,0x6,0x6,0x7,
    0xf,0x3,0xb,0xc,0xc,0x9,0x0,0x8,
    0xb,0x2,0xf,0xb,0x1,0x3,0x6,0x6,
    0xe,0xa,0x9,0x5,0x7,0xd,0x3,0xe,
    0x3,0xa,0xd,0xe,0xc,0x1,0x7,0x5,
    0x1,0x2,0x7,0x7,0x5,0x0,0x9,0x9,
    0xd,0xa,0x2,0xf,0x5,0x9,0x0,0xb,
    0x0,0x6,0x6,0x7,0x3,0x2,0x2,0xa
};

JH_S := [2][16]byte {
    {9,0,4,11,13,12,3,15,1,10,2,6,7,5,8,14},
    {3,12,6,13,5,7,1,9,15,2,0,4,11,10,14,8}
};

JH :: struct {
    hashbitlen: int,
    databitlen: u64,
    datasize_in_buffer: u64,
    H: [128]byte,
    A: [256]byte,
    roundconstant: [64]byte,
    buffer: [64]byte,
}

JH_L :: inline proc "contextless"(a, b: byte) -> (byte, byte) {
    (b) ~= ( ( (a) << 1) ~ ( (a) >> 3) ~ (( (a) >> 2) & 2) ) & 0xf;
    (a) ~= ( ( (b) << 1) ~ ( (b) >> 3) ~ (( (b) >> 2) & 2) ) & 0xf;
    return a, b;
}

JH_E8_finaldegroup :: proc(ctx: ^JH) {
    t0,t1,t2,t3: byte;
    tem: [256]u8;

    for i := 0; i < 128; i += 1 {
        tem[i] = ctx.A[i << 1];
        tem[i+128] = ctx.A[(i << 1)+1];
    }

    for i := 0; i < 128; i += 1 do ctx.H[i] = 0;
    for i := 0; i < 256; i += 1 {
        t0 = (tem[i] >> 3) & 1;
        t1 = (tem[i] >> 2) & 1;
        t2 = (tem[i] >> 1) & 1;
        t3 = (tem[i] >> 0) & 1;

        ctx.H[uint(i)>>3] |= t0 << (7 - (uint(i) & 7));
        ctx.H[(uint(i) + 256)>>3] |= t1 << (7 - (uint(i) & 7));
        ctx.H[(uint(i) + 512)>>3] |= t2 << (7 - (uint(i) & 7));
        ctx.H[(uint(i) + 768)>>3] |= t3 << (7 - (uint(i) & 7));
    }
}

jh_update_roundconstant :: proc(ctx: ^JH) {
    tem: [64]byte;
    t: byte;

    for i := 0; i < 64; i += 1 do tem[i] = JH_S[0][ctx.roundconstant[i]];
    for i := 0; i < 64; i += 2 do tem[i], tem[i+1] = JH_L(tem[i], tem[i+1]);
    for i := 0; i < 64; i += 4 {
        t = tem[i+2];
        tem[i+2] = tem[i+3];
        tem[i+3] = t;
    }
    for i := 0; i < 32; i += 1 {
        ctx.roundconstant[i]    = tem[i<<1];
        ctx.roundconstant[i+32] = tem[(i<<1)+1];
    }
    for i := 32; i < 64; i += 2 {
        t = ctx.roundconstant[i];
        ctx.roundconstant[i] = ctx.roundconstant[i+1];
        ctx.roundconstant[i+1] = t;
    }
}

JH_R8 :: proc(ctx: ^JH) {
    t: byte;
    tem, roundconstant_expanded: [256]byte;

    for i := u32(0); i < 256; i += 1 do roundconstant_expanded[i] = (ctx.roundconstant[i >> 2] >> (3 - (i & 3)) ) & 1;
    for i := 0; i < 256; i += 1 do tem[i] = JH_S[roundconstant_expanded[i]][ctx.A[i]];
    for i := 0; i < 256; i += 2 do tem[i], tem[i+1] = JH_L(tem[i], tem[i+1]);
    for i := 0; i < 256; i += 4 {
        t = tem[i+2];
        tem[i+2] = tem[i+3];
        tem[i+3] = t;
    }
    for i := 0; i < 128; i += 1 {
        ctx.A[i] = tem[i<<1];
        ctx.A[i+128] = tem[(i<<1)+1];
    }
    for i := 128; i < 256; i += 2 {
        t = ctx.A[i];
        ctx.A[i] = ctx.A[i+1];
        ctx.A[i+1] = t;
    }
}

JH_E8_initialgroup :: proc(ctx: ^JH) {
    t0,t1,t2,t3: byte;
    tem: [256]byte;

    for i := u32(0); i < 256; i += 1 {
        t0 = (ctx.H[i>>3] >> (7 - (i & 7)) ) & 1;
        t1 = (ctx.H[(i+256)>>3] >> (7 - (i & 7)) ) & 1;
        t2 = (ctx.H[(i+ 512 )>>3] >> (7 - (i & 7)) ) & 1;
        t3 = (ctx.H[(i+ 768 )>>3] >> (7 - (i & 7)) ) & 1;
        tem[i] = (t0 << 3) | (t1 << 2) | (t2 << 1) | (t3 << 0);
    }

    for i := 0; i < 128; i += 1 {
        ctx.A[i << 1] = tem[i];
        ctx.A[(i << 1)+1] = tem[i+128];
    }
}

JH_E8 :: proc(ctx: ^JH) {
    t0,t1,t2,t3: byte;
    tem: [256]byte;

    for i := 0; i < 64; i += 1 do ctx.roundconstant[i] = JH_ROUNDCONSTANT_ZERO[i];
    JH_E8_initialgroup(ctx);
    for i := 0; i < 42; i += 1 {
        JH_R8(ctx);
        jh_update_roundconstant(ctx);
    }
    JH_E8_finaldegroup(ctx);
}

JH_F8 :: proc(ctx: ^JH) {
    for i := 0; i < 64; i += 1 do ctx.H[i] ~= ctx.buffer[i];
    JH_E8(ctx);
    for i := 0; i < 64; i += 1 do ctx.H[i + 64] ~= ctx.buffer[i];
}

jh_init :: proc(ctx: ^JH, hashbitlen: int) {
    ctx.databitlen = 0;
	ctx.datasize_in_buffer = 0;
    ctx.hashbitlen = hashbitlen;
    for i := 0; i < 64; i += 1 do ctx.buffer[i] = 0;
    for i := 0; i < 128; i += 1 do ctx.H[i] = 0;
    ctx.H[1] = u8(hashbitlen) & 0xff;
    ctx.H[0] = u8(hashbitlen >> 8) & 0xff;
    JH_F8(ctx);
}

jh_update :: proc(ctx: ^JH, data: []byte) {
    databitlen := u64(len(data)) * 8;
    ctx.databitlen += databitlen;
    index := u64(0);

    if (ctx.datasize_in_buffer > 0) && ((ctx.datasize_in_buffer + databitlen) < 512) {
        if (databitlen & 7) == 0 {
            copy(ctx.buffer[ctx.datasize_in_buffer >> 3:], data[:64-(ctx.datasize_in_buffer >> 3)]);
		} else {
            copy(ctx.buffer[ctx.datasize_in_buffer >> 3:], data[:64-(ctx.datasize_in_buffer >> 3) + 1]);
        } 
        ctx.datasize_in_buffer += databitlen;
        databitlen = 0;
    }

    if (ctx.datasize_in_buffer > 0 ) && ((ctx.datasize_in_buffer + databitlen) >= 512) {
        copy(ctx.buffer[ctx.datasize_in_buffer >> 3:], data[:64-(ctx.datasize_in_buffer >> 3)]);
	    index = 64-(ctx.datasize_in_buffer >> 3);
	    databitlen = databitlen - (512 - ctx.datasize_in_buffer);
	    JH_F8(ctx);
	    ctx.datasize_in_buffer = 0;
    }

    for databitlen >= 512 {
        copy(ctx.buffer[:], data[index:index+64]);
        JH_F8(ctx);
        index += 64;
        databitlen -= 512;
    }

    if databitlen > 0 {
        if (databitlen & 7) == 0 {
            copy(ctx.buffer[:], data[index:index + ((databitlen & 0x1ff) >> 3)]);
        } else {
            copy(ctx.buffer[:], data[index:index + ((databitlen & 0x1ff) >> 3) + 1]);
        }
        ctx.datasize_in_buffer = databitlen;
    }
}

jh_final :: proc(ctx: ^JH) -> [128]byte {
    if (ctx.databitlen & 0x1ff) == 0 {
        for i := 0; i < 64; i += 1 do ctx.buffer[i] = 0;
        ctx.buffer[0] = 0x80;
        ctx.buffer[63] = u8(ctx.databitlen) & 0xff;
        ctx.buffer[62] = u8(ctx.databitlen >> 8) & 0xff;
        ctx.buffer[61] = u8(ctx.databitlen >> 16) & 0xff;
        ctx.buffer[60] = u8(ctx.databitlen >> 24) & 0xff;
        ctx.buffer[59] = u8(ctx.databitlen >> 32) & 0xff;
        ctx.buffer[58] = u8(ctx.databitlen >> 40) & 0xff;
        ctx.buffer[57] = u8(ctx.databitlen >> 48) & 0xff;
        ctx.buffer[56] = u8(ctx.databitlen >> 56) & 0xff;
        JH_F8(ctx);
    } else {
        if (ctx.datasize_in_buffer & 7) == 0 {
            for i := (ctx.databitlen & 0x1ff) >> 3; i < 64; i += 1 do ctx.buffer[i] = 0;
        } else {
            for i := ((ctx.databitlen & 0x1ff) >> 3) + 1; i < 64; i += 1 do ctx.buffer[i] = 0;
        }
                   
        ctx.buffer[(ctx.databitlen & 0x1ff) >> 3] |= 1 << (7- (ctx.databitlen & 7));
        JH_F8(ctx);
        for i := 0; i < 64; i += 1 do ctx.buffer[i] = 0;
        ctx.buffer[63] = u8(ctx.databitlen) & 0xff;
        ctx.buffer[62] = u8(ctx.databitlen >> 8) & 0xff;
        ctx.buffer[61] = u8(ctx.databitlen >> 16) & 0xff;
        ctx.buffer[60] = u8(ctx.databitlen >> 24) & 0xff;
        ctx.buffer[59] = u8(ctx.databitlen >> 32) & 0xff;
        ctx.buffer[58] = u8(ctx.databitlen >> 40) & 0xff;
        ctx.buffer[57] = u8(ctx.databitlen >> 48) & 0xff;
        ctx.buffer[56] = u8(ctx.databitlen >> 56) & 0xff;
        JH_F8(ctx);
    }
    return ctx.H;
}

hash_224 :: proc "contextless" (data: []byte) -> [28]byte #no_bounds_check {
    hash : [28]byte;
    ctx : JH;
    jh_init(&ctx, 224);
    jh_update(&ctx, data);
    tmp := jh_final(&ctx);
    copy(hash[:], tmp[100:128]);
    return hash;
}

hash_256 :: proc "contextless" (data: []byte) -> [32]byte #no_bounds_check {
    hash : [32]byte;
    ctx : JH;
    jh_init(&ctx, 256);
    jh_update(&ctx, data);
    tmp := jh_final(&ctx);
    copy(hash[:], tmp[96:128]);
    return hash;
}

hash_384 :: proc "contextless" (data: []byte) -> [48]byte #no_bounds_check {
    hash : [48]byte;
    ctx : JH;
    jh_init(&ctx, 384);
    jh_update(&ctx, data);
    tmp := jh_final(&ctx);
    copy(hash[:], tmp[80:128]);
    return hash;
}

hash_512 :: proc "contextless" (data: []byte) -> [64]byte #no_bounds_check {
    hash : [64]byte;
    ctx : JH;
    jh_init(&ctx, 512);
    jh_update(&ctx, data);
    tmp := jh_final(&ctx);
    copy(hash[:], tmp[64:128]);
    return hash;
}