package gost

import "core:mem"

// @ref(zh): https://github.com/mjosaarinen/gost-r34.11-94

GOST :: struct {
    sum: [8]u32,
    hash: [8]u32,
    len: [8]u32,
    partial: [32]u8,
    partial_bytes: u8,
}

GOST_SBOX_1 : [256]u32;
GOST_SBOX_2 : [256]u32;
GOST_SBOX_3 : [256]u32;
GOST_SBOX_4 : [256]u32;

GOST_ENCRYPT_ROUND :: #force_inline proc "contextless"(l, r, t, k1, k2: u32) -> (u32, u32, u32) {
    l, r, t := l, r, t;
    t  = (k1) + r; 
    l ~= GOST_SBOX_1[t & 0xff] ~ GOST_SBOX_2[(t >> 8) & 0xff] ~ GOST_SBOX_3[(t >> 16) & 0xff] ~ GOST_SBOX_4[t >> 24]; 
    t  = (k2) + l; 
    r ~= GOST_SBOX_1[t & 0xff] ~ GOST_SBOX_2[(t >> 8) & 0xff] ~ GOST_SBOX_3[(t >> 16) & 0xff] ~ GOST_SBOX_4[t >> 24];
    return l, r, t;
}

GOST_ENCRYPT :: #force_inline proc "contextless"(l, r, t: u32, key: []u32) -> (u32, u32, u32) {
    l, r, t := l, r, t;
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[0], key[1]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[2], key[3]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[4], key[5]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[6], key[7]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[0], key[1]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[2], key[3]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[4], key[5]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[6], key[7]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[0], key[1]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[2], key[3]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[4], key[5]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[6], key[7]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[7], key[6]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[5], key[4]); 
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[3], key[2]);
    l, r, t = GOST_ENCRYPT_ROUND(l, r, t, key[1], key[0]); 
    t = r; 
    r = l; 
    l = t;
    return l, r, t;
}

gost_bytes :: proc(ctx: ^GOST, buf: []byte, bits: u32) {
    a, c: u32; 
    m: [8]u32;

    for i, j := 0, 0; i < 8; i += 1 {
        a = u32(buf[j]) | u32(buf[j + 1]) << 8 | u32(buf[j + 2]) << 16 | u32(buf[j + 3]) << 24;
        j += 4;
        m[i] = a;
        c = a + c + ctx.sum[i];
        ctx.sum[i] = c;
        c = c < a ? 1 : 0;
    }

    gost_compress(ctx.hash[:], m[:]);
    ctx.len[0] += bits;
    if ctx.len[0] < bits do ctx.len[1] += 1;
}

gost_compress :: proc(h, m: []u32) {
    key, u, v, w, s: [8]u32;

    copy(u[:], h);
    copy(v[:], m);

    for i := 0; i < 8; i += 2 {
        w[0] = u[0] ~ v[0];
        w[1] = u[1] ~ v[1];
        w[2] = u[2] ~ v[2];
        w[3] = u[3] ~ v[3];
        w[4] = u[4] ~ v[4];
        w[5] = u[5] ~ v[5];
        w[6] = u[6] ~ v[6];
        w[7] = u[7] ~ v[7];

        key[0] = (w[0] & 0x000000ff)       | (w[2] & 0x000000ff) <<  8 | (w[4] & 0x000000ff) << 16 | (w[6] & 0x000000ff) << 24;
        key[1] = (w[0] & 0x0000ff00) >>  8 | (w[2] & 0x0000ff00)       | (w[4] & 0x0000ff00) <<  8 | (w[6] & 0x0000ff00) << 16;
        key[2] = (w[0] & 0x00ff0000) >> 16 | (w[2] & 0x00ff0000) >>  8 | (w[4] & 0x00ff0000)       | (w[6] & 0x00ff0000) <<  8;
        key[3] = (w[0] & 0xff000000) >> 24 | (w[2] & 0xff000000) >> 16 | (w[4] & 0xff000000) >>  8 | (w[6] & 0xff000000);
        key[4] = (w[1] & 0x000000ff)       | (w[3] & 0x000000ff) <<  8 | (w[5] & 0x000000ff) << 16 | (w[7] & 0x000000ff) << 24;
        key[5] = (w[1] & 0x0000ff00) >>  8 | (w[3] & 0x0000ff00)       | (w[5] & 0x0000ff00) <<  8 | (w[7] & 0x0000ff00) << 16;
        key[6] = (w[1] & 0x00ff0000) >> 16 | (w[3] & 0x00ff0000) >>  8 | (w[5] & 0x00ff0000)       | (w[7] & 0x00ff0000) <<  8;
        key[7] = (w[1] & 0xff000000) >> 24 | (w[3] & 0xff000000) >> 16 | (w[5] & 0xff000000) >>  8 | (w[7] & 0xff000000);

        r := h[i];
        l := h[i + 1];
        t: u32;
        l, r, t = GOST_ENCRYPT(l, r, 0, key[:]);

        s[i] = r;
        s[i + 1] = l;

        if i == 6 do break;

        l    = u[0] ~ u[2];                 
        r    = u[1] ~ u[3];
        u[0] = u[2];
        u[1] = u[3];
        u[2] = u[4];
        u[3] = u[5];
        u[4] = u[6];
        u[5] = u[7];
        u[6] = l;
        u[7] = r;

        if i == 2 {
            u[0] ~= 0xff00ff00;
            u[1] ~= 0xff00ff00;
            u[2] ~= 0x00ff00ff;
            u[3] ~= 0x00ff00ff;
            u[4] ~= 0x00ffff00;
            u[5] ~= 0xff0000ff;
            u[6] ~= 0x000000ff;
            u[7] ~= 0xff00ffff;
        }

        l    = v[0];
        r    = v[2];
        v[0] = v[4];
        v[2] = v[6];
        v[4] = l ~ r;
        v[6] = v[0] ~ r;
        l    = v[1];
        r    = v[3];
        v[1] = v[5];
        v[3] = v[7];
        v[5] = l ~ r;
        v[7] = v[1] ~ r;
    }

    u[0] = m[0] ~ s[6];
    u[1] = m[1] ~ s[7];
    u[2] = m[2] ~ (s[0] << 16) ~ (s[0] >> 16) ~ (s[0] & 0xffff) ~ 
        (s[1] & 0xffff) ~ (s[1] >> 16) ~ (s[2] << 16) ~ s[6] ~ (s[6] << 16) ~
        (s[7] & 0xffff0000) ~ (s[7] >> 16);
    u[3] = m[3] ~ (s[0] & 0xffff) ~ (s[0] << 16) ~ (s[1] & 0xffff) ~
        (s[1] << 16) ~ (s[1] >> 16) ~ (s[2] << 16) ~ (s[2] >> 16) ~
        (s[3] << 16) ~ s[6] ~ (s[6] << 16) ~ (s[6] >> 16) ~ (s[7] & 0xffff) ~
        (s[7] << 16) ~ (s[7] >> 16);
    u[4] = m[4] ~
        (s[0] & 0xffff0000) ~ (s[0] << 16) ~ (s[0] >> 16) ~
        (s[1] & 0xffff0000) ~ (s[1] >> 16) ~ (s[2] << 16) ~ (s[2] >> 16) ~
        (s[3] << 16) ~ (s[3] >> 16) ~ (s[4] << 16) ~ (s[6] << 16) ~
        (s[6] >> 16) ~(s[7] & 0xffff) ~ (s[7] << 16) ~ (s[7] >> 16);
    u[5] = m[5] ~ (s[0] << 16) ~ (s[0] >> 16) ~ (s[0] & 0xffff0000) ~
        (s[1] & 0xffff) ~ s[2] ~ (s[2] >> 16) ~ (s[3] << 16) ~ (s[3] >> 16) ~
        (s[4] << 16) ~ (s[4] >> 16) ~ (s[5] << 16) ~  (s[6] << 16) ~
        (s[6] >> 16) ~ (s[7] & 0xffff0000) ~ (s[7] << 16) ~ (s[7] >> 16);
    u[6] = m[6] ~ s[0] ~ (s[1] >> 16) ~ (s[2] << 16) ~ s[3] ~ (s[3] >> 16) ~
        (s[4] << 16) ~ (s[4] >> 16) ~ (s[5] << 16) ~ (s[5] >> 16) ~ s[6] ~
        (s[6] << 16) ~ (s[6] >> 16) ~ (s[7] << 16);
    u[7] = m[7] ~ (s[0] & 0xffff0000) ~ (s[0] << 16) ~ (s[1] & 0xffff) ~
        (s[1] << 16) ~ (s[2] >> 16) ~ (s[3] << 16) ~ s[4] ~ (s[4] >> 16) ~
        (s[5] << 16) ~ (s[5] >> 16) ~ (s[6] >> 16) ~ (s[7] & 0xffff) ~
        (s[7] << 16) ~ (s[7] >> 16);

    v[0] = h[0] ~ (u[1] << 16) ~ (u[0] >> 16);
    v[1] = h[1] ~ (u[2] << 16) ~ (u[1] >> 16);
    v[2] = h[2] ~ (u[3] << 16) ~ (u[2] >> 16);
    v[3] = h[3] ~ (u[4] << 16) ~ (u[3] >> 16);
    v[4] = h[4] ~ (u[5] << 16) ~ (u[4] >> 16);
    v[5] = h[5] ~ (u[6] << 16) ~ (u[5] >> 16);
    v[6] = h[6] ~ (u[7] << 16) ~ (u[6] >> 16);
    v[7] = h[7] ~ (u[0] & 0xffff0000) ~ (u[0] << 16) ~ (u[7] >> 16) ~ (u[1] & 0xffff0000) ~ (u[1] << 16) ~ (u[6] << 16) ~ (u[7] & 0xffff0000);

    h[0] = (v[0] & 0xffff0000) ~ (v[0] << 16) ~ (v[0] >> 16) ~ (v[1] >> 16) ~
        (v[1] & 0xffff0000) ~ (v[2] << 16) ~ (v[3] >> 16) ~ (v[4] << 16) ~
        (v[5] >> 16) ~ v[5] ~ (v[6] >> 16) ~ (v[7] << 16) ~ (v[7] >> 16) ~
        (v[7] & 0xffff);
    h[1] = (v[0] << 16) ~ (v[0] >> 16) ~ (v[0] & 0xffff0000) ~ (v[1] & 0xffff) ~
        v[2] ~ (v[2] >> 16) ~ (v[3] << 16) ~ (v[4] >> 16) ~ (v[5] << 16) ~
        (v[6] << 16) ~ v[6] ~ (v[7] & 0xffff0000) ~ (v[7] >> 16);
    h[2] = (v[0] & 0xffff) ~ (v[0] << 16) ~ (v[1] << 16) ~ (v[1] >> 16) ~
        (v[1] & 0xffff0000) ~ (v[2] << 16) ~ (v[3] >> 16) ~ v[3] ~ (v[4] << 16) ~
        (v[5] >> 16) ~ v[6] ~ (v[6] >> 16) ~ (v[7] & 0xffff) ~ (v[7] << 16) ~
        (v[7] >> 16);
    h[3] = (v[0] << 16) ~ (v[0] >> 16) ~ (v[0] & 0xffff0000) ~
        (v[1] & 0xffff0000) ~ (v[1] >> 16) ~ (v[2] << 16) ~ (v[2] >> 16) ~ v[2] ~
        (v[3] << 16) ~ (v[4] >> 16) ~ v[4] ~ (v[5] << 16) ~ (v[6] << 16) ~
        (v[7] & 0xffff) ~ (v[7] >> 16);
    h[4] = (v[0] >> 16) ~ (v[1] << 16) ~ v[1] ~ (v[2] >> 16) ~ v[2] ~
        (v[3] << 16) ~ (v[3] >> 16) ~ v[3] ~ (v[4] << 16) ~ (v[5] >> 16) ~
        v[5] ~ (v[6] << 16) ~ (v[6] >> 16) ~ (v[7] << 16);
    h[5] = (v[0] << 16) ~ (v[0] & 0xffff0000) ~ (v[1] << 16) ~ (v[1] >> 16) ~
        (v[1] & 0xffff0000) ~ (v[2] << 16) ~ v[2] ~ (v[3] >> 16) ~ v[3] ~
        (v[4] << 16) ~ (v[4] >> 16) ~ v[4] ~ (v[5] << 16) ~ (v[6] << 16) ~
        (v[6] >> 16) ~ v[6] ~ (v[7] << 16) ~ (v[7] >> 16) ~ (v[7] & 0xffff0000);
    h[6] = v[0] ~ v[2] ~ (v[2] >> 16) ~ v[3] ~ (v[3] << 16) ~ v[4] ~
        (v[4] >> 16) ~ (v[5] << 16) ~ (v[5] >> 16) ~ v[5] ~ (v[6] << 16) ~
        (v[6] >> 16) ~ v[6] ~ (v[7] << 16) ~ v[7];
    h[7] = v[0] ~ (v[0] >> 16) ~ (v[1] << 16) ~ (v[1] >> 16) ~ (v[2] << 16) ~
        (v[3] >> 16) ~ v[3] ~ (v[4] << 16) ~ v[4] ~ (v[5] >> 16) ~ v[5] ~
        (v[6] << 16) ~ (v[6] >> 16) ~ (v[7] << 16) ~ v[7];
}

gost_init :: proc() {
    sbox: [8][16]u32 = {
        {  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
        { 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
        {  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
        {  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
        {  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
        {  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
        { 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
        {  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 },
    };

    i := 0;
    for a := 0; a < 16; a += 1 {
        ax := sbox[1][a] << 15;
        bx := sbox[3][a] << 23;
        cx := sbox[5][a];
        cx = (cx >> 1) | (cx << 31);
        dx := sbox[7][a] << 7;
        for b := 0; b < 16; b, i = b + 1, i + 1 {
            GOST_SBOX_1[i] = ax | (sbox[0][b] << 11);
            GOST_SBOX_2[i] = bx | (sbox[2][b] << 19);
            GOST_SBOX_3[i] = cx | (sbox[4][b] << 27);
            GOST_SBOX_4[i] = dx | (sbox[6][b] << 3);
        }
    }
}

gost_reset :: proc(ctx: ^GOST) {
    mem.set(&ctx.sum, 0, 32);
    mem.set(&ctx.hash, 0, 32);
    mem.set(&ctx.len, 0, 32);
    mem.set(&ctx.partial, 0, 32);
    ctx.partial_bytes = 0;
}

gost_update :: proc(ctx: ^GOST, buf: []byte) {
    length := u8(len(buf));
    j: u8;

    i := ctx.partial_bytes;
    for i < 32 && j < length {
        ctx.partial[i] = buf[j];
        i, j = i + 1, j + 1;
    }

    if i < 32 {
        ctx.partial_bytes = i;
        return;
    }
    gost_bytes(ctx, ctx.partial[:], 256);

    for (j + 32) < length {
        gost_bytes(ctx, buf[j:], 256);
        j += 32;
    }

    i = 0;
    for j < length {
        ctx.partial[i] = buf[j];
        i, j = i + 1, j + 1;
    }
    ctx.partial_bytes = i;
}

gost_final :: proc(ctx: ^GOST, digest: []byte) {
    if ctx.partial_bytes > 0 {
        mem.set(&ctx.partial[ctx.partial_bytes], 0, 32 - int(ctx.partial_bytes));
        gost_bytes(ctx, ctx.partial[:], u32(ctx.partial_bytes) << 3);
    }
  
    gost_compress(ctx.hash[:], ctx.len[:]);
    gost_compress(ctx.hash[:], ctx.sum[:]);

    for i, j := 0, 0; i < 8; i, j = i + 1, j + 4 {
        digest[j]     = u8(ctx.hash[i]);
        digest[j + 1] = u8(ctx.hash[i] >> 8);
        digest[j + 2] = u8(ctx.hash[i] >> 16);
        digest[j + 3] = u8(ctx.hash[i] >> 24);
    }
}

hash :: proc (data: []byte) -> [32]byte #no_bounds_check {
    hash : [32]byte;
    ctx: GOST;
    gost_init();
    gost_reset(&ctx);
    gost_update(&ctx, data);
    gost_final(&ctx, hash[:]);
    return hash;
}