package md4

import "core:mem"
import "../util"

MD4_BLOCK_SIZE :: 16;

MD4_CTX :: struct {
    data: [64]u8,
    state: [4]u32,
    bitlen: u64,
    datalen: u32,
}

MD4_F :: #force_inline proc "contextless" (x, y, z : u32) -> u32 {
    return ((x & y) | (~x & z));
}

MD4_G :: #force_inline proc "contextless" (x, y, z : u32) -> u32 {
    return ((x & y) | (x & z) | (y & z));
}

MD4_H :: #force_inline proc "contextless" (x, y, z : u32) -> u32 {
    return (x ~ y ~ z);
}

MD4_FF :: #force_inline proc "contextless" (a, b, c, d, x, s : u32) -> u32 {
    a := a;
    a += MD4_F(b,c,d) + x;
    a = util.ROTL32(a,int(s)); 
    return a;
}

MD4_GG :: #force_inline proc "contextless" (a, b, c, d, x, s : u32) -> u32 {
    a := a;
    a += MD4_G(b,c,d) + x + 0x5a827999;
    a = util.ROTL32(a,int(s));
    return a;
}

MD4_HH :: #force_inline proc "contextless" (a, b, c, d, x, s : u32) -> u32 {
    a := a;
    a += MD4_H(b,c,d) + x + 0x6ed9eba1;
    a = util.ROTL32(a,int(s)); 
    return a;
}

md4_transform :: proc(ctx: ^MD4_CTX, data: [64]byte) {
	a, b, c, d,  i, j : u32;
    m : [MD4_BLOCK_SIZE]u32;

    for i, j = 0, 0; i < MD4_BLOCK_SIZE; i+=1 {
        m[i] = u32(data[j]) | (u32(data[j + 1]) << 8) | (u32(data[j + 2]) << 16) | (u32(data[j + 3]) << 24);
        j+=4;
    }

    a = ctx.state[0];
    b = ctx.state[1];
    c = ctx.state[2];
    d = ctx.state[3];

    a = MD4_FF(a, b, c, d, m[0], 3);
    d = MD4_FF(d, a, b, c, m[1], 7);
    c = MD4_FF(c, d, a, b, m[2], 11);
    b = MD4_FF(b, c, d, a, m[3], 19);
    a = MD4_FF(a, b, c, d, m[4], 3);
    d = MD4_FF(d, a, b, c, m[5], 7);
    c = MD4_FF(c, d, a, b, m[6], 11);
    b = MD4_FF(b, c, d, a, m[7], 19);
    a = MD4_FF(a, b, c, d, m[8], 3);
    d = MD4_FF(d, a, b, c, m[9], 7);
    c = MD4_FF(c, d, a, b, m[10], 11);
    b = MD4_FF(b, c, d, a, m[11], 19);
    a = MD4_FF(a, b, c, d, m[12], 3);
    d = MD4_FF(d, a, b, c, m[13], 7);
    c = MD4_FF(c, d, a, b, m[14], 11);
    b = MD4_FF(b, c, d, a, m[15], 19);

    a = MD4_GG(a, b, c, d, m[0], 3);
    d = MD4_GG(d, a, b, c, m[4], 5);
    c = MD4_GG(c, d, a, b, m[8], 9);
    b = MD4_GG(b, c, d, a, m[12], 13);
    a = MD4_GG(a, b, c, d, m[1], 3);
    d = MD4_GG(d, a, b, c, m[5], 5);
    c = MD4_GG(c, d, a, b, m[9], 9);
    b = MD4_GG(b, c, d, a, m[13], 13);
    a = MD4_GG(a, b, c, d, m[2], 3);
    d = MD4_GG(d, a, b, c, m[6], 5);
    c = MD4_GG(c, d, a, b, m[10], 9);
    b = MD4_GG(b, c, d, a, m[14], 13);
    a = MD4_GG(a, b, c, d, m[3], 3);
    d = MD4_GG(d, a, b, c, m[7], 5);
    c = MD4_GG(c, d, a, b, m[11], 9);
    b = MD4_GG(b, c, d, a, m[15], 13);

    a = MD4_HH(a, b, c, d, m[0], 3);
    d = MD4_HH(d, a, b, c, m[8], 9);
    c = MD4_HH(c, d, a, b, m[4], 11);
    b = MD4_HH(b, c, d, a, m[12], 15);
    a = MD4_HH(a, b, c, d, m[2], 3);
    d = MD4_HH(d, a, b, c, m[10], 9);
    c = MD4_HH(c, d, a, b, m[6], 11);
    b = MD4_HH(b, c, d, a, m[14], 15);
    a = MD4_HH(a, b, c, d, m[1], 3);
    d = MD4_HH(d, a, b, c, m[9], 9);
    c = MD4_HH(c, d, a, b, m[5], 11);
    b = MD4_HH(b, c, d, a, m[13], 15);
    a = MD4_HH(a, b, c, d, m[3], 3);
    d = MD4_HH(d, a, b, c, m[11], 9);
    c = MD4_HH(c, d, a, b, m[7], 11);
    b = MD4_HH(b, c, d, a, m[15], 15);

    ctx.state[0] += a;
	ctx.state[1] += b;
	ctx.state[2] += c;
	ctx.state[3] += d;
}

md4_init :: proc(ctx: ^MD4_CTX) {
    
    ctx.datalen = 0;
	ctx.bitlen = 0;
	ctx.state[0] = 0x67452301;
	ctx.state[1] = 0xefcdab89;
	ctx.state[2] = 0x98badcfe;
	ctx.state[3] = 0x10325476;
}

md4_update :: proc(ctx: ^MD4_CTX, data: []byte) {

    for i := 0; i < len(data); i += 1 {
        
        ctx.data[ctx.datalen] = data[i];
        ctx.datalen += 1;

        if(ctx.datalen == 64) {
            md4_transform(ctx, ctx.data);
            ctx.bitlen += 512;
            ctx.datalen = 0;
        }
    }
}

md4_final :: proc(ctx: ^MD4_CTX, hash: ^[MD4_BLOCK_SIZE]u8){

    i : u32;
    i = ctx.datalen;

    if ctx.datalen < 56 {

        ctx.data[i] = 0x80;
        i += 1;

        for i < 56 {
            ctx.data[i] = 0x00;
            i += 1;
        }
    
    } else if ctx.datalen >= 56 {

        ctx.data[i] = 0x80;
        i += 1;

        for i < 64 {
            ctx.data[i] = 0x00;
            i+=1;
        }
        
        md4_transform(ctx, ctx.data);
        mem.set(&ctx.data, 0, 56);
    }

    ctx.bitlen += u64(ctx.datalen * 8);
    ctx.data[56] = u8(ctx.bitlen);
    ctx.data[57] = u8(ctx.bitlen >> 8);
    ctx.data[58] = u8(ctx.bitlen >> 16);
    ctx.data[59] = u8(ctx.bitlen >> 24);
    ctx.data[60] = u8(ctx.bitlen >> 32);
    ctx.data[61] = u8(ctx.bitlen >> 40);
    ctx.data[62] = u8(ctx.bitlen >> 48);
    ctx.data[63] = u8(ctx.bitlen >> 56);
    md4_transform(ctx, ctx.data);

    for i = 0; i < 4; i+=1 {
		hash[i]      = u8((ctx.state[0] >> (i * 8))) & 0x000000ff;
		hash[i + 4]  = u8((ctx.state[1] >> (i * 8))) & 0x000000ff;
		hash[i + 8]  = u8((ctx.state[2] >> (i * 8))) & 0x000000ff;
		hash[i + 12] = u8((ctx.state[3] >> (i * 8))) & 0x000000ff;
    }
}

hash :: proc(data: []byte) -> [MD4_BLOCK_SIZE]byte {

    hash : [MD4_BLOCK_SIZE]byte;
    ctx : MD4_CTX;

    md4_init(&ctx);
	md4_update(&ctx, data);
	md4_final(&ctx, &hash);

    return hash;
}