package crypto

import "core:mem"

MD5_BLOCK_SIZE :: 16;

MD5_CTX :: struct {
    data: [64]u8,
    state: [4]u32,
    bitlen: u64,
    datalen: u32,
}

MD5_F :: inline proc "contextless" (x, y, z : u32) -> u32 {
    return ((x & y) | (~x & z));
}

MD5_G :: inline proc "contextless" (x, y, z : u32) -> u32 {
    return ((x & z) | (y & ~z));
}

MD5_H :: inline proc "contextless" (x, y, z : u32) -> u32 {
    return (x ~ y ~ z);
}

MD5_I :: inline proc "contextless" (x, y, z : u32) -> u32 {
    return (y ~ (x | ~z));
}

MD5_FF :: inline proc "contextless" (a, b, c, d, m, s, t : u32) -> u32 {
    a += MD5_F(b,c,d) + m + t;
    a = b + ROTL32(a,s); 
    return a;
}

MD5_GG :: inline proc "contextless" (a, b, c, d, m, s, t : u32) -> u32 {
    a += MD5_G(b,c,d) + m + t;
    a = b + ROTL32(a,s);
    return a;
}

MD5_HH :: inline proc "contextless" (a, b, c, d, m, s, t : u32) -> u32 {
    a += MD5_H(b,c,d) + m + t;
    a = b + ROTL32(a,s); 
    return a;
}

MD5_II :: inline proc "contextless" (a, b, c, d, m, s, t : u32) -> u32 {
    a += MD5_I(b,c,d) + m + t;
    a = b + ROTL32(a,s); 
    return a;
}

md5_transform :: proc(ctx: ^MD5_CTX, data: [64]byte) {

    a, b, c, d,  i, j : u32;
    m : [MD5_BLOCK_SIZE]u32;

    for i, j = 0, 0; i < MD5_BLOCK_SIZE; i+=1 {
        m[i] = u32(data[j]) + u32(data[j + 1]) << 8 + u32(data[j + 2]) << 16 + u32(data[j + 3]) << 24;
        j+=4;
    }

    a = ctx.state[0];
    b = ctx.state[1];
    c = ctx.state[2];
    d = ctx.state[3];

    a = MD5_FF(a,b,c,d,m[0],  7,0xd76aa478);
    d = MD5_FF(d,a,b,c,m[1], 12,0xe8c7b756);
    c = MD5_FF(c,d,a,b,m[2], 17,0x242070db);
    b = MD5_FF(b,c,d,a,m[3], 22,0xc1bdceee);
    a = MD5_FF(a,b,c,d,m[4],  7,0xf57c0faf);
    d = MD5_FF(d,a,b,c,m[5], 12,0x4787c62a);
    c = MD5_FF(c,d,a,b,m[6], 17,0xa8304613);
    b = MD5_FF(b,c,d,a,m[7], 22,0xfd469501);
    a = MD5_FF(a,b,c,d,m[8],  7,0x698098d8);
    d = MD5_FF(d,a,b,c,m[9], 12,0x8b44f7af);
    c = MD5_FF(c,d,a,b,m[10],17,0xffff5bb1);
    b = MD5_FF(b,c,d,a,m[11],22,0x895cd7be);
    a = MD5_FF(a,b,c,d,m[12], 7,0x6b901122);
    d = MD5_FF(d,a,b,c,m[13],12,0xfd987193);
    c = MD5_FF(c,d,a,b,m[14],17,0xa679438e);
    b = MD5_FF(b,c,d,a,m[15],22,0x49b40821);

    a = MD5_GG(a,b,c,d,m[1],  5,0xf61e2562);
    d = MD5_GG(d,a,b,c,m[6],  9,0xc040b340);
    c = MD5_GG(c,d,a,b,m[11],14,0x265e5a51);
    b = MD5_GG(b,c,d,a,m[0], 20,0xe9b6c7aa);
    a = MD5_GG(a,b,c,d,m[5],  5,0xd62f105d);
    d = MD5_GG(d,a,b,c,m[10], 9,0x02441453);
    c = MD5_GG(c,d,a,b,m[15],14,0xd8a1e681);
    b = MD5_GG(b,c,d,a,m[4], 20,0xe7d3fbc8);
    a = MD5_GG(a,b,c,d,m[9],  5,0x21e1cde6);
    d = MD5_GG(d,a,b,c,m[14], 9,0xc33707d6);
    c = MD5_GG(c,d,a,b,m[3], 14,0xf4d50d87);
    b = MD5_GG(b,c,d,a,m[8], 20,0x455a14ed);
    a = MD5_GG(a,b,c,d,m[13], 5,0xa9e3e905);
    d = MD5_GG(d,a,b,c,m[2],  9,0xfcefa3f8);
    c = MD5_GG(c,d,a,b,m[7], 14,0x676f02d9);
    b = MD5_GG(b,c,d,a,m[12],20,0x8d2a4c8a);

    a = MD5_HH(a,b,c,d,m[5],  4,0xfffa3942);
    d = MD5_HH(d,a,b,c,m[8], 11,0x8771f681);
    c = MD5_HH(c,d,a,b,m[11],16,0x6d9d6122);
    b = MD5_HH(b,c,d,a,m[14],23,0xfde5380c);
    a = MD5_HH(a,b,c,d,m[1],  4,0xa4beea44);
    d = MD5_HH(d,a,b,c,m[4], 11,0x4bdecfa9);
    c = MD5_HH(c,d,a,b,m[7], 16,0xf6bb4b60);
    b = MD5_HH(b,c,d,a,m[10],23,0xbebfbc70);
    a = MD5_HH(a,b,c,d,m[13], 4,0x289b7ec6);
    d = MD5_HH(d,a,b,c,m[0], 11,0xeaa127fa);
    c = MD5_HH(c,d,a,b,m[3], 16,0xd4ef3085);
    b = MD5_HH(b,c,d,a,m[6], 23,0x04881d05);
    a = MD5_HH(a,b,c,d,m[9],  4,0xd9d4d039);
    d = MD5_HH(d,a,b,c,m[12],11,0xe6db99e5);
    c = MD5_HH(c,d,a,b,m[15],16,0x1fa27cf8);
    b = MD5_HH(b,c,d,a,m[2], 23,0xc4ac5665);

    a = MD5_II(a,b,c,d,m[0],  6,0xf4292244);
    d = MD5_II(d,a,b,c,m[7], 10,0x432aff97);
    c = MD5_II(c,d,a,b,m[14],15,0xab9423a7);
    b = MD5_II(b,c,d,a,m[5], 21,0xfc93a039);
    a = MD5_II(a,b,c,d,m[12], 6,0x655b59c3);
    d = MD5_II(d,a,b,c,m[3], 10,0x8f0ccc92);
    c = MD5_II(c,d,a,b,m[10],15,0xffeff47d);
    b = MD5_II(b,c,d,a,m[1], 21,0x85845dd1);
    a = MD5_II(a,b,c,d,m[8],  6,0x6fa87e4f);
    d = MD5_II(d,a,b,c,m[15],10,0xfe2ce6e0);
    c = MD5_II(c,d,a,b,m[6], 15,0xa3014314);
    b = MD5_II(b,c,d,a,m[13],21,0x4e0811a1);
    a = MD5_II(a,b,c,d,m[4],  6,0xf7537e82);
    d = MD5_II(d,a,b,c,m[11],10,0xbd3af235);
    c = MD5_II(c,d,a,b,m[2], 15,0x2ad7d2bb);
    b = MD5_II(b,c,d,a,m[9], 21,0xeb86d391);

    ctx.state[0] += a;
	ctx.state[1] += b;
	ctx.state[2] += c;
	ctx.state[3] += d;
}

md5_init :: proc(ctx: ^MD5_CTX) {

    ctx.datalen = 0;
	ctx.bitlen = 0;
	ctx.state[0] = 0x67452301;
	ctx.state[1] = 0xefcdab89;
	ctx.state[2] = 0x98badcfe;
	ctx.state[3] = 0x10325476;
}

md5_update :: proc(ctx: ^MD5_CTX, data: []byte) {

    for i := 0; i < len(data); i += 1 {
        
        ctx.data[ctx.datalen] = data[i];
        ctx.datalen += 1;

        if(ctx.datalen == 64) {
            md5_transform(ctx, ctx.data);
            ctx.bitlen += 512;
            ctx.datalen = 0;
        }
    }
}

md5_final :: proc(ctx: ^MD5_CTX, hash: ^[MD5_BLOCK_SIZE]u8){

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
        
        md5_transform(ctx, ctx.data);
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
    md5_transform(ctx, ctx.data);

    for i = 0; i < 4; i+=1 {
		hash[i]      = u8((ctx.state[0] >> (i * 8))) & 0x000000ff;
		hash[i + 4]  = u8((ctx.state[1] >> (i * 8))) & 0x000000ff;
		hash[i + 8]  = u8((ctx.state[2] >> (i * 8))) & 0x000000ff;
		hash[i + 12] = u8((ctx.state[3] >> (i * 8))) & 0x000000ff;
    }
}

md5 :: proc(data: []byte) -> [MD5_BLOCK_SIZE]byte {

    hash : [MD5_BLOCK_SIZE]byte;
    ctx : MD5_CTX;

    md5_init(&ctx);
	md5_update(&ctx, data);
	md5_final(&ctx, &hash);

    return hash;
}