package sha1

import "core:mem"
import "../util"

DIGEST_SIZE :: 20;
BLOCK_SIZE :: 64;

SHA1_CTX :: struct {
    data : [BLOCK_SIZE]u8,
    datalen : u32,
    bitlen : u64,
    state : [5]u32,
    k : [4]u32,
}

sha1_transform :: proc(ctx : ^SHA1_CTX, data : [BLOCK_SIZE]byte) {
    a, b, c, d, e, i, j, t : u32;
    m : [80]u32;

	for i, j = 0, 0; i < 16; i += 1 {
        m[i] = u32(data[j]) << 24 + u32(data[j + 1]) << 16 + u32(data[j + 2]) << 8 + u32(data[j + 3]);
        j += 4;
    }
	for i < 80 {
		m[i] = (m[i - 3] ~ m[i - 8] ~ m[i - 14] ~ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
        i += 1;
	}

	a = ctx.state[0];
	b = ctx.state[1];
	c = ctx.state[2];
	d = ctx.state[3];
	e = ctx.state[4];

	for i = 0; i < 20; i += 1 {
		t = util.ROTL32(a, 5) + ((b & c) ~ (~b & d)) + e + ctx.k[0] + m[i];
		e = d;
		d = c;
		c = util.ROTL32(b, 30);
		b = a;
		a = t;
	}
	for i < 40 {
		t = util.ROTL32(a, 5) + (b ~ c ~ d) + e + ctx.k[1] + m[i];
		e = d;
		d = c;
		c = util.ROTL32(b, 30);
		b = a;
		a = t;
        i += 1;
	}
	for i < 60 {
		t = util.ROTL32(a, 5) + ((b & c) ~ (b & d) ~ (c & d)) + e + ctx.k[2] + m[i];
		e = d;
		d = c;
		c = util.ROTL32(b, 30);
		b = a;
		a = t;
        i += 1;
	}
	for i < 80 {
		t = util.ROTL32(a, 5) + (b ~ c ~ d) + e + ctx.k[3] + m[i];
		e = d;
		d = c;
		c = util.ROTL32(b, 30);
		b = a;
		a = t;
        i += 1;
	}

	ctx.state[0] += a;
	ctx.state[1] += b;
	ctx.state[2] += c;
	ctx.state[3] += d;
	ctx.state[4] += e;
}

sha1_init :: proc(ctx : ^SHA1_CTX) {
    ctx.datalen = 0;
	ctx.bitlen = 0;
	ctx.state[0] = 0x67452301;
	ctx.state[1] = 0xefcdab89;
	ctx.state[2] = 0x98badcfe;
	ctx.state[3] = 0x10325476;
	ctx.state[4] = 0xc3d2e1f0;
	ctx.k[0] = 0x5a827999;
	ctx.k[1] = 0x6ed9eba1;
	ctx.k[2] = 0x8f1bbcdc;
	ctx.k[3] = 0xca62c1d6;
}

sha1_update :: proc(ctx : ^SHA1_CTX, data : []byte) {
	for i : i32 = 0; i < i32(len(data)); i += 1 {
		ctx.data[ctx.datalen] = data[i];
		ctx.datalen += 1;
		if (ctx.datalen == BLOCK_SIZE) {
			sha1_transform(ctx, ctx.data);
			ctx.bitlen += 512;
			ctx.datalen = 0;
		}
	}
}

sha1_final :: proc(ctx : ^SHA1_CTX, hash : ^[DIGEST_SIZE]byte) {
	i := ctx.datalen;

	if ctx.datalen < 56 {
		ctx.data[i] = 0x80;
        i += 1;
        for i < 56 {
            ctx.data[i] = 0x00;
            i += 1;
        }
	}
	else {
		ctx.data[i] = 0x80;
        i += 1;
        for i < BLOCK_SIZE {
            ctx.data[i] = 0x00;
            i += 1;
        }
		sha1_transform(ctx, ctx.data);
		mem.set(&ctx.data, 0, 56);
	}

	ctx.bitlen += u64(ctx.datalen * 8);
	ctx.data[63] = u8(ctx.bitlen);
	ctx.data[62] = u8(ctx.bitlen >> 8);
	ctx.data[61] = u8(ctx.bitlen >> 16);
	ctx.data[60] = u8(ctx.bitlen >> 24);
	ctx.data[59] = u8(ctx.bitlen >> 32);
	ctx.data[58] = u8(ctx.bitlen >> 40);
	ctx.data[57] = u8(ctx.bitlen >> 48);
	ctx.data[56] = u8(ctx.bitlen >> 56);
	sha1_transform(ctx, ctx.data);

	for i : u32 = 0; i < 4; i += 1 {
		hash[i]      = u8((ctx.state[0] >> (24 - i * 8))) & 0x000000ff;
		hash[i + 4]  = u8((ctx.state[1] >> (24 - i * 8))) & 0x000000ff;
		hash[i + 8]  = u8((ctx.state[2] >> (24 - i * 8))) & 0x000000ff;
		hash[i + 12] = u8((ctx.state[3] >> (24 - i * 8))) & 0x000000ff;
		hash[i + 16] = u8((ctx.state[4] >> (24 - i * 8))) & 0x000000ff;
	}
}

hash :: proc(data: []byte) -> [DIGEST_SIZE]byte {
    hash : [DIGEST_SIZE]byte;
    ctx : SHA1_CTX;
    sha1_init(&ctx);
	sha1_update(&ctx, data);
	sha1_final(&ctx, &hash);
    return hash;
}