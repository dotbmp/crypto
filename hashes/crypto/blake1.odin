package crypto

import "core:runtime"
import "core:mem"
import "core:fmt"

// @ref(zh): https://github.com/ouzklcn/blake

BLAKE1_SIZE_224 :: 28;
BLAKE1_SIZE_256 :: 32;
BLAKE1_SIZE_384 :: 48;
BLAKE1_SIZE_512 :: 64;
BLAKE1_BLOCKSIZE_256 :: 64;
BLAKE1_BLOCKSIZE_512 :: 128;

BLAKE1_INIT_0_224 :: 0xc1059ed8;
BLAKE1_INIT_1_224 :: 0x367cd507;
BLAKE1_INIT_2_224 :: 0x3070dd17;
BLAKE1_INIT_3_224 :: 0xf70e5939;
BLAKE1_INIT_4_224 :: 0xffc00b31;
BLAKE1_INIT_5_224 :: 0x68581511;
BLAKE1_INIT_6_224 :: 0x64f98fa7;
BLAKE1_INIT_7_224 :: 0xbefa4fa4;
BLAKE1_INIT_0_256 :: 0x6a09e667;
BLAKE1_INIT_1_256 :: 0xbb67ae85;
BLAKE1_INIT_2_256 :: 0x3c6ef372;
BLAKE1_INIT_3_256 :: 0xa54ff53a;
BLAKE1_INIT_4_256 :: 0x510e527f;
BLAKE1_INIT_5_256 :: 0x9b05688c;
BLAKE1_INIT_6_256 :: 0x1f83d9ab;
BLAKE1_INIT_7_256 :: 0x5be0cd19;
BLAKE1_INIT_0_384 :: 0xcbbb9d5dc1059ed8;
BLAKE1_INIT_1_384 :: 0x629a292a367cd507;
BLAKE1_INIT_2_384 :: 0x9159015a3070dd17;
BLAKE1_INIT_3_384 :: 0x152fecd8f70e5939;
BLAKE1_INIT_4_384 :: 0x67332667ffc00b31;
BLAKE1_INIT_5_384 :: 0x8eb44a8768581511;
BLAKE1_INIT_6_384 :: 0xdb0c2e0d64f98fa7;
BLAKE1_INIT_7_384 :: 0x47b5481dbefa4fa4;
BLAKE1_INIT_0_512 :: 0x6a09e667f3bcc908;
BLAKE1_INIT_1_512 :: 0xbb67ae8584caa73b;
BLAKE1_INIT_2_512 :: 0x3c6ef372fe94f82b;
BLAKE1_INIT_3_512 :: 0xa54ff53a5f1d36f1;
BLAKE1_INIT_4_512 :: 0x510e527fade682d1;
BLAKE1_INIT_5_512 :: 0x9b05688c2b3e6c1f;
BLAKE1_INIT_6_512 :: 0x1f83d9abfb41bd6b;
BLAKE1_INIT_7_512 :: 0x5be0cd19137e2179;

BLAKE1_256_CTX :: struct {
    h : [8]u32,
    s : [4]u32,
    t : u32,
    x : [64]byte,
    nx : i32,
    is224 : bool,
    nullt : bool,
}

BLAKE1_512_CTX :: struct {
    h : [8]u64,
    s : [4]u64,
    t : u64,
    x : [128]byte,
    nx : i32,
    is384 : bool,
    nullt : bool,
}

BLAKE1_SIGMA := []i32 {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
	11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
	7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
	9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
	2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
	12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
	13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
	6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
	10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
};

BLAKE1_U256 := [16]u32 {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

BLAKE1_U512 := [16]u64 {
	0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
	0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
	0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
	0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69
};

blake1_g256 :: inline proc "contextless" (a, b, c, d: u32, m: [16]u32, i, j: u32) -> (u32, u32, u32, u32) {
	a += m[BLAKE1_SIGMA[(i % 10) * 16 + (2 * j)]] ~ BLAKE1_U256[BLAKE1_SIGMA[(i % 10) * 16 + (2 * j + 1)]];
	a += b;
	d ~= a;
	d = d << (32 - 16) | d >> 16;
	c += d;
	b ~= c;
	b = b << (32 - 12) | b >> 12;
	a += m[BLAKE1_SIGMA[(i % 10) * 16 + (2 * j + 1)]] ~ BLAKE1_U256[BLAKE1_SIGMA[(i % 10) * 16 + (2 * j)]];
	a += b;
	d ~= a;
	d = d << (32 - 8) | d >> 8;
	c += d;
	b ~= c;
	b = b << (32 - 7) | b >> 7;
	return a, b, c, d;
}

blake1_g512 :: inline proc "contextless" (a, b, c, d: u64, m: [16]u64, i, j: u32) -> (u64, u64, u64, u64) {
	a += m[BLAKE1_SIGMA[(i % 10) * 16 + (2 * j)]] ~ BLAKE1_U512[BLAKE1_SIGMA[(i % 10) * 16 + (2 * j + 1)]];
	a += b;
	d ~= a;
	d = d << (64 - 32) | d >> 32;
	c += d;
	b ~= c;
	b = b << (64 - 25) | b >> 25;
	a += m[BLAKE1_SIGMA[(i % 10) * 16 + (2 * j + 1)]] ~ BLAKE1_U512[BLAKE1_SIGMA[(i % 10) * 16 + (2 * j)]];
	a += b;
	d ~= a;
	d = d << (64 - 16) | d >> 16;
	c += d;
	b ~= c;
	b = b << (64 - 11) | b >> 11;
	return a, b, c, d;
}

blake1_block256 :: proc(ctx : ^BLAKE1_256_CTX, p : []u8) {
    h : [8]u32;
	i, j : u32;
	for i = 0; i < 8; i += 1 {
		h[i] = ctx.h[i];
	}

	for len(p) >= BLAKE1_BLOCKSIZE_256 {
		v : [16]u32;
		for i = 0; i < 4; i += 1 {
			v[i], v[i + 4] = h[i], h[i + 4];
			v[i + 8], v[i + 12] = ctx.s[i] ~ BLAKE1_U256[i], BLAKE1_U256[i + 4];
		}

		ctx.t += 512;
		if !ctx.nullt {
			v[12] ~= ctx.t;
			v[13] ~= ctx.t;
			v[14] ~= ctx.t >> 32;
			v[15] ~= ctx.t >> 32;
		}

		m : [16]u32;
		for i, j = 0, 0; i < 16; i += 1 {
			m[i] = u32(p[j]) << 24 | u32(p[j + 1]) << 16 | u32(p[j + 2]) << 8 | u32(p[j + 3]);
            j += 4;
		}

		for i = 0; i < 14; i += 1 {
			for j = 0; j < 4; j += 1 {
				v[j], v[j + 4], v[j + 8], v[j + 12] = blake1_g256(v[j], v[j + 4], v[j + 8], v[j + 12], m, i, j);
			}
			for j = 0; j < 4; j += 1 {
				v[j], v[((j + 1) % 4) + 4], v[((j + 2) % 4) + 8], v[((j + 3) % 4) + 12] = blake1_g256(v[j], v[((j + 1) % 4) + 4], v[((j + 2) % 4) + 8], v[((j + 3) % 4) + 12], m, i, j + 4);
			}
		}

		for i = 0; i < 8; i += 1 {
			h[i] ~= ctx.s[i % 4] ~ v[i] ~ v[i + 8];
		}
		p = p[BLAKE1_BLOCKSIZE_256:];
	}

	for i = 0; i < 8; i += 1 {
		ctx.h[i] = h[i];
	}
}

blake1_block512 :: proc(ctx : ^BLAKE1_512_CTX, p : []u8) {
    h : [8]u64;
	i, j : u32;
	for i = 0; i < 8; i += 1 {
		h[i] = ctx.h[i];
	}

	for len(p) >= BLAKE1_BLOCKSIZE_512 {
		v : [16]u64;
		for i = 0; i < 4; i += 1 {
			v[i], v[i + 4] = h[i], h[i + 4];
			v[i + 8], v[i + 12] = ctx.s[i] ~ BLAKE1_U512[i], u64(BLAKE1_U512[i + 4]);
		}

		ctx.t += 1024;
		if !ctx.nullt {
			v[12] ~= ctx.t;
			v[13] ~= ctx.t;
			v[14] ~= 0;
			v[15] ~= 0;
		}

		m : [16]u64;
		for i, j = 0, 0; i < 16; i += 1 {
			m[i] = u64(p[j]) << 56 | u64(p[j + 1]) << 48 | u64(p[j + 2]) << 40 | u64(p[j + 3]) << 32 | u64(p[j + 4]) << 24 | u64(p[j + 5]) << 16 | u64(p[j + 6]) << 8 | u64(p[j + 7]);
            j += 8;
		}

		for i = 0; i < 16; i += 1 {
			for j = 0; j < 4; j += 1 {
				v[j], v[j + 4], v[j + 8], v[j + 12] = blake1_g512(v[j], v[j + 4], v[j + 8], v[j + 12], m, i, j);
			}
			for j = 0; j < 4; j += 1 {
				v[j], v[((j + 1) % 4) + 4], v[((j + 2) % 4) + 8], v[((j + 3) % 4) + 12] = blake1_g512(v[j], v[((j + 1) % 4) + 4], v[((j + 2) % 4) + 8], v[((j + 3) % 4) + 12], m, i, j + 4);
			}
		}

		for i = 0; i < 8; i += 1 {
			h[i] ~= ctx.s[i % 4] ~ v[i] ~ v[i + 8];
		}
		p = p[BLAKE1_BLOCKSIZE_512:];
	}

	for i = 0; i < 8; i += 1 {
		ctx.h[i] = h[i];
	}
}

blake1_reset_256 :: proc(ctx : ^BLAKE1_256_CTX) {
    if ctx.is224 {
		ctx.h[0] = BLAKE1_INIT_0_224;
		ctx.h[1] = BLAKE1_INIT_1_224;
		ctx.h[2] = BLAKE1_INIT_2_224;
		ctx.h[3] = BLAKE1_INIT_3_224;
		ctx.h[4] = BLAKE1_INIT_4_224;
		ctx.h[5] = BLAKE1_INIT_5_224;
		ctx.h[6] = BLAKE1_INIT_6_224;
		ctx.h[7] = BLAKE1_INIT_7_224;
	} else {
		ctx.h[0] = BLAKE1_INIT_0_256;
		ctx.h[1] = BLAKE1_INIT_1_256;
		ctx.h[2] = BLAKE1_INIT_2_256;
		ctx.h[3] = BLAKE1_INIT_3_256;
		ctx.h[4] = BLAKE1_INIT_4_256;
		ctx.h[5] = BLAKE1_INIT_5_256;
		ctx.h[6] = BLAKE1_INIT_6_256;
		ctx.h[7] = BLAKE1_INIT_7_256;
	}
	ctx.t = 0;
	ctx.nx = 0;
	ctx.nullt = false;
}

blake1_reset_512 :: proc(ctx : ^BLAKE1_512_CTX) {
	if ctx.is384 {
		ctx.h[0] = BLAKE1_INIT_0_384;
		ctx.h[1] = BLAKE1_INIT_1_384;
		ctx.h[2] = BLAKE1_INIT_2_384;
		ctx.h[3] = BLAKE1_INIT_3_384;
		ctx.h[4] = BLAKE1_INIT_4_384;
		ctx.h[5] = BLAKE1_INIT_5_384;
		ctx.h[6] = BLAKE1_INIT_6_384;
		ctx.h[7] = BLAKE1_INIT_7_384;
	} else {
		ctx.h[0] = BLAKE1_INIT_0_512;
		ctx.h[1] = BLAKE1_INIT_1_512;
		ctx.h[2] = BLAKE1_INIT_2_512;
		ctx.h[3] = BLAKE1_INIT_3_512;
		ctx.h[4] = BLAKE1_INIT_4_512;
		ctx.h[5] = BLAKE1_INIT_5_512;
		ctx.h[6] = BLAKE1_INIT_6_512;
		ctx.h[7] = BLAKE1_INIT_7_512;
	}
	ctx.t = 0;
	ctx.nx = 0;
	ctx.nullt = false;
}

blake1_write_256 :: proc(ctx : ^BLAKE1_256_CTX, p: []byte) {
	if ctx.nx > 0 {
		n := copy(ctx.x[ctx.nx:], p);
		ctx.nx += i32(n);
		if ctx.nx == BLAKE1_BLOCKSIZE_256 {
			blake1_block256(ctx, ctx.x[:]);
			ctx.nx = 0;
		}
		p = p[n:];
	}
	if len(p) >= BLAKE1_BLOCKSIZE_256 {
		n := len(p) &~ (BLAKE1_BLOCKSIZE_256 - 1);
		blake1_block256(ctx, p[:n]);
		p = p[n:];
	}
	if len(p) > 0 {
		n := copy(ctx.x[:], p);
		ctx.nx += i32(n);
	}
}

blake1_write_512 :: proc(ctx : ^BLAKE1_512_CTX, p: []byte) {
	if ctx.nx > 0 {
		n := copy(ctx.x[ctx.nx:], p);
		ctx.nx += i32(n);
		if ctx.nx == BLAKE1_BLOCKSIZE_512 {
			blake1_block512(ctx, ctx.x[:]);
			ctx.nx = 0;
		}
		p = p[n:];
	}
	if len(p) >= BLAKE1_BLOCKSIZE_512 {
		n := len(p) &~ (BLAKE1_BLOCKSIZE_512 - 1);
		blake1_block512(ctx, p[:n]);
		p = p[n:];
	}
	if len(p) > 0 {
		n := copy(ctx.x[:], p);
		ctx.nx += i32(n);
	}
}

blake1_checksum_256 :: proc(ctx: ^BLAKE1_256_CTX) -> [BLAKE1_SIZE_256]byte {
	
	nx := u64(ctx.nx);

	tmp : [65]byte;
	tmp[0] = 0x80;
	length := (u64(ctx.t) + nx) << 3;

	if nx == 55 {
		if ctx.is224 {
			blake1_writeAdditionalData_256(ctx, []byte{0x80});
		} else {
			blake1_writeAdditionalData_256(ctx, []byte{0x81});
		}
	} else {
		if nx < 55 {
			if nx == 0 {
				ctx.nullt = true;
			}
			blake1_writeAdditionalData_256(ctx, tmp[0 : 55 - nx]);
		} else { 
			blake1_writeAdditionalData_256(ctx, tmp[0 : 64 - nx]);
			blake1_writeAdditionalData_256(ctx, tmp[1:56]);
			ctx.nullt = true;
		}
		if ctx.is224 {
			blake1_writeAdditionalData_256(ctx, []byte{0x00});
		} else {
			blake1_writeAdditionalData_256(ctx, []byte{0x01});
		}
	}

	for i : u32 = 0; i < 8; i += 1 {
		tmp[i] = byte(length >> (56 - 8 * i));
	}
	blake1_writeAdditionalData_256(ctx, tmp[0:8]);
	h := ctx.h[:];
	if ctx.is224 do h = h[0:7];

	digest : [BLAKE1_SIZE_256]byte;

	cap : u32 = 8;
	if ctx.is224 do cap = 7;
	
	for i : u32 = 0; i < cap; i += 1 {
		digest[i * 4] = byte(h[i] >> 24);
		digest[i * 4 + 1] = byte(h[i] >> 16);
		digest[i * 4 + 2] = byte(h[i] >> 8);
		digest[i * 4 + 3] = byte(h[i]);
	}

	return digest;
}

blake1_checksum_512 :: proc(ctx: ^BLAKE1_512_CTX) -> [BLAKE1_SIZE_512]byte {
	
	nx := u64(ctx.nx);

	tmp : [129]byte;
	tmp[0] = 0x80;
	length := (ctx.t + nx) << 3;

	if nx == 111 {
		if ctx.is384 {
			blake1_writeAdditionalData_512(ctx, []byte{0x80});
		} else {
			blake1_writeAdditionalData_512(ctx, []byte{0x81});
		}
	} else {
		if nx < 111 {
			if nx == 0 {
				ctx.nullt = true;
			}
			blake1_writeAdditionalData_512(ctx, tmp[0 : 111 - nx]);
		} else { 
			blake1_writeAdditionalData_512(ctx, tmp[0 : 128 - nx]);
			blake1_writeAdditionalData_512(ctx, tmp[1:112]);
			ctx.nullt = true;
		}
		if ctx.is384 {
			blake1_writeAdditionalData_512(ctx, []byte{0x00});
		} else {
			blake1_writeAdditionalData_512(ctx, []byte{0x01});
		}
	}

	for i : u32 = 0; i < 8; i += 1 {
		tmp[i] = byte(length >> (120 - 8 * i));
	}
	blake1_writeAdditionalData_512(ctx, tmp[0:16]);
	h := ctx.h[:];
	if ctx.is384 do h = h[0:6];

	digest : [BLAKE1_SIZE_512]byte;

	cap : u32 = 8;
	if ctx.is384 do cap = 7;
	
	for i : u32 = 0; i < cap; i += 1 {
		digest[i*8] = byte(h[i] >> 56);
		digest[i*8+1] = byte(h[i] >> 48);
		digest[i*8+2] = byte(h[i] >> 40);
		digest[i*8+3] = byte(h[i] >> 32);
		digest[i*8+4] = byte(h[i] >> 24);
		digest[i*8+5] = byte(h[i] >> 16);
		digest[i*8+6] = byte(h[i] >> 8);
		digest[i*8+7] = byte(h[i]);
	}

	return digest;
}

blake1_writeAdditionalData_256 :: proc(ctx: ^BLAKE1_256_CTX, p: []byte) {
	ctx.t -= u32(len(p)) << 3;
	blake1_write_256(ctx, p);
}

blake1_writeAdditionalData_512 :: proc(ctx: ^BLAKE1_512_CTX, p: []byte) {
	ctx.t -= u64(len(p)) << 3;
	blake1_write_512(ctx, p);
}

blake1_224 :: proc(data: []byte) -> [BLAKE1_SIZE_224]byte {

    hash : [BLAKE1_SIZE_224]byte;
    ctx : BLAKE1_256_CTX;
    ctx.is224 = true;
    blake1_reset_256(&ctx);
	blake1_write_256(&ctx, data);
	tmp := blake1_checksum_256(&ctx);
	mem.copy(&hash, &tmp, BLAKE1_SIZE_224);

    return hash;
}

blake1_256 :: proc(data: []byte) -> [BLAKE1_SIZE_256]byte {

    hash : [BLAKE1_SIZE_256]byte;
    ctx : BLAKE1_256_CTX;
    ctx.is224 = false;
    blake1_reset_256(&ctx);
	blake1_write_256(&ctx, data);
	hash = blake1_checksum_256(&ctx);

    return hash;
}

blake1_384 :: proc(data: []byte) -> [BLAKE1_SIZE_384]byte {

    hash : [BLAKE1_SIZE_384]byte;
    ctx : BLAKE1_512_CTX;
    ctx.is384 = true;
    blake1_reset_512(&ctx);
	blake1_write_512(&ctx, data);
	tmp := blake1_checksum_512(&ctx);
	mem.copy(&hash, &tmp, BLAKE1_SIZE_384);

    return hash;
}

blake1_512 :: proc(data: []byte) -> [BLAKE1_SIZE_512]byte {

    hash : [BLAKE1_SIZE_512]byte;
    ctx : BLAKE1_512_CTX;
    ctx.is384 = false;
    blake1_reset_512(&ctx);
	blake1_write_512(&ctx, data);
	hash = blake1_checksum_512(&ctx);

    return hash;
}