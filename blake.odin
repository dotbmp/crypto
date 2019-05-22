package crypto

import "core:runtime"
import "core:mem"
import "core:fmt"

// @ref(zh): https://github.com/ouzklcn/blake

// BLAKE reference implemenation:
// @ref(bp): https://github.com/veorq/BLAKE


BLAKE_SIZE_224 :: 28;
BLAKE_SIZE_256 :: 32;
BLAKE_SIZE_384 :: 48;
BLAKE_SIZE_512 :: 64;
BLAKE_BLOCKSIZE_256 :: 64;
BLAKE_BLOCKSIZE_512 :: 128;

BLAKE_INIT_0_224 :: 0xc1059ed8;
BLAKE_INIT_1_224 :: 0x367cd507;
BLAKE_INIT_2_224 :: 0x3070dd17;
BLAKE_INIT_3_224 :: 0xf70e5939;
BLAKE_INIT_4_224 :: 0xffc00b31;
BLAKE_INIT_5_224 :: 0x68581511;
BLAKE_INIT_6_224 :: 0x64f98fa7;
BLAKE_INIT_7_224 :: 0xbefa4fa4;
BLAKE_INIT_0_256 :: 0x6a09e667;
BLAKE_INIT_1_256 :: 0xbb67ae85;
BLAKE_INIT_2_256 :: 0x3c6ef372;
BLAKE_INIT_3_256 :: 0xa54ff53a;
BLAKE_INIT_4_256 :: 0x510e527f;
BLAKE_INIT_5_256 :: 0x9b05688c;
BLAKE_INIT_6_256 :: 0x1f83d9ab;
BLAKE_INIT_7_256 :: 0x5be0cd19;
BLAKE_INIT_0_384 :: 0xcbbb9d5dc1059ed8;
BLAKE_INIT_1_384 :: 0x629a292a367cd507;
BLAKE_INIT_2_384 :: 0x9159015a3070dd17;
BLAKE_INIT_3_384 :: 0x152fecd8f70e5939;
BLAKE_INIT_4_384 :: 0x67332667ffc00b31;
BLAKE_INIT_5_384 :: 0x8eb44a8768581511;
BLAKE_INIT_6_384 :: 0xdb0c2e0d64f98fa7;
BLAKE_INIT_7_384 :: 0x47b5481dbefa4fa4;
BLAKE_INIT_0_512 :: 0x6a09e667f3bcc908;
BLAKE_INIT_1_512 :: 0xbb67ae8584caa73b;
BLAKE_INIT_2_512 :: 0x3c6ef372fe94f82b;
BLAKE_INIT_3_512 :: 0xa54ff53a5f1d36f1;
BLAKE_INIT_4_512 :: 0x510e527fade682d1;
BLAKE_INIT_5_512 :: 0x9b05688c2b3e6c1f;
BLAKE_INIT_6_512 :: 0x1f83d9abfb41bd6b;
BLAKE_INIT_7_512 :: 0x5be0cd19137e2179;


BLAKE_256 :: struct {
    h : [8]u32,
    s : [4]u32,
    t : u64,
    x : [64]byte,
    nx : int,
    is224 : bool,
    nullt : bool,
}

BLAKE_512 :: struct {
    h : [8]u64,
    s : [4]u64,
    t : u64,
    x : [128]byte,
    nx : int,
    is384 : bool,
    nullt : bool,
}

BLAKE_SIGMA := [?]int {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
	11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
	7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
	9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
	2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
	12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
	13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
	6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
	10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
};

BLAKE_PADDING := [?]byte {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

BLAKE_U256 := [16]u32 {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

BLAKE_U512 := [16]u64 {
	0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
	0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
	0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
	0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69
};

blake256_g :: inline proc "contextless" (a, b, c, d: u32, m: [16]u32, i, j: int) -> (u32, u32, u32, u32) #no_bounds_check {
	a += m[BLAKE_SIGMA[(i % 10) * 16 + (2 * j)]] ~ BLAKE_U256[BLAKE_SIGMA[(i % 10) * 16 + (2 * j + 1)]];
	a += b;
	d ~= a;
	d = d << (32 - 16) | d >> 16;
	c += d;
	b ~= c;
	b = b << (32 - 12) | b >> 12;
	a += m[BLAKE_SIGMA[(i % 10) * 16 + (2 * j + 1)]] ~ BLAKE_U256[BLAKE_SIGMA[(i % 10) * 16 + (2 * j)]];
	a += b;
	d ~= a;
	d = d << (32 - 8) | d >> 8;
	c += d;
	b ~= c;
	b = b << (32 - 7) | b >> 7;
	return a, b, c, d;
}

blake512_g :: inline proc "contextless" (a, b, c, d: u64, m: [16]u64, i, j: int) -> (u64, u64, u64, u64) #no_bounds_check {
	a += m[BLAKE_SIGMA[(i % 10) * 16 + (2 * j)]] ~ BLAKE_U512[BLAKE_SIGMA[(i % 10) * 16 + (2 * j + 1)]];
	a += b;
	d ~= a;
	d = d << (64 - 32) | d >> 32;
	c += d;
	b ~= c;
	b = b << (64 - 25) | b >> 25;
	a += m[BLAKE_SIGMA[(i % 10) * 16 + (2 * j + 1)]] ~ BLAKE_U512[BLAKE_SIGMA[(i % 10) * 16 + (2 * j)]];
	a += b;
	d ~= a;
	d = d << (64 - 16) | d >> 16;
	c += d;
	b ~= c;
	b = b << (64 - 11) | b >> 11;
	return a, b, c, d;
}

blake_block256 :: proc "contextless" (using ctx : ^BLAKE_256, p : []u8) #no_bounds_check {
	i, j : int = ---, ---;
	v, m : [16]u32 = ---, ---;
	
	for len(p) >= BLAKE_BLOCKSIZE_256 {
		v[0]  = h[0];
		v[1]  = h[1];
		v[2]  = h[2];
		v[3]  = h[3];
		v[4]  = h[4];
		v[5]  = h[5];
		v[6]  = h[6];
		v[7]  = h[7];
		v[8]  = s[0] ~ BLAKE_U256[0]; 
		v[9]  = s[1] ~ BLAKE_U256[1]; 
		v[10] = s[2] ~ BLAKE_U256[2]; 
		v[11] = s[3] ~ BLAKE_U256[3];
		v[12] = BLAKE_U256[4];
		v[13] = BLAKE_U256[5];
		v[14] = BLAKE_U256[6];
		v[15] = BLAKE_U256[7];

		t += 512;
		if !nullt {
			v[12] ~= u32(ctx.t);
			v[13] ~= u32(ctx.t);
			v[14] ~= u32(ctx.t >> 32);
			v[15] ~= u32(ctx.t >> 32);
		}

		for i, j = 0, 0; i < 16; i, j = i+1, j+4 {
			m[i] = u32((^u32be)(&p[j])^);
		}

		for i = 0; i < 14; i += 1 {
			v[0], v[4], v[8],  v[12] = blake256_g(v[0], v[4], v[8],  v[12], m, i, 0);
			v[1], v[5], v[9],  v[13] = blake256_g(v[1], v[5], v[9],  v[13], m, i, 1);
			v[2], v[6], v[10], v[14] = blake256_g(v[2], v[6], v[10], v[14], m, i, 2);
			v[3], v[7], v[11], v[15] = blake256_g(v[3], v[7], v[11], v[15], m, i, 3);
			v[0], v[5], v[10], v[15] = blake256_g(v[0], v[5], v[10], v[15], m, i, 4);
			v[1], v[6], v[11], v[12] = blake256_g(v[1], v[6], v[11], v[12], m, i, 5);
			v[2], v[7], v[8],  v[13] = blake256_g(v[2], v[7], v[8],  v[13], m, i, 6);
			v[3], v[4], v[9],  v[14] = blake256_g(v[3], v[4], v[9],  v[14], m, i, 7);
		}

		for i = 0; i < 8; i += 1 {
			h[i] ~= s[i % 4] ~ v[i] ~ v[i + 8];
		}
		p = p[BLAKE_BLOCKSIZE_256:];
	}
}

blake512_compress :: proc "contextless" (using ctx : ^BLAKE_512, p : []u8) #no_bounds_check {
	i, j : int = ---, ---;
	v, m : [16]u64 = ---, ---;

	for len(p) >= BLAKE_BLOCKSIZE_512 {
		v[0]  = h[0];
		v[1]  = h[1];
		v[2]  = h[2];
		v[3]  = h[3];
		v[4]  = h[4];
		v[5]  = h[5];
		v[6]  = h[6];
		v[7]  = h[7];
		v[8]  = s[0] ~ BLAKE_U512[0]; 
		v[9]  = s[1] ~ BLAKE_U512[1]; 
		v[10] = s[2] ~ BLAKE_U512[2]; 
		v[11] = s[3] ~ BLAKE_U512[3];
		v[12] = BLAKE_U512[4];
		v[13] = BLAKE_U512[5];
		v[14] = BLAKE_U512[6];
		v[15] = BLAKE_U512[7];

		t += 1024;
		if !nullt {
			v[12] ~= t;
			v[13] ~= t;
			v[14] ~= 0;
			v[15] ~= 0;
		}

		for i, j = 0, 0; i < 16; i, j = i+1, j+8 {
			m[i] = u64((^u64be)(&p[j])^);
		}

		for i = 0; i < 16; i += 1 {
			v[0], v[4], v[8],  v[12] = blake512_g(v[0], v[4], v[8],  v[12], m, i, 0);
			v[1], v[5], v[9],  v[13] = blake512_g(v[1], v[5], v[9],  v[13], m, i, 1);
			v[2], v[6], v[10], v[14] = blake512_g(v[2], v[6], v[10], v[14], m, i, 2);
			v[3], v[7], v[11], v[15] = blake512_g(v[3], v[7], v[11], v[15], m, i, 3);
			v[0], v[5], v[10], v[15] = blake512_g(v[0], v[5], v[10], v[15], m, i, 4);
			v[1], v[6], v[11], v[12] = blake512_g(v[1], v[6], v[11], v[12], m, i, 5);
			v[2], v[7], v[8],  v[13] = blake512_g(v[2], v[7], v[8],  v[13], m, i, 6);
			v[3], v[4], v[9],  v[14] = blake512_g(v[3], v[4], v[9],  v[14], m, i, 7);
		}

		for i = 0; i < 8; i += 1 {
			h[i] ~= s[i % 4] ~ v[i] ~ v[i + 8];
		}
		p = p[BLAKE_BLOCKSIZE_512:];
	}
}

blake_reset_256 :: proc "contextless" (ctx : ^BLAKE_256) #no_bounds_check {
    if ctx.is224 {
		ctx.h[0] = BLAKE_INIT_0_224;
		ctx.h[1] = BLAKE_INIT_1_224;
		ctx.h[2] = BLAKE_INIT_2_224;
		ctx.h[3] = BLAKE_INIT_3_224;
		ctx.h[4] = BLAKE_INIT_4_224;
		ctx.h[5] = BLAKE_INIT_5_224;
		ctx.h[6] = BLAKE_INIT_6_224;
		ctx.h[7] = BLAKE_INIT_7_224;
	} else {
		ctx.h[0] = BLAKE_INIT_0_256;
		ctx.h[1] = BLAKE_INIT_1_256;
		ctx.h[2] = BLAKE_INIT_2_256;
		ctx.h[3] = BLAKE_INIT_3_256;
		ctx.h[4] = BLAKE_INIT_4_256;
		ctx.h[5] = BLAKE_INIT_5_256;
		ctx.h[6] = BLAKE_INIT_6_256;
		ctx.h[7] = BLAKE_INIT_7_256;
	}
	ctx.t = 0;
	ctx.nx = 0;
	ctx.nullt = false;
}

blake512_reset :: proc "contextless" (ctx : ^BLAKE_512) #no_bounds_check {
	if ctx.is384 {
		ctx.h[0] = BLAKE_INIT_0_384;
		ctx.h[1] = BLAKE_INIT_1_384;
		ctx.h[2] = BLAKE_INIT_2_384;
		ctx.h[3] = BLAKE_INIT_3_384;
		ctx.h[4] = BLAKE_INIT_4_384;
		ctx.h[5] = BLAKE_INIT_5_384;
		ctx.h[6] = BLAKE_INIT_6_384;
		ctx.h[7] = BLAKE_INIT_7_384;
	} else {
		ctx.h[0] = BLAKE_INIT_0_512;
		ctx.h[1] = BLAKE_INIT_1_512;
		ctx.h[2] = BLAKE_INIT_2_512;
		ctx.h[3] = BLAKE_INIT_3_512;
		ctx.h[4] = BLAKE_INIT_4_512;
		ctx.h[5] = BLAKE_INIT_5_512;
		ctx.h[6] = BLAKE_INIT_6_512;
		ctx.h[7] = BLAKE_INIT_7_512;
	}
	ctx.t = 0;
	ctx.nx = 0;
	ctx.nullt = false;
}

blake_write_256 :: proc "contextless" (ctx : ^BLAKE_256, p: []byte) #no_bounds_check {
	if ctx.nx > 0 {
		n := copy(ctx.x[ctx.nx:], p);
		ctx.nx += n;
		if ctx.nx == BLAKE_BLOCKSIZE_256 {
			blake_block256(ctx, ctx.x[:]);
			ctx.nx = 0;
		}
		p = p[n:];
	}
	if len(p) >= BLAKE_BLOCKSIZE_256 {
		n := len(p) &~ (BLAKE_BLOCKSIZE_256 - 1);
		blake_block256(ctx, p[:n]);
		p = p[n:];
	}
	if len(p) > 0 {
		ctx.nx = copy(ctx.x[:], p);
	}
}

blake512_write :: proc "contextless" (ctx : ^BLAKE_512, p: []byte) #no_bounds_check {
	if ctx.nx > 0 {
		n := copy(ctx.x[ctx.nx:], p);
		ctx.nx += n;
		if ctx.nx == BLAKE_BLOCKSIZE_512 {
			blake512_compress(ctx, ctx.x[:]);
			ctx.nx = 0;
		}
		p = p[n:];
	}
	if len(p) >= BLAKE_BLOCKSIZE_512 {
		n := len(p) &~ (BLAKE_BLOCKSIZE_512 - 1);
		blake512_compress(ctx, p[:n]);
		p = p[n:];
	}
	if len(p) > 0 {
		ctx.nx = copy(ctx.x[:], p);
	}
}

blake_checksum_256 :: proc "contextless" (ctx: ^BLAKE_256) -> [BLAKE_SIZE_256]byte #no_bounds_check {
	
	nx := u64(ctx.nx);

	tmp : [65]byte;
	tmp[0] = 0x80;
	length := (ctx.t + nx) << 3;

	if nx == 55 {
		if ctx.is224 {
			blake_writeAdditionalData_256(ctx, {0x80});
		} else {
			blake_writeAdditionalData_256(ctx, {0x81});
		}
	} else {
		if nx < 55 {
			if nx == 0 {
				ctx.nullt = true;
			}
			blake_writeAdditionalData_256(ctx, tmp[0 : 55 - nx]);
		} else { 
			blake_writeAdditionalData_256(ctx, tmp[0 : 64 - nx]);
			blake_writeAdditionalData_256(ctx, tmp[1:56]);
			ctx.nullt = true;
		}
		if ctx.is224 {
			blake_writeAdditionalData_256(ctx, {0x00});
		} else {
			blake_writeAdditionalData_256(ctx, {0x01});
		}
	}

	for i : uint = 0; i < 8; i += 1 {
		tmp[i] = (56 - 8 * i) < 64 ? byte(length >> (56 - 8 * i)) : 0; // @todo(bp): remove this hideous fucking monstrosity once the compiler is fixed
	}
	blake_writeAdditionalData_256(ctx, tmp[0:8]);

	assert(ctx.nx == 0); // @note(bp): remove after thorough testing?

	h := ctx.h[:];
	if ctx.is224 do h = h[0:7];

	digest : [BLAKE_SIZE_256]byte;
	
	for s, i in h {
		digest[i * 4]     = byte(s >> 24);
		digest[i * 4 + 1] = byte(s >> 16);
		digest[i * 4 + 2] = byte(s >> 8);
		digest[i * 4 + 3] = byte(s);
	}

	return digest;
}

blake512_final :: proc "contextless" (ctx: ^BLAKE_512) -> [BLAKE_SIZE_512]byte #no_bounds_check {
	
	nx := u64(ctx.nx);

	tmp : [129]byte;
	tmp[0] = 0x80;
	length := (ctx.t + nx) << 3;

	if nx == 111 {
		if ctx.is384 {
			blake_writeAdditionalData_512(ctx, {0x80});
		} else {
			blake_writeAdditionalData_512(ctx, {0x81});
		}
	} else {
		if nx < 111 {
			if nx == 0 {
				ctx.nullt = true;
			}
			blake_writeAdditionalData_512(ctx, tmp[0 : 111 - nx]);
		} else { 
			blake_writeAdditionalData_512(ctx, tmp[0 : 128 - nx]);
			blake_writeAdditionalData_512(ctx, tmp[1:112]);
			ctx.nullt = true;
		}
		if ctx.is384 {
			blake_writeAdditionalData_512(ctx, {0x00});
		} else {
			blake_writeAdditionalData_512(ctx, {0x01});
		}
	}

	for i : uint = 0; i < 16; i += 1 {
		tmp[i] = (120 - 8 * i) < 64 ? byte(length >> (120 - 8 * i)) : 0; // @todo(bp): remove this hideous fucking monstrosity once the compiler is fixed
	}
	blake_writeAdditionalData_512(ctx, tmp[0:16]);

	assert(ctx.nx == 0); // @note(bp): remove after thorough testing?

	h := ctx.h[:];
	if ctx.is384 do h = h[0:6];

	digest : [BLAKE_SIZE_512]byte;

	for s, i in h {
		digest[i * 8]     = byte(s >> 56);
		digest[i * 8 + 1] = byte(s >> 48);
		digest[i * 8 + 2] = byte(s >> 40);
		digest[i * 8 + 3] = byte(s >> 32);
		digest[i * 8 + 4] = byte(s >> 24);
		digest[i * 8 + 5] = byte(s >> 16);
		digest[i * 8 + 6] = byte(s >> 8);
		digest[i * 8 + 7] = byte(s);
	}

	return digest;
}

blake_writeAdditionalData_256 :: proc "contextless" (ctx: ^BLAKE_256, p: []byte) {
	ctx.t -= u64(len(p)) << 3;
	blake_write_256(ctx, p);
}

blake_writeAdditionalData_512 :: proc "contextless" (ctx: ^BLAKE_512, p: []byte) {
	ctx.t -= u64(len(p)) << 3;
	blake512_write(ctx, p);
}

blake224 :: proc "contextless" (data: []byte) -> [BLAKE_SIZE_224]byte #no_bounds_check {
	hash : [BLAKE_SIZE_224]byte = ---;
    ctx : BLAKE_256;
    ctx.is224 = true;
    blake_reset_256(&ctx);
	blake_write_256(&ctx, data);
	tmp := blake_checksum_256(&ctx);
	copy(hash[:], tmp[:BLAKE_SIZE_224]);

    return hash;
}

blake256 :: proc "contextless" (data: []byte) -> [BLAKE_SIZE_256]byte #no_bounds_check {

	hash : [BLAKE_SIZE_256]byte = ---;
    ctx : BLAKE_256;
    blake_reset_256(&ctx);
	blake_write_256(&ctx, data);
	hash = blake_checksum_256(&ctx);

    return hash;
}

blake384 :: proc "contextless" (data: []byte) -> [BLAKE_SIZE_384]byte #no_bounds_check {

	hash : [BLAKE_SIZE_384]byte = ---;
    ctx : BLAKE_512;
    ctx.is384 = true;
    blake512_reset(&ctx);
	blake512_write(&ctx, data);
	tmp := blake512_final(&ctx);
	copy(hash[:], tmp[:BLAKE_SIZE_384]);

    return hash;
}

blake512 :: proc "contextless" (data: []byte) -> [BLAKE_SIZE_512]byte #no_bounds_check {

	hash : [BLAKE_SIZE_512]byte = ---;
    ctx : BLAKE_512;
    blake512_reset(&ctx);
	blake512_write(&ctx, data);
	hash = blake512_final(&ctx);

    return hash;
}
