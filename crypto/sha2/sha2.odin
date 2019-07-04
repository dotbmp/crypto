package sha2

import "core:mem"

SHA224_BLOCK_SIZE :: 28;
SHA256_BLOCK_SIZE :: 32;
SHA384_BLOCK_SIZE :: 48;
SHA512_BLOCK_SIZE :: 64;

SHA_256 :: struct {
    data: [64]u8,
    state: [8]u32,
    bitlen: u64,
    datalen: u32,
	is224: bool,
}

SHA_512 :: struct {
    data: [128]u8,
    state: [8]u64,
    bitlen: u64,
    datalen: u32,
	is384: bool,
}

SHA256_CH :: inline proc "contextless"(x, y, z: u32) -> u32 {
    return (((x) & (y)) ~ (~(x) & (z)));
}

SHA256_MAJ :: inline proc "contextless"(x, y, z: u32) -> u32 {
    return (((x) & (y)) ~ ((x) & (z)) ~ ((y) & (z)));
}

SHA512_CH :: inline proc "contextless"(x, y, z: u64) -> u64 {
    return (((x) & (y)) ~ (~(x) & (z)));
}

SHA512_MAJ :: inline proc "contextless"(x, y, z: u64) -> u64 {
    return (((x) & (y)) ~ ((x) & (z)) ~ ((y) & (z)));
}

SHA256_EP0 :: inline proc "contextless"(x: u32) -> u32 {
    return (ROTR32(x, 6) ~ ROTR32(x, 11) ~ ROTR32(x, 25));
}

SHA256_EP1 :: inline proc "contextless"(x: u32) -> u32 {
    return (ROTR32(x, 2) ~ ROTR32(x, 13) ~ ROTR32(x, 22));
}

SHA256_SIG0 :: inline proc "contextless"(x: u32) -> u32 {
    return (ROTR32(x, 7) ~ ROTR32(x, 18) ~ ((x) >> 3));
}

SHA256_SIG1 :: inline proc "contextless"(x: u32) -> u32 {
    return (ROTR32(x, 17) ~ ROTR32(x, 19) ~ ((x) >> 10));
}

SHA512_EP0 :: inline proc "contextless"(x: u64) -> u64 {
    return (ROTR64(x, 28) ~ ROTR64(x, 34) ~ ROTR64(x, 39));
}

SHA512_EP1 :: inline proc "contextless"(x: u64) -> u64 {
    return (ROTR64(x, 14) ~ ROTR64(x, 18) ~ ROTR64(x, 41));
}

SHA512_SIG0 :: inline proc "contextless"(x: u64) -> u64 {
    return (ROTR64(x, 1) ~ ROTR64(x, 8) ~ ((x) >> 7));
}

SHA512_SIG1 :: inline proc "contextless"(x: u64) -> u64 {
    return (ROTR64(x, 19) ~ ROTR64(x, 61) ~ ((x) >> 6));
}

SHA256_K := [64]u32 {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

SHA512_K := [80]u64 {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

sha256_transform :: proc(ctx: ^SHA_256, data: []byte) {
    a, b, c, d, e, f, g, h, i, j, t1, t2 : u32; 
    m : [64]u32;

    for i, j = 0, 0; i < 16; i, j = i + 1, j + 4 {
		m[i] = u32(data[j]) << 24 | u32(data[j + 1]) << 16 | u32(data[j + 2]) << 8 | u32(data[j + 3]);
    }
	for i < 64 {
        m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];
		i += 1;
    }

    a = ctx.state[0];
	b = ctx.state[1];
	c = ctx.state[2];
	d = ctx.state[3];
	e = ctx.state[4];
	f = ctx.state[5];
	g = ctx.state[6];
	h = ctx.state[7];

    for i = 0; i < 64; i += 1 {
		t1 = h + SHA256_EP0(e) + SHA256_CH(e, f, g) + SHA256_K[i] + m[i];
		t2 = SHA256_EP1(a) + SHA256_MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx.state[0] += a;
	ctx.state[1] += b;
	ctx.state[2] += c;
	ctx.state[3] += d;
	ctx.state[4] += e;
	ctx.state[5] += f;
	ctx.state[6] += g;
	ctx.state[7] += h;
}

sha512_transform :: proc(ctx: ^SHA_512, data: []byte) {
    a, b, c, d, e, f, g, h, i, j, t1, t2 : u64; 
    m : [80]u64;

    for i, j = 0, 0; i < 16; i, j = i + 1, j + 8 {
		m[i] = u64(data[j]) << 56 | u64(data[j + 1]) << 48 | u64(data[j + 2]) << 40 | u64(data[j + 3]) << 32 | u64(data[j + 4]) << 24 | u64(data[j + 5]) << 16 | u64(data[j + 6]) << 8 | u64(data[j + 7]);
    }
	for i < 80 {
        m[i] = SHA512_SIG1(m[i - 2]) + m[i - 7] + SHA512_SIG0(m[i - 15]) + m[i - 16];
		i += 1;
    }

    a = ctx.state[0];
	b = ctx.state[1];
	c = ctx.state[2];
	d = ctx.state[3];
	e = ctx.state[4];
	f = ctx.state[5];
	g = ctx.state[6];
	h = ctx.state[7];

    for i = 0; i < 80; i += 1 {
		t1 = h + SHA512_EP1(e) + SHA512_CH(e, f, g) + SHA512_K[i] + m[i];
		t2 = SHA512_EP0(a) + SHA512_MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx.state[0] += a;
	ctx.state[1] += b;
	ctx.state[2] += c;
	ctx.state[3] += d;
	ctx.state[4] += e;
	ctx.state[5] += f;
	ctx.state[6] += g;
	ctx.state[7] += h;
}

sha2_init :: proc(ctx: ^$T) {
    ctx.datalen, ctx.bitlen = 0, 0;
	when T == SHA_256 {
		if ctx.is224 {
			ctx.state[0] = 0xc1059ed8;
			ctx.state[1] = 0x367cd507;
			ctx.state[2] = 0x3070dd17;
			ctx.state[3] = 0xf70e5939;
			ctx.state[4] = 0xffc00b31;
			ctx.state[5] = 0x68581511;
			ctx.state[6] = 0x64f98fa7;
			ctx.state[7] = 0xbefa4fa4;
		} else {
			ctx.state[0] = 0x6a09e667;
			ctx.state[1] = 0xbb67ae85;
			ctx.state[2] = 0x3c6ef372;
			ctx.state[3] = 0xa54ff53a;
			ctx.state[4] = 0x510e527f;
			ctx.state[5] = 0x9b05688c;
			ctx.state[6] = 0x1f83d9ab;
			ctx.state[7] = 0x5be0cd19;
		}
	} else when T == SHA_512 {
		if ctx.is384 {
			ctx.state[0] = 0xcbbb9d5dc1059ed8;
			ctx.state[1] = 0x629a292a367cd507;
			ctx.state[2] = 0x9159015a3070dd17;
			ctx.state[3] = 0x152fecd8f70e5939;
			ctx.state[4] = 0x67332667ffc00b31;
			ctx.state[5] = 0x8eb44a8768581511;
			ctx.state[6] = 0xdb0c2e0d64f98fa7;
			ctx.state[7] = 0x47b5481dbefa4fa4;
		} else {
			ctx.state[0] = 0x6a09e667f3bcc908;
			ctx.state[1] = 0xbb67ae8584caa73b;
			ctx.state[2] = 0x3c6ef372fe94f82b;
			ctx.state[3] = 0xa54ff53a5f1d36f1;
			ctx.state[4] = 0x510e527fade682d1;
			ctx.state[5] = 0x9b05688c2b3e6c1f;
			ctx.state[6] = 0x1f83d9abfb41bd6b;
			ctx.state[7] = 0x5be0cd19137e2179;
		}
	}
}

sha2_update :: proc(ctx: ^$T, data: []byte) {
    for i := 0; i < len(data); i += 1 {
		ctx.data[ctx.datalen] = data[i];
		ctx.datalen += 1;
		if ctx.datalen == 64 {
			when T == SHA_256 {
				sha256_transform(ctx, ctx.data[:]);
				ctx.bitlen += 512;
			} else when T == SHA_512{
				sha512_transform(ctx, ctx.data[:]);
				ctx.bitlen += 1024;
			}
			ctx.datalen = 0;
		}
	}
}

sha2_final :: proc(ctx: ^$T, hash: []byte, block_size: int) {
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
		for i < 64 {
            ctx.data[i] = 0x00;
            i += 1;
        }
		when T == SHA_256 do sha256_transform(ctx, ctx.data[:]);
		else when T == SHA_512 do sha512_transform(ctx, ctx.data[:]);
		mem.set(&ctx.data, 0, 56);
	}

	ctx.bitlen += u64(ctx.datalen) * 8;
	ctx.data[63] = u8(ctx.bitlen);
	ctx.data[62] = u8(ctx.bitlen) >> 8;
	ctx.data[61] = u8(ctx.bitlen) >> 16;
	ctx.data[60] = u8(ctx.bitlen) >> 24;
	ctx.data[59] = u8(ctx.bitlen) >> 32;
	ctx.data[58] = u8(ctx.bitlen) >> 40;
	ctx.data[57] = u8(ctx.bitlen) >> 48;
	ctx.data[56] = u8(ctx.bitlen) >> 56;

	when T == SHA_256 {
		sha256_transform(ctx, ctx.data[:]);
		for i = 0; i < 4; i += 1 {
			hash[i]      = u8(ctx.state[0] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 4]  = u8(ctx.state[1] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 8]  = u8(ctx.state[2] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 12] = u8(ctx.state[3] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 16] = u8(ctx.state[4] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 20] = u8(ctx.state[5] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 24] = u8(ctx.state[6] >> (24 - i * 8)) & 0x000000ff;
			if !ctx.is224 do hash[i + 28] = u8(ctx.state[7] >> (24 - i * 8)) & 0x000000ff;
		}
	} else when T == SHA_512 {
		sha512_transform(ctx, ctx.data[:]);
		for i = 0; i < 8; i += 1 {
			hash[i]      = u8(ctx.state[0] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 8]  = u8(ctx.state[1] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 16] = u8(ctx.state[2] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 24] = u8(ctx.state[3] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 32] = u8(ctx.state[4] >> (24 - i * 8)) & 0x000000ff;
			hash[i + 40] = u8(ctx.state[5] >> (24 - i * 8)) & 0x000000ff;
			if !ctx.is384 {
				hash[i + 48] = u8(ctx.state[6] >> (24 - i * 8)) & 0x000000ff;
				hash[i + 56] = u8(ctx.state[7] >> (24 - i * 8)) & 0x000000ff;
			}
		}
	}
}

hash_224 :: proc "contextless" (data: []byte) -> [SHA224_BLOCK_SIZE]byte #no_bounds_check {
    hash : [SHA224_BLOCK_SIZE]byte;
    ctx : SHA_256;
	ctx.is224 = true;
    sha2_init(&ctx);
	sha2_update(&ctx, data);
	sha2_final(&ctx, hash[:], SHA224_BLOCK_SIZE);

    return hash;
}

hash_256 :: proc "contextless" (data: []byte) -> [SHA256_BLOCK_SIZE]byte #no_bounds_check {
    hash : [SHA256_BLOCK_SIZE]byte;
    ctx : SHA_256;

    sha2_init(&ctx);
	sha2_update(&ctx, data);
	sha2_final(&ctx, hash[:], SHA256_BLOCK_SIZE);

    return hash;
}

hash_384 :: proc "contextless" (data: []byte) -> [SHA384_BLOCK_SIZE]byte #no_bounds_check {
    hash : [SHA384_BLOCK_SIZE]byte;
    ctx : SHA_512;
	ctx.is384 = true;
    sha2_init(&ctx);
	sha2_update(&ctx, data);
	sha2_final(&ctx, hash[:], SHA384_BLOCK_SIZE);

    return hash;
}

hash_512 :: proc "contextless" (data: []byte) -> [SHA512_BLOCK_SIZE]byte #no_bounds_check {
    hash : [SHA512_BLOCK_SIZE]byte;
    ctx : SHA_512;

    sha2_init(&ctx);
	sha2_update(&ctx, data);
	sha2_final(&ctx, hash[:], SHA512_BLOCK_SIZE);

    return hash;
}