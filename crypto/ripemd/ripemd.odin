package ripemd

import "../util"

// @ref(zh): https://github.com/maoxs2/go-ripemd <- Has a lot of errors and mixups with 256 and 320
// Fixed them using info from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html#Outline

RIPEMD_128_SIZE :: 16;
RIPEMD_128_BLOCK_SIZE :: 64;
RIPEMD_160_SIZE :: 20;
RIPEMD_160_BLOCK_SIZE :: 64;
RIPEMD_256_SIZE :: 32;
RIPEMD_256_BLOCK_SIZE :: 64;
RIPEMD_320_SIZE :: 40;
RIPEMD_320_BLOCK_SIZE :: 64;

RIPEMD_S0 :: 0x67452301;
RIPEMD_S1 :: 0xefcdab89;
RIPEMD_S2 :: 0x98badcfe;
RIPEMD_S3 :: 0x10325476;
RIPEMD_S4 :: 0xc3d2e1f0;
RIPEMD_S5 :: 0x76543210;
RIPEMD_S6 :: 0xfedcba98;
RIPEMD_S7 :: 0x89abcdef;
RIPEMD_S8 :: 0x01234567;
RIPEMD_S9 :: 0x3c2d1e0f;

RIPEMD_128_N0 := [64]uint{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
};
RIPEMD_128_R0 := [64]uint{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
};
RIPEMD_128_N1 := [64]uint{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
};
RIPEMD_128_R1 := [64]uint{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
};
RIPEMD_160_N0 := [80]uint{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
};
RIPEMD_160_R0 := [80]uint{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
};
RIPEMD_160_N1 := [80]uint{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
};
RIPEMD_160_R1 := [80]uint{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
};

RIPEMD_128 :: struct {
	s : [4]u32,
	x : [RIPEMD_128_BLOCK_SIZE]byte,
	nx : int,
	tc : u64,
}

RIPEMD_160 :: struct {
	s : [5]u32,
	x : [RIPEMD_160_BLOCK_SIZE]byte,
	nx : int,
	tc : u64,
}

RIPEMD_256 :: struct {
	s : [8]u32,
	x : [RIPEMD_256_BLOCK_SIZE]byte,
	nx : int,
	tc : u64,
}

RIPEMD_320 :: struct {
	s : [10]u32,
	x : [RIPEMD_320_BLOCK_SIZE]byte,
	nx : int,
	tc : u64,
}

ripemd_reset :: proc(ctx: ^$T) {
    ctx.nx = 0;
	ctx.tc = 0;
    when T == RIPEMD_128 {
        ctx.s[0], ctx.s[1], ctx.s[2], ctx.s[3] = RIPEMD_S0, RIPEMD_S1, RIPEMD_S2, RIPEMD_S3;
    } else when T == RIPEMD_160 {
        ctx.s[0], ctx.s[1], ctx.s[2], ctx.s[3], ctx.s[4] = RIPEMD_S0, RIPEMD_S1, RIPEMD_S2, RIPEMD_S3, RIPEMD_S4;
    } else when T == RIPEMD_256 {
        ctx.s[0], ctx.s[1], ctx.s[2], ctx.s[3] = RIPEMD_S0, RIPEMD_S1, RIPEMD_S2, RIPEMD_S3;
        ctx.s[4], ctx.s[5], ctx.s[6], ctx.s[7] = RIPEMD_S5, RIPEMD_S6, RIPEMD_S7, RIPEMD_S8;
    } else when T == RIPEMD_320 {
        ctx.s[0], ctx.s[1], ctx.s[2], ctx.s[3], ctx.s[4] = RIPEMD_S0, RIPEMD_S1, RIPEMD_S2, RIPEMD_S3, RIPEMD_S4;
        ctx.s[5], ctx.s[6], ctx.s[7], ctx.s[8], ctx.s[9] = RIPEMD_S5, RIPEMD_S6, RIPEMD_S7, RIPEMD_S8, RIPEMD_S9;
    }
}

ripemd_block :: #force_inline proc (ctx: ^$T, p: []byte) -> int {
    when T      == RIPEMD_128 do return ripemd_128_block(ctx, p);
    else when T == RIPEMD_160 do return ripemd_160_block(ctx, p);
    else when T == RIPEMD_256 do return ripemd_256_block(ctx, p);
    else when T == RIPEMD_320 do return ripemd_320_block(ctx, p);
    else do return 0;
}

ripemd_128_block :: proc(ctx: ^$T, p: []byte) -> int {
	n := 0;
	x : [16]u32 = ---;
	alpha : u32 = ---;
	p := p;
	for len(p) >= RIPEMD_128_BLOCK_SIZE {
		a, b, c, d := ctx.s[0], ctx.s[1], ctx.s[2], ctx.s[3];
		aa, bb, cc, dd := a, b, c, d;
		for i,j := 0, 0; i < 16; i, j = i+1, j+4 {
			x[i] = u32(p[j]) | u32(p[j+1])<<8 | u32(p[j+2])<<16 | u32(p[j+3])<<24;
		}
		i := 0;
		for i < 16 {
			alpha = a + (b ~ c ~ d) + x[RIPEMD_128_N0[i]];
			s := int(RIPEMD_128_R0[i]);
			alpha = util.ROTL32(alpha, s);
			a, b, c, d = d, alpha, b, c;
			alpha = aa + (bb & dd | cc &~ dd) + x[RIPEMD_128_N1[i]] + 0x50a28be6;
			s = int(RIPEMD_128_R1[i]);
			alpha = util.ROTL32(alpha, s);
			aa, bb, cc, dd= dd, alpha, bb, cc;
			i += 1;
		}
		for i < 32 {
			alpha = a + (d ~ (b & (c~d))) + x[RIPEMD_128_N0[i]] + 0x5a827999;
			s := int(RIPEMD_128_R0[i]);
			alpha = util.ROTL32(alpha, s);
			a, b, c, d = d, alpha, b, c;
			alpha = aa + (dd ~ (bb | ~cc)) + x[RIPEMD_128_N1[i]] + 0x5c4dd124;
			s = int(RIPEMD_128_R1[i]);
			alpha = util.ROTL32(alpha, s);
			aa, bb, cc, dd = dd, alpha, bb, cc;
			i += 1;
		}
		for i < 48 {
			alpha = a + (d ~ (b | ~c)) + x[RIPEMD_128_N0[i]] + 0x6ed9eba1;
			s := int(RIPEMD_128_R0[i]);
			alpha = util.ROTL32(alpha, s);
			a, b, c, d = d, alpha, b, c;
			alpha = aa + (dd ~ (bb & (cc~dd))) + x[RIPEMD_128_N1[i]] + 0x6d703ef3;
			s = int(RIPEMD_128_R1[i]);
			alpha = util.ROTL32(alpha, s);
			aa, bb, cc, dd = dd, alpha, bb, cc;
			i += 1;
		}
		for i < 64 {
			alpha = a + (c ~ (d & (b~c))) + x[RIPEMD_128_N0[i]] + 0x8f1bbcdc;
			s := int(RIPEMD_128_R0[i]);
			alpha = util.ROTL32(alpha, s);
			a, b, c, d = d, alpha, b, c;
			alpha = aa + (bb ~ cc ~ dd) + x[RIPEMD_128_N1[i]];
			s = int(RIPEMD_128_R1[i]);
			alpha = util.ROTL32(alpha, s);
			aa, bb, cc, dd = dd, alpha, bb, cc;
			i += 1;
		}
		c = ctx.s[1] + c + dd;
		ctx.s[1] = ctx.s[2] + d + aa;
		ctx.s[2] = ctx.s[3] + a + bb;
		ctx.s[3] = ctx.s[0] + b + cc;
		ctx.s[0] = c;
		p = p[RIPEMD_128_BLOCK_SIZE:];
		n += RIPEMD_128_BLOCK_SIZE;
	}
	return n;
}

ripemd_160_block :: proc(ctx: ^$T, p: []byte) -> int {
    n := 0;
	x : [16]u32 = ---;
	alpha, beta : u32 = ---, ---;
	p := p;
	for len(p) >= RIPEMD_160_BLOCK_SIZE {
		a, b, c, d, e := ctx.s[0], ctx.s[1], ctx.s[2], ctx.s[3], ctx.s[4];
		aa, bb, cc, dd, ee := a, b, c, d, e;
		for i,j := 0, 0; i < 16; i, j = i+1, j+4 {
			x[i] = u32(p[j]) | u32(p[j+1])<<8 | u32(p[j+2])<<16 | u32(p[j+3])<<24;
		}
		i := 0;
		for i < 16 {
			alpha = a + (b ~ c ~ d) + x[RIPEMD_160_N0[i]];
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb ~ (cc | ~dd)) + x[RIPEMD_160_N1[i]] + 0x50a28be6;
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		for i < 32 {
			alpha = a + (b&c | ~b&d) + x[RIPEMD_160_N0[i]] + 0x5a827999;
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb&dd | cc&~dd) + x[RIPEMD_160_N1[i]] + 0x5c4dd124;
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		for i < 48 {
			alpha = a + (b | ~c ~ d) + x[RIPEMD_160_N0[i]] + 0x6ed9eba1;
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb | ~cc ~ dd) + x[RIPEMD_160_N1[i]] + 0x6d703ef3;
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		for i < 64 {
			alpha = a + (b&d | c&~d) + x[RIPEMD_160_N0[i]] + 0x8f1bbcdc;
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb&cc | ~bb&dd) + x[RIPEMD_160_N1[i]] + 0x7a6d76e9;
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		for i < 80 {
			alpha = a + (b ~ (c | ~d)) + x[RIPEMD_160_N0[i]] + 0xa953fd4e;
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb ~ cc ~ dd) + x[RIPEMD_160_N1[i]];
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		dd += c + ctx.s[1];
		ctx.s[1] = ctx.s[2] + d + ee;
		ctx.s[2] = ctx.s[3] + e + aa;
		ctx.s[3] = ctx.s[4] + a + bb;
		ctx.s[4] = ctx.s[0] + b + cc;
		ctx.s[0] = dd;
		p = p[RIPEMD_160_BLOCK_SIZE:];
		n += RIPEMD_160_BLOCK_SIZE;
	}
	return n;
}

ripemd_256_block :: proc(ctx: ^$T, p: []byte) -> int {
	n := 0;
	x : [16]u32 = ---;
	alpha : u32 = ---;
	p := p;
	for len(p) >= RIPEMD_256_BLOCK_SIZE {
		a, b, c, d := ctx.s[0], ctx.s[1], ctx.s[2], ctx.s[3];
		aa, bb, cc, dd := ctx.s[4], ctx.s[5], ctx.s[6], ctx.s[7];
		for i,j := 0, 0; i < 16; i, j = i+1, j+4 {
			x[i] = u32(p[j]) | u32(p[j+1])<<8 | u32(p[j+2])<<16 | u32(p[j+3])<<24;
		}
		i := 0;
		for i < 16 {
			alpha = a + (b ~ c ~ d) + x[RIPEMD_128_N0[i]];
			s := int(RIPEMD_128_R0[i]);
			alpha = util.ROTL32(alpha, s);
			a, b, c, d = d, alpha, b, c;
			alpha = aa + (bb & dd | cc &~ dd) + x[RIPEMD_128_N1[i]] + 0x50a28be6;
			s = int(RIPEMD_128_R1[i]);
			alpha = util.ROTL32(alpha, s);
			aa, bb, cc, dd= dd, alpha, bb, cc;
			i += 1;
		}
		t := a;
		a = aa;
		aa = t;
		for i < 32 {
			alpha = a + (d ~ (b & (c~d))) + x[RIPEMD_128_N0[i]] + 0x5a827999;
			s := int(RIPEMD_128_R0[i]);
			alpha = util.ROTL32(alpha, s);
			a, b, c, d = d, alpha, b, c;
			alpha = aa + (dd ~ (bb | ~cc)) + x[RIPEMD_128_N1[i]] + 0x5c4dd124;
			s = int(RIPEMD_128_R1[i]);
			alpha = util.ROTL32(alpha, s);
			aa, bb, cc, dd = dd, alpha, bb, cc;
			i += 1;
		}
		t = b; 
		b = bb; 
		bb = t;
		for i < 48 {
			alpha = a + (d ~ (b | ~c)) + x[RIPEMD_128_N0[i]] + 0x6ed9eba1;
			s := int(RIPEMD_128_R0[i]);
			alpha = util.ROTL32(alpha, s);
			a, b, c, d = d, alpha, b, c;
			alpha = aa + (dd ~ (bb & (cc~dd))) + x[RIPEMD_128_N1[i]] + 0x6d703ef3;
			s = int(RIPEMD_128_R1[i]);
			alpha = util.ROTL32(alpha, s);
			aa, bb, cc, dd = dd, alpha, bb, cc;
			i += 1;
		}
		t = c; 
		c = cc; 
		cc = t;
		for i < 64 {
			alpha = a + (c ~ (d & (b~c))) + x[RIPEMD_128_N0[i]] + 0x8f1bbcdc;
			s := int(RIPEMD_128_R0[i]);
			alpha = util.ROTL32(alpha, s);
			a, b, c, d = d, alpha, b, c;
			alpha = aa + (bb ~ cc ~ dd) + x[RIPEMD_128_N1[i]];
			s = int(RIPEMD_128_R1[i]);
			alpha = util.ROTL32(alpha, s);
			aa, bb, cc, dd = dd, alpha, bb, cc;
			i += 1;
		}
		t = d; 
		d = dd; 
		dd = t;
		ctx.s[0] += a;
		ctx.s[1] += b;
		ctx.s[2] += c;
		ctx.s[3] += d;
		ctx.s[4] += aa;
		ctx.s[5] += bb;
		ctx.s[6] += cc;
		ctx.s[7] += dd;
		p = p[RIPEMD_256_BLOCK_SIZE:];
		n += RIPEMD_256_BLOCK_SIZE;
	}
	return n;
}

ripemd_320_block :: proc(ctx: ^$T, p: []byte) -> int {
    n := 0;
	x : [16]u32 = ---;
	alpha, beta : u32 = ---, ---;
	p := p;
	for len(p) >= RIPEMD_320_BLOCK_SIZE {
		a, b, c, d, e := ctx.s[0], ctx.s[1], ctx.s[2], ctx.s[3], ctx.s[4];
		aa, bb, cc, dd, ee := ctx.s[5], ctx.s[6], ctx.s[7], ctx.s[8], ctx.s[9];
		for i,j := 0, 0; i < 16; i, j = i+1, j+4 {
			x[i] = u32(p[j]) | u32(p[j+1])<<8 | u32(p[j+2])<<16 | u32(p[j+3])<<24;
		}
		i := 0;
		for i < 16 {
			alpha = a + (b ~ c ~ d) + x[RIPEMD_160_N0[i]];
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb ~ (cc | ~dd)) + x[RIPEMD_160_N1[i]] + 0x50a28be6;
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		t := b;
		b = bb;
		bb = t;
		for i < 32 {
			alpha = a + (b&c | ~b&d) + x[RIPEMD_160_N0[i]] + 0x5a827999;
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb&dd | cc&~dd) + x[RIPEMD_160_N1[i]] + 0x5c4dd124;
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		t = d;
		d = dd;
		dd = t;
		for i < 48 {
			alpha = a + (b | ~c ~ d) + x[RIPEMD_160_N0[i]] + 0x6ed9eba1;
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb | ~cc ~ dd) + x[RIPEMD_160_N1[i]] + 0x6d703ef3;
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		t = a;
		a = aa;
		aa = t;
		for i < 64 {
			alpha = a + (b&d | c&~d) + x[RIPEMD_160_N0[i]] + 0x8f1bbcdc;
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb&cc | ~bb&dd) + x[RIPEMD_160_N1[i]] + 0x7a6d76e9;
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		t = c;
		c = cc;
		cc = t;
		for i < 80 {
			alpha = a + (b ~ (c | ~d)) + x[RIPEMD_160_N0[i]] + 0xa953fd4e;
			s := int(RIPEMD_160_R0[i]);
			alpha = util.ROTL32(alpha, s) + e;
			beta = util.ROTL32(c, 10);
			a, b, c, d, e = e, alpha, b, beta, d;
			alpha = aa + (bb ~ cc ~ dd) + x[RIPEMD_160_N1[i]];
			s = int(RIPEMD_160_R1[i]);
			alpha = util.ROTL32(alpha, s) + ee;
			beta = util.ROTL32(cc, 10);
			aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd;
			i += 1;
		}
		t = e;
		e = ee;
		ee = t;
		ctx.s[0] += a;
		ctx.s[1] += b;
		ctx.s[2] += c;
		ctx.s[3] += d;
		ctx.s[4] += e;
		ctx.s[5] += aa;
		ctx.s[6] += bb;
		ctx.s[7] += cc;
		ctx.s[8] += dd;
		ctx.s[9] += ee;
		p = p[RIPEMD_320_BLOCK_SIZE:];
		n += RIPEMD_320_BLOCK_SIZE;
	}
	return n;
}

ripemd_write :: proc(ctx: ^$T, p: []byte) {
    ctx.tc += u64(len(p));
	p := p;
	if ctx.nx > 0 {
		n := len(p);

        when T == RIPEMD_128 {
            if n > RIPEMD_128_BLOCK_SIZE - ctx.nx {
			    n = RIPEMD_128_BLOCK_SIZE - ctx.nx;
		    }
        } else when T == RIPEMD_160 {
            if n > RIPEMD_160_BLOCK_SIZE - ctx.nx {
			    n = RIPEMD_160_BLOCK_SIZE - ctx.nx;
		    }
        } else when T == RIPEMD_256{
            if n > RIPEMD_256_BLOCK_SIZE - ctx.nx {
			    n = RIPEMD_256_BLOCK_SIZE - ctx.nx;
		    }
        } else when T == RIPEMD_320{
            if n > RIPEMD_320_BLOCK_SIZE - ctx.nx {
			    n = RIPEMD_320_BLOCK_SIZE - ctx.nx;
		    }
        }

		for i := 0; i < n; i += 1 {
			ctx.x[ctx.nx + i] = p[i];
		}

		ctx.nx += n;
        when T == RIPEMD_128 {
            if ctx.nx == RIPEMD_128_BLOCK_SIZE {
                ripemd_block(ctx, ctx.x[0:]);
                ctx.nx = 0;
            }
        } else when T == RIPEMD_160 {
            if ctx.nx == RIPEMD_160_BLOCK_SIZE {
                ripemd_block(ctx, ctx.x[0:]);
                ctx.nx = 0;
            }
        } else when T == RIPEMD_256{
            if ctx.nx == RIPEMD_256_BLOCK_SIZE {
                ripemd_block(ctx, ctx.x[0:]);
                ctx.nx = 0;
            }
        } else when T == RIPEMD_320{
            if ctx.nx == RIPEMD_320_BLOCK_SIZE {
                ripemd_block(ctx, ctx.x[0:]);
                ctx.nx = 0;
            }
        }
		p = p[n:];
	}
    n := ripemd_block(ctx, p);
	p = p[n:];
	if len(p) > 0 {
		ctx.nx = copy(ctx.x[:], p);
	}
}

ripemd_checksum :: proc(ctx: ^$T, p: []byte) -> []byte {
	d := ctx;
    tc := d.tc;
    tmp : [64]byte;
    tmp[0] = 0x80;

    if tc % 64 < 56 {
        ripemd_write(d, tmp[0:56 - tc % 64]);
    } else {
        ripemd_write(d, tmp[0:64 + 56 - tc % 64]);
    }

    tc <<= 3;
    for i : u32 = 0; i < 8; i += 1 {
        tmp[i] = byte(tc >> (8 * i));
    }

    ripemd_write(d, tmp[0:8]);
    assert(d.nx == 0); // @note(zh): remove after thorough testing?
    size : int;
    when T == RIPEMD_128 {
        size = RIPEMD_128_SIZE;
    } else when T == RIPEMD_160 {
        size = RIPEMD_160_SIZE;
    } else when T == RIPEMD_256{
        size = RIPEMD_256_SIZE;
    } else when T == RIPEMD_320{
        size = RIPEMD_320_SIZE;
    }

    digest := make([]byte, size);
    for s, i in d.s {
		digest[i * 4] = byte(s);
		digest[i * 4 + 1] = byte(s >> 8);
		digest[i * 4 + 2] = byte(s >> 16);
		digest[i * 4 + 3] = byte(s >> 24);
	}
    return digest;
}

hash_128 :: proc (data: []byte) -> [RIPEMD_128_SIZE]byte #no_bounds_check {

	hash : [RIPEMD_128_SIZE]byte = ---;
    ctx : RIPEMD_128;
    ripemd_reset(&ctx);
	ripemd_write(&ctx, data);
    tmp := ripemd_checksum(&ctx, data);
	defer delete(tmp);
	copy(hash[:], tmp[:]);

    return hash;
}

hash_160 :: proc (data: []byte) -> [RIPEMD_160_SIZE]byte #no_bounds_check {

	hash : [RIPEMD_160_SIZE]byte = ---;
    ctx : RIPEMD_160;
    ripemd_reset(&ctx);
	ripemd_write(&ctx, data);
    tmp := ripemd_checksum(&ctx, data);
	defer delete(tmp);
	copy(hash[:], tmp[:]);
    
	return hash;
}

hash_256 :: proc (data: []byte) -> [RIPEMD_256_SIZE]byte #no_bounds_check {

	hash : [RIPEMD_256_SIZE]byte = ---;
    ctx : RIPEMD_256;
    ripemd_reset(&ctx);
	ripemd_write(&ctx, data);
    tmp := ripemd_checksum(&ctx, data);
	defer delete(tmp);
	copy(hash[:], tmp[:]);
    
	return hash;
}

hash_320 :: proc (data: []byte) -> [RIPEMD_320_SIZE]byte #no_bounds_check {

	hash : [RIPEMD_320_SIZE]byte = ---;
    ctx : RIPEMD_320;
    ripemd_reset(&ctx);
	ripemd_write(&ctx, data);
    tmp := ripemd_checksum(&ctx, data);
	defer delete(tmp);
	copy(hash[:], tmp[:]);
    
	return hash;
}