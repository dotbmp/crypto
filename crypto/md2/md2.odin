package md2

// @ref(zh): https://github.com/B-Con/crypto-algorithms

import "core:fmt"
import "core:hash"
import "core:runtime"
import "core:math/bits"

MD2_BLOCK_SIZE :: 16;

MD2_CTX :: struct {
    data: [MD2_BLOCK_SIZE]u8,
    state: [MD2_BLOCK_SIZE * 3]u8,
    checksum: [MD2_BLOCK_SIZE]u8,
    len: int,
}

MD2_TABLE := [MD2_BLOCK_SIZE * MD2_BLOCK_SIZE]u8{
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

md2_transform :: proc(ctx: ^MD2_CTX, data: [MD2_BLOCK_SIZE]byte) {

    j,k,t : u8;

	for j=0; j < MD2_BLOCK_SIZE; j += 1 {
		ctx.state[j + MD2_BLOCK_SIZE] = data[j];
		ctx.state[j + MD2_BLOCK_SIZE * 2] = (ctx.state[j+MD2_BLOCK_SIZE] ~ ctx.state[j]);
	}

	t = 0;
	for j = 0; j < MD2_BLOCK_SIZE + 2; j+=1 {
		for k = 0; k < MD2_BLOCK_SIZE * 3; k+=1 {
			ctx.state[k] ~= MD2_TABLE[t];
			t = ctx.state[k];
		}
		t = (t+j) & 0xFF;
	}

	t = ctx.checksum[MD2_BLOCK_SIZE - 1];
	for j=0; j < MD2_BLOCK_SIZE; j+=1 {
		ctx.checksum[j] ~= MD2_TABLE[data[j] ~ t];
		t = ctx.checksum[j];
	}
}

md2_init :: proc(ctx: ^MD2_CTX) {

	for i:=0; i < MD2_BLOCK_SIZE * 3; i+=1 {
		ctx.state[i] = 0;

		if i < MD2_BLOCK_SIZE {
			ctx.checksum[i] = 0;
		}
    }

	ctx.len = 0;
}

md2_update :: proc(ctx: ^MD2_CTX, data: []byte) {

	for i := 0; i < len(data); i+=1 {
		ctx.data[ctx.len] = data[i];
		ctx.len+=1;
		if (ctx.len == MD2_BLOCK_SIZE) {
			md2_transform(ctx, ctx.data);
			ctx.len = 0;
		}
	}
}

md2_final :: proc(ctx: ^MD2_CTX, hash: ^[MD2_BLOCK_SIZE]u8){

	to_pad := u8(MD2_BLOCK_SIZE - ctx.len);

    for ctx.len < MD2_BLOCK_SIZE {

        ctx.data[ctx.len] = to_pad;
		ctx.len += 1;
    }

	md2_transform(ctx, ctx.data);
	md2_transform(ctx, ctx.checksum);

    for i := 0; i < MD2_BLOCK_SIZE; i += 1 {
        hash[i] = ctx.state[i];
    }
}

md2 :: proc(data: []byte) -> [MD2_BLOCK_SIZE]byte {

    hash : [MD2_BLOCK_SIZE]byte;
    ctx : MD2_CTX;

    md2_init(&ctx);
	md2_update(&ctx, data);
	md2_final(&ctx, &hash);

    return hash;
}