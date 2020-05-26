package idea

// @ref(zh): https://www.source-code.biz/idea/java/ (Also has the original C code)

ROUNDS   :: 8;
KEY_SIZE :: 52;

Idea :: struct {
	expanded_key: [KEY_SIZE]i32,
	is_encrypt: bool,
};


add :: inline proc(a, b: i32) -> i32 {
	return (a + b) & 0xffff;
}

add_inv :: inline proc(x: i32) -> i32 {
	return (0x10000 - x) & 0xffff;
}

mul :: inline proc(a, b: i32) -> i32 {
	r := u32(a * b);
	if r != 0 {
		return i32(r % 0x10001) & 0xffff;
	} else {
		return (1 - a - b) & 0xffff;
	}
}

mul_inv :: inline proc(x: i32) -> i32 {
	if x <= 1 do return x;
	y  := i32(0x10001);
	t0 := i32(1);
	t1 := i32(0);
	x := x;
	for {
		t1 += y / x * t0;
		y %= x;
		if y == 1 do return 0x10001 - t1;
		t0 += x / y * t1;
		x %= y;
		if x == 1 do return t0;
	}
	return 0;
}

crypt :: proc(ctx: ^Idea, input, output: []byte) {
	x0 := i32(((i32(input[0] & 0xff)) << 8) | i32(input[1] & 0xff));
	x1 := i32(((i32(input[2] & 0xff)) << 8) | i32(input[3] & 0xff));
	x2 := i32(((i32(input[4] & 0xff)) << 8) | i32(input[5] & 0xff));
	x3 := i32(((i32(input[6] & 0xff)) << 8) | i32(input[7] & 0xff));

	p := 0;
	for a in 0..<ROUNDS {
		y0 := i32(mul(x0, ctx.expanded_key[p])); p += 1;
		y1 := i32(add(x1, ctx.expanded_key[p])); p += 1;
		y2 := i32(add(x2, ctx.expanded_key[p])); p += 1;
		y3 := i32(mul(x3, ctx.expanded_key[p])); p += 1;

		t0 := i32(mul(y0 ~ y2, ctx.expanded_key[p])); p += 1;
		t1 := i32(add(y1 ~ y3, t0));
		t2 := i32(mul(t1, ctx.expanded_key[p])); 	  p += 1;
		t3 := i32(add(t0, t2));

		x0 = y0 ~ t2;
     	x1 = y2 ~ t2;
     	x2 = y1 ~ t3;
      	x3 = y3 ~ t3;
	}

	r0 := i32(mul(x0, ctx.expanded_key[p])); p += 1;
	r1 := i32(add(x2, ctx.expanded_key[p])); p += 1;
	r2 := i32(add(x1, ctx.expanded_key[p])); p += 1;
	r3 := i32(mul(x3, ctx.expanded_key[p])); p += 1;

	output[0] = byte(r0 >> 8);
    output[1] = byte(r0);
    output[2] = byte(r1 >> 8);
    output[3] = byte(r1);
    output[4] = byte(r2 >> 8);
    output[5] = byte(r2);
    output[6] = byte(r3 >> 8);
    output[7] = byte(r3);
}

init :: proc(ctx: ^Idea, key: []byte) {
	sub_key := expand_key(key);
	if ctx.is_encrypt {
		ctx.expanded_key = sub_key;
	} else {
		ctx.expanded_key = invert_key(sub_key);
	}
}

expand_key :: proc(key: []byte) -> [KEY_SIZE]i32 {
	length := len(key);
	assert(length == 16, "Invalid key length. Must be 16");
	expanded_key: [KEY_SIZE]i32;
	for i in 0..<(length / 2) {
		expanded_key[i] = i32(((i32(key[2 * i]) & 0xff) << 8) | (i32(key[2 * i + 1]) & 0xff));
	}
	for i in (length / 2)..<len(expanded_key) {
		expanded_key[i] = i32(((expanded_key[(i + 1) % 8 != 0 ? i - 7 : i - 15] << 9) | (expanded_key[(i + 2) % 8 < 2 ? i - 14 : i - 6] >> 7)) & 0xffff);
	}
	return expanded_key;
}

invert_key :: proc(key: [KEY_SIZE]i32) -> [KEY_SIZE]i32 {
	inverted_key: [KEY_SIZE]i32;
	p := 0;
	i := ROUNDS * 6;
	inverted_key[i + 0] = mul_inv(key[p]); p += 1;
	inverted_key[i + 1] = add_inv(key[p]); p += 1;
	inverted_key[i + 2] = add_inv(key[p]); p += 1;
	inverted_key[i + 3] = mul_inv(key[p]); p += 1;
	for r := ROUNDS - 1; r >= 0; r -= 1 {
		i = r * 6;
		m := r > 0 ? 2 : 1;
		n := r > 0 ? 1 : 2;
		inverted_key[i + 4] = key[p];		   p += 1;
		inverted_key[i + 5] = key[p]; 		   p += 1;
		inverted_key[i + 0] = mul_inv(key[p]); p += 1;
		inverted_key[i + m] = add_inv(key[p]); p += 1;
		inverted_key[i + n] = add_inv(key[p]); p += 1;
		inverted_key[i + 3] = mul_inv(key[p]); p += 1;
	}
	return inverted_key;
}

encrypt :: proc(key, plaintext: []byte, allocator := context.allocator) -> []byte {
	ciphertext := make([]byte, len(plaintext), allocator);
	ctx: Idea;
	ctx.is_encrypt = true;
	init(&ctx, key);
	crypt(&ctx, plaintext, ciphertext);
	return ciphertext;
}

decrypt :: proc(key, ciphertext: []byte, allocator := context.allocator) -> []byte {
	plaintext := make([]byte, len(ciphertext), allocator);
	ctx: Idea;
	ctx.is_encrypt = false;
	init(&ctx, key);
	crypt(&ctx, ciphertext, plaintext);
	return plaintext;
}