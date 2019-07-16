package rc5

using import ".."

// @ref(zh): https://github.com/dgryski/go-rc5/blob/master/rc5.go

SKEY_TABLE := [?]u32 {
	0xb7e15163, 0x5618cb1c, 0xf45044d5, 0x9287be8e, 0x30bf3847, 0xcef6b200, 0x6d2e2bb9, 0x0b65a572,
	0xa99d1f2b, 0x47d498e4, 0xe60c129d, 0x84438c56, 0x227b060f, 0xc0b27fc8, 0x5ee9f981, 0xfd21733a,
	0x9b58ecf3, 0x399066ac, 0xd7c7e065, 0x75ff5a1e, 0x1436d3d7, 0xb26e4d90, 0x50a5c749, 0xeedd4102,
	0x8d14babb, 0x2b4c3474,
};

ROUNDS :: 12;
ROUNDKEYS :: 26;
KEYWORDS :: 4;

u32_le :: inline proc "contextless"(b: []byte) -> u32 {
	return u32(b[0]) | u32(b[1]) << 8 | u32(b[2]) << 16 | u32(b[3]) << 24;
}

put_u32_le :: inline proc "contextless"(b: []byte, v: u32) {
	b[0] = byte(v);
	b[1] = byte(v >> 8);
	b[2] = byte(v >> 16);
	b[3] = byte(v >> 24);
}

expand_key :: proc(key: []byte) -> [ROUNDKEYS]u32 {
    key_len := len(key);
    assert(key_len == 16);

    rk: [ROUNDKEYS]u32;
    L: [KEYWORDS]u32;

    for i := 0; i < KEYWORDS; i += 1 {
        L[i] = u32_le(key[:4]);
        key = key[4:];
    }

    copy(rk[:], SKEY_TABLE[:]);

    A, B: u32;
    i, j: int;

    for k := 0; k < 3 * ROUNDKEYS; k += 1 {
        rk[i] = ROTL32(rk[i] + A + B, 3);
        A = rk[i];
        L[j] = ROTL32(L[j] + A + B, int(A + B));
        B = L[j];

        i = (i + 1) % ROUNDKEYS;
        j = (j + 1) % KEYWORDS;
    }

    return rk;
}

encrypt :: proc(key, plaintext: []byte) -> []byte {
    ciphertext := make([]byte, 8);
    expanded_key := expand_key(key);

    A := u32_le(plaintext[:4]) + expanded_key[0];
    B := u32_le(plaintext[4:8]) + expanded_key[1];

    kidx := 2;

    for r := 0; r < ROUNDS; r += 1 {
        A = ROTL32(A ~ B, int(B)) + expanded_key[kidx];
        B = ROTL32(B ~ A, int(A)) + expanded_key[kidx + 1];
        kidx += 2;
    }

    put_u32_le(ciphertext[:4], A);
    put_u32_le(ciphertext[4:8], B);

    return ciphertext;
}

decrypt :: proc(key, ciphertext: []byte) -> []byte {
    plaintext:= make([]byte, 8);
    expanded_key := expand_key(key);

    A := u32_le(ciphertext[:4]);
    B := u32_le(ciphertext[4:8]);

    kidx := 2 * ROUNDS;

    for r := 0; r < ROUNDS; r += 1 {
        B = ROTL32(B - expanded_key[kidx + 1], -int(A)) ~ A;
        A = ROTL32(A - expanded_key[kidx], -int(B)) ~ B;
        kidx -= 2;
    }

    put_u32_le(plaintext[4:8], B - expanded_key[1]);
    put_u32_le(plaintext[:4], A - expanded_key[0]);

    return plaintext;
}