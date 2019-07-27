package rc6

using import ".."
import "core:fmt"

// @ref(zh): https://github.com/dgryski/go-rc6

SKEY_TABLE := [?]u32 {
	0xb7e15163, 0x5618cb1c, 0xf45044d5, 0x9287be8e, 0x30bf3847, 0xcef6b200, 0x6d2e2bb9, 0x0b65a572,
	0xa99d1f2b, 0x47d498e4, 0xe60c129d, 0x84438c56, 0x227b060f, 0xc0b27fc8, 0x5ee9f981, 0xfd21733a,
	0x9b58ecf3, 0x399066ac, 0xd7c7e065, 0x75ff5a1e, 0x1436d3d7, 0xb26e4d90, 0x50a5c749, 0xeedd4102,
	0x8d14babb, 0x2b4c3474, 0xc983ae2d, 0x67bb27e6, 0x05f2a19f, 0xa42a1b58, 0x42619511, 0xe0990eca,
	0x7ed08883, 0x1d08023c, 0xbb3f7bf5, 0x5976f5ae, 0xf7ae6f67, 0x95e5e920, 0x341d62d9, 0xd254dc92,
	0x708c564b, 0x0ec3d004, 0xacfb49bd, 0x4b32c376,
};

ROUNDS :: 20;
ROUNDKEYS :: 44;
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
    key := key;
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
    ciphertext := make([]byte, 16);
    expanded_key := expand_key(key);

    A := u32_le(plaintext[:4]);
    B := u32_le(plaintext[4:8]);
    C := u32_le(plaintext[8:12]);
    D := u32_le(plaintext[12:16]);

    B += expanded_key[0];
    D += expanded_key[1];

    for i := 1; i <= ROUNDS; i += 1 {
        t := ROTL32(B * (2 * B + 1), 5);
        u := ROTL32(D * (2 * D + 1), 5);
        A = ROTL32((A ~ t), int(u)) + expanded_key[2 * i];
        C = ROTL32((C ~ u), int(t)) + expanded_key[2 * i + 1];
        A, B, C, D = B, C, D, A;
    }
    A += expanded_key[2 * ROUNDS + 2];
    C += expanded_key[2 * ROUNDS + 3];

    put_u32_le(ciphertext[:4], A);
    put_u32_le(ciphertext[4:8], B);
    put_u32_le(ciphertext[8:12], C);
    put_u32_le(ciphertext[12:16], D);

    return ciphertext;
}

decrypt :: proc(key, ciphertext: []byte) -> []byte {
    plaintext:= make([]byte, 16);
    expanded_key := expand_key(key);

    A := u32_le(ciphertext[:4]);
    B := u32_le(ciphertext[4:8]);
    C := u32_le(ciphertext[8:12]);
    D := u32_le(ciphertext[12:16]);

    C -= expanded_key[2 * ROUNDS + 3];
    A -= expanded_key[2 * ROUNDS + 2];
    for i := ROUNDS; i >= 1; i -= 1 {
        A, B, C, D = D, A, B, C;
        u := ROTL32(D * (2 * D + 1), 5);
        t := ROTL32(B * (2 * B + 1), 5);
        C = ROTL32(C - expanded_key[2 * i + 1], -int(t)) ~ u;
        A = ROTL32(A - expanded_key[2 * i], -int(u)) ~ t;
    }
    D -= expanded_key[1];
    B -= expanded_key[0];

    put_u32_le(plaintext[:4], A);
    put_u32_le(plaintext[4:8], B);
    put_u32_le(plaintext[8:12], C);
    put_u32_le(plaintext[12:16], D);

    return plaintext;
}