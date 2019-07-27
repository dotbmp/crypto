package groestl

// @ref(zh): Reference implementation taken from http://www.groestl.info/Groestl.zip

GROESTL_S := [256]u8 {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

GROESTL_SHIFT := [2][2][8]int {
    {{0,1,2,3,4,5,6,7}, {1,3,5,7,0,2,4,6}},
    {{0,1,2,3,4,5,6,11}, {1,3,5,11,0,2,4,6}}
};

GROESTL :: struct {
    chaining: [8][16]u8,
    block_counter: u64,
    hashbitlen: int,
    buffer: [128]byte,
    buf_ptr: int,
    bits_in_last_byte: int,
    columns: int,
    rounds: int,
    statesize: int,
}

Groestl_Variant :: enum {
    P512 = 0, 
    Q512 = 1, 
    P1024 = 2, 
    Q1024 = 3
}

GROESTL_MUL2 :: inline proc "contextless"(b: u8) -> u8 {
    return (b >> 7) != 0 ? (b << 1) ~ 0x1b : (b << 1);
}

GROESTL_MUL3 :: inline proc "contextless"(b: u8) -> u8 {
    return GROESTL_MUL2(b) ~ b;
}

GROESTL_MUL4 :: inline proc "contextless"(b: u8) -> u8 {
    return GROESTL_MUL2(GROESTL_MUL2(b));
}

GROESTL_MUL5 :: inline proc "contextless"(b: u8) -> u8 {
    return GROESTL_MUL4(b) ~ b;
}

GROESTL_MUL6 :: inline proc "contextless"(b: u8) -> u8 {
    return GROESTL_MUL4(b) ~ GROESTL_MUL2(b);
}

GROESTL_MUL7 :: inline proc "contextless"(b: u8) -> u8 {
    return GROESTL_MUL4(b) ~ GROESTL_MUL2(b) ~ b;
}

groestl_subbytes :: inline proc "contextless"(x: [][16]byte, columns: int) {
    for i := 0; i < 8; i += 1 {
        for j := 0; j < columns; j += 1 do x[i][j] = GROESTL_S[x[i][j]];
    }
}

groestl_shiftbytes :: inline proc "contextless"(x: [][16]byte, columns: int, v: Groestl_Variant) {
    temp: [16]u8;
    R := &GROESTL_SHIFT[int(v) / 2][int(v) & 1];

    for i := 0; i < 8; i += 1 {
        for j := 0; j < columns; j += 1 do temp[j] = x[i][(j + R[i]) % columns];
        for j := 0; j < columns; j += 1 do x[i][j] = temp[j];
    }
}

groestl_mixbytes :: inline proc "contextless"(x: [][16]byte, columns: int) {
    temp: [8]u8;

    for i := 0; i < columns; i += 1 {
        for j := 0; j < 8; j += 1 {
            temp[j] = 	GROESTL_MUL2(x[(j + 0) % 8][i]) ~
                        GROESTL_MUL2(x[(j + 1) % 8][i]) ~
                        GROESTL_MUL3(x[(j + 2) % 8][i]) ~
                        GROESTL_MUL4(x[(j + 3) % 8][i]) ~
                        GROESTL_MUL5(x[(j + 4) % 8][i]) ~
                        GROESTL_MUL3(x[(j + 5) % 8][i]) ~
                        GROESTL_MUL5(x[(j + 6) % 8][i]) ~
                        GROESTL_MUL7(x[(j + 7) % 8][i]);
        }
        for j := 0; j < 8; j += 1 do x[j][i] = temp[j];
    }
}

groestl_p :: inline proc "contextless"(ctx: ^GROESTL, x: [][16]byte) {
    v := ctx.columns == 8 ? Groestl_Variant.P512 : Groestl_Variant.P1024;
    for i := 0; i < ctx.rounds; i += 1 {
        groestl_add_roundconstant(x, ctx.columns, u8(i), v);
        groestl_subbytes(x, ctx.columns);
        groestl_shiftbytes(x, ctx.columns, v);
        groestl_mixbytes(x, ctx.columns);
    }
}

groestl_q :: inline proc "contextless"(ctx: ^GROESTL, x: [][16]byte) {
    v := ctx.columns == 8 ? Groestl_Variant.Q512 : Groestl_Variant.Q1024;
    for i := 0; i < ctx.rounds; i += 1 {
        groestl_add_roundconstant(x, ctx.columns, u8(i), v);
        groestl_subbytes(x, ctx.columns);
        groestl_shiftbytes(x, ctx.columns, v);
        groestl_mixbytes(x, ctx.columns);
    }
}

groestl_transform :: proc(ctx: ^GROESTL, input: []byte, msglen: u32) {
    temp1, temp2: [8][16]u8;
    input, msglen := input, msglen;

    for msglen >= u32(ctx.statesize) {
        for i := 0; i < 8; i += 1 {
            for j := 0; j < ctx.columns; j += 1 {
                temp1[i][j] = ctx.chaining[i][j] ~ input[j * 8 + i];
                temp2[i][j] = input[j * 8 + i];
            }
        }

        groestl_p(ctx, temp1[:]);
        groestl_q(ctx, temp2[:]);

        for i := 0; i < 8; i += 1 {
            for j := 0; j < ctx.columns; j += 1 do ctx.chaining[i][j] ~= temp1[i][j] ~ temp2[i][j];
        }

        ctx.block_counter += 1;
        msglen -= u32(ctx.statesize);
        input = input[ctx.statesize:];
    }
}

groestl_output_transformation :: proc(ctx: ^GROESTL) {
    temp: [8][16]u8;

    for i := 0; i < 8; i += 1 {
        for j := 0; j < ctx.columns; j += 1 do temp[i][j] = ctx.chaining[i][j];
    }

    groestl_p(ctx, temp[:]);

    for i := 0; i < 8; i += 1 {
        for j := 0; j < ctx.columns; j += 1 do ctx.chaining[i][j] ~= temp[i][j];
    }
}

groestl_add_roundconstant :: proc(x: [][16]byte, columns: int, round: byte, v: Groestl_Variant) {
    switch (i32(v) & 1) {
        case 0: 
            for i := 0; i < columns; i += 1 do x[0][i] ~= u8(i << 4) ~ round;
        case 1:
            for i := 0; i < columns; i += 1 {
                for j := 0; j < 7; j += 1 do x[j][i] ~= 0xff;
            }
            for i := 0; i < columns; i += 1 do x[7][i] ~= u8(i << 4) ~ 0xff ~ round;
    }
}

groestl_init :: proc(ctx: ^GROESTL, hashbitlen: int) {
    if hashbitlen <= 256 {
        ctx.rounds = 10;
        ctx.columns = 8;
        ctx.statesize = 64;
    } else {
        ctx.rounds = 14;
        ctx.columns = 16;
        ctx.statesize = 128;
    }

    for i := 0; i < 8; i += 1 {
        for j := 0; j < ctx.columns; j += 1 {
            ctx.chaining[i][j] = 0;
        }
    }

    ctx.hashbitlen = hashbitlen;
    for i := 8 - size_of(i32); i < 8; i += 1 {
        ctx.chaining[i][ctx.columns - 1] = u8(hashbitlen >> (8 * (7 - uint(i))));
    }

    ctx.buf_ptr = 0;
    ctx.block_counter = 0;
    ctx.bits_in_last_byte = 0;
}

groestl_update :: proc(ctx: ^GROESTL, input: []byte) {
    databitlen := len(input) * 8;
    index: int;
    msglen := databitlen / 8;
    rem := databitlen % 8;

    assert(ctx.bits_in_last_byte == 0);

    if ctx.buf_ptr != 0 {
        for index = 0; ctx.buf_ptr < ctx.statesize && index < msglen; index, ctx.buf_ptr =  index + 1, ctx.buf_ptr + 1 {
            ctx.buffer[ctx.buf_ptr] = input[index];
        }

        if ctx.buf_ptr < ctx.statesize {
            if rem != 0 {
                ctx.bits_in_last_byte = rem;
                ctx.buffer[ctx.buf_ptr] = input[index];
                ctx.buf_ptr += 1;
            }
            return;
        }

        ctx.buf_ptr = 0;
        groestl_transform(ctx, ctx.buffer[:], u32(ctx.statesize));
    }

    groestl_transform(ctx, input[index:], u32(msglen - index));
    index += ((msglen - index) / ctx.statesize) * ctx.statesize;
    for index < msglen {
        ctx.buffer[ctx.buf_ptr] = input[index];
        index, ctx.buf_ptr = index + 1, ctx.buf_ptr + 1;
    }
    
    if rem != 0 {
        ctx.bits_in_last_byte = rem;
        ctx.buffer[ctx.buf_ptr] = input[index];
        ctx.buf_ptr += 1;
    }
}

groestl_final :: proc(ctx: ^GROESTL, output: []byte) {
    hashbytelen := ctx.hashbitlen / 8;

    if ctx.bits_in_last_byte != 0 {
        ctx.buffer[ctx.buf_ptr - 1] &= ((1 << uint(ctx.bits_in_last_byte)) - 1) << (8 - uint(ctx.bits_in_last_byte));
        ctx.buffer[ctx.buf_ptr - 1] ~= 0x1 << (7 - uint(ctx.bits_in_last_byte));
    } else {
        ctx.buffer[ctx.buf_ptr] = 0x80;
        ctx.buf_ptr += 1;
    }

    if ctx.buf_ptr > ctx.statesize - 8 {
        for ctx.buf_ptr < ctx.statesize {
            ctx.buffer[ctx.buf_ptr] = 0;
            ctx.buf_ptr += 1;
        }
        groestl_transform(ctx, ctx.buffer[:], u32(ctx.statesize));
        ctx.buf_ptr = 0;
    }

    for ctx.buf_ptr < ctx.statesize - 8 {
        ctx.buffer[ctx.buf_ptr] = 0;
        ctx.buf_ptr += 1;
    }

    ctx.block_counter += 1;
    ctx.buf_ptr = ctx.statesize;

    for ctx.buf_ptr > ctx.statesize - 8 {
        ctx.buf_ptr -= 1;
        ctx.buffer[ctx.buf_ptr] = u8(ctx.block_counter);
        ctx.block_counter >>= 8;
    }

    groestl_transform(ctx, ctx.buffer[:], u32(ctx.statesize));
    groestl_output_transformation(ctx);

    for i, j := ctx.statesize - hashbytelen , 0; i < ctx.statesize; i, j = i + 1, j + 1 {
        output[j] = ctx.chaining[i % 8][i / 8];
    }
    
    for i := 0; i < 8; i += 1 {
        for j := 0; j < ctx.columns; j += 1 do ctx.chaining[i][j] = 0;
    }

    for i := 0; i < ctx.statesize; i += 1 do ctx.buffer[i] = 0;
}

hash_224 :: proc "contextless" (data: []byte) -> [28]byte #no_bounds_check {
    hash : [28]byte;
    ctx : GROESTL;
    groestl_init(&ctx, 224);
    groestl_update(&ctx, data);
    groestl_final(&ctx, hash[:]);
    return hash;
}

hash_256 :: proc "contextless" (data: []byte) -> [32]byte #no_bounds_check {
    hash : [32]byte;
    ctx : GROESTL;
    groestl_init(&ctx, 256);
    groestl_update(&ctx, data);
    groestl_final(&ctx, hash[:]);
    return hash;
}

hash_384 :: proc "contextless" (data: []byte) -> [48]byte #no_bounds_check {
    hash : [48]byte;
    ctx : GROESTL;
    groestl_init(&ctx, 384);
    groestl_update(&ctx, data);
    groestl_final(&ctx, hash[:]);
    return hash;
}

hash_512 :: proc "contextless" (data: []byte) -> [64]byte #no_bounds_check {
    hash : [64]byte;
    ctx : GROESTL;
    groestl_init(&ctx, 512);
    groestl_update(&ctx, data);
    groestl_final(&ctx, hash[:]);
    return hash;
}