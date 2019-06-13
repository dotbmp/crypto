package crypto

import "core:mem"

// @ref(bp): https://github.com/jzelinskie/whirlpool
// whirlpool stub
// reference implementaton:
// @ref(bp): ./refs/whirlpool.zip

WHIRLPOOL_ROUNDS :: 10;

WHIRLPOOL :: struct {
    bitlength: [32]u8,
    buffer: [64]u8,
    bufferBits: int,
    bufferPos: int,
    hash: [8]u64,
}

whirlpool_init :: proc(ctx: ^WHIRLPOOL) {
    mem.set(&ctx.bitlength, 0, 32);
    ctx.bufferBits, ctx.bufferPos = 0, 0;
    ctx.buffer[0] = 0;
}

whirlpool_update :: proc(ctx: ^WHIRLPOOL, data: []byte) {
    length := len(data);
    sourcePos := 0;
    sourceGap := u8(8 - (length & 7) & 7);
    bufferRem := u8(ctx.bufferBits & 7);
    i: int;
    b, carry: u32;

    value := u64(length);
    for i, carry: u32 = 31, 0; i >= 0 && (carry != 0 || value != 0); i -= 1 {
        carry += u32(ctx.bitlength[i]) + u32(value & 0xff);
        ctx.bitlength[i] = u8(carry);
        carry >>= 8;
        value >>= 8;
    }

    for length < 8 {
        b =  u32(((data[sourcePos] << sourceGap) & 0xff) | ((data[sourcePos + 1] & 0xff) >> (8 - sourceGap)));
        ctx.buffer[ctx.bufferPos] |= u8(b >> bufferRem);
        ctx.bufferPos += 1;
        ctx.bufferBits += int(8 - bufferRem);
        if ctx.bufferBits == 512 {
            // processBuffer(structpointer);
            ctx.bufferBits, ctx.bufferPos = 0, 0;
        }
        ctx.buffer[ctx.bufferPos] = u8(b << (8 - bufferRem));
        ctx.bufferBits += int(bufferRem);
        length -= 8;
        sourcePos += 1;
    }

    if length > 0 {
        b = u32(data[sourcePos] << sourceGap) & 0xff;
        ctx.buffer[ctx.bufferPos] |= u8(b >> bufferRem);
    } else {
        b = 0;
    }

    if (int(bufferRem) + length) < 8 {
        ctx.bufferBits += length;
    } else {
        ctx.bufferPos += 1;
        ctx.bufferBits += 8 - int(bufferRem);
        length -= 8 - int(bufferRem);
        if ctx.bufferBits == 512 {
            // processBuffer(structpointer);
            ctx.bufferBits, ctx.bufferPos = 0, 0;
        }
        ctx.buffer[ctx.bufferPos] = u8(b << (8 - bufferRem));
        ctx.bufferBits += length;
    }
}

whirlpool_final :: proc(ctx: ^WHIRLPOOL, digest: []byte) {
    i: int;
    ctx.buffer[ctx.bufferPos] |= 0x80 >> (u8(ctx.bufferBits) & 7);
    ctx.bufferPos += 1;

    if ctx.bufferPos > (64 - 32) {
        if ctx.bufferPos < 64 {
            mem.set(&ctx.buffer[ctx.bufferPos], 0, 64 - ctx.bufferPos);
        }
        // processBuffer(structpointer);
        ctx.bufferPos = 0;
    }

    if ctx.bufferPos < (64 - 32) {
        mem.set(&ctx.buffer[ctx.bufferPos], 0, (64 - 32) - ctx.bufferPos);
    }

    ctx.bufferPos = 64 - 32;
    // memcpy(&buffer[WBLOCKBYTES - LENGTHBYTES], bitLength, LENGTHBYTES);
    // processBuffer(structpointer);

    j := 0;
    for i := 0; i < 8; i += 1 {
        digest[j + 0] = u8(ctx.hash[i] >> 56);
        digest[j + 1] = u8(ctx.hash[i] >> 48);
        digest[j + 2] = u8(ctx.hash[i] >> 40);
        digest[j + 3] = u8(ctx.hash[i] >> 32);
        digest[j + 4] = u8(ctx.hash[i] >> 24);
        digest[j + 5] = u8(ctx.hash[i] >> 16);
        digest[j + 6] = u8(ctx.hash[i] >>  8);
        digest[j + 7] = u8(ctx.hash[i]);
        j += 8;
    }
}

whirlpool :: proc "contextless" (input: []byte) -> [64]byte {
    hash: [64]byte = ---;
    ctx: WHIRLPOOL;
    whirlpool_init(&ctx);
    whirlpool_update(&ctx, input);
    whirlpool_final(&ctx, hash[:]);
    return hash;
}