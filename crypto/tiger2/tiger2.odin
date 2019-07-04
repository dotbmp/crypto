package tiger2

using import "_tiger"

hash_128 :: proc "contextless" (input: []byte) -> [16]byte {
    hash: [16]byte;
    ctx: TIGER;
	ctx.ver = 2;
    tiger_init(&ctx);
    tiger_update(&ctx, input);
    tmp := tiger_final(&ctx);
	copy(hash[:], tmp[:16]);
    return hash;
}

hash_160 :: proc "contextless" (input: []byte) -> [20]byte {
    hash: [20]byte;
    ctx: TIGER;
	ctx.ver = 2;
    tiger_init(&ctx);
    tiger_update(&ctx, input);
    tmp := tiger_final(&ctx);
	copy(hash[:], tmp[:20]);
    return hash;
}

hash_192 :: proc "contextless" (input: []byte) -> [24]byte {
    hash: [24]byte;
    ctx: TIGER;
	ctx.ver = 2;
    tiger_init(&ctx);
    tiger_update(&ctx, input);
    hash = tiger_final(&ctx);
    return hash;
}