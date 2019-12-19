package tiger

import t "../_tiger"

hash_128 :: proc "contextless" (input: []byte) -> [16]byte {
    hash: [16]byte;
    ctx: t.TIGER;
	ctx.ver = 1;
    t.tiger_init(&ctx);
    t.tiger_update(&ctx, input);
    tmp := t.tiger_final(&ctx);
	copy(hash[:], tmp[:16]);
    return hash;
}

hash_160 :: proc "contextless" (input: []byte) -> [20]byte {
    hash: [20]byte;
    ctx: t.TIGER;
	ctx.ver = 1;
    t.tiger_init(&ctx);
    t.tiger_update(&ctx, input);
    tmp := t.tiger_final(&ctx);
	copy(hash[:], tmp[:20]);
    return hash;
}

hash_192 :: proc "contextless" (input: []byte) -> [24]byte {
    hash: [24]byte;
    ctx: t.TIGER;
	ctx.ver = 1;
    t.tiger_init(&ctx);
    t.tiger_update(&ctx, input);
    hash = t.tiger_final(&ctx);
    return hash;
}