package tiger2

import t "../_tiger"

hash_128 :: proc (input: []byte) -> [16]byte {
    hash: [16]byte;
    ctx: t.TIGER;
	ctx.ver = 2;
    t.tiger_init(&ctx);
    t.tiger_update(&ctx, input);
    tmp := t.tiger_final(&ctx);
	copy(hash[:], tmp[:16]);
    return hash;
}

hash_160 :: proc (input: []byte) -> [20]byte {
    hash: [20]byte;
    ctx: t.TIGER;
	ctx.ver = 2;
    t.tiger_init(&ctx);
    t.tiger_update(&ctx, input);
    tmp := t.tiger_final(&ctx);
	copy(hash[:], tmp[:20]);
    return hash;
}

hash_192 :: proc (input: []byte) -> [24]byte {
    hash: [24]byte;
    ctx: t.TIGER;
	ctx.ver = 2;
    t.tiger_init(&ctx);
    t.tiger_update(&ctx, input);
    hash = t.tiger_final(&ctx);
    return hash;
}