package blake2b

using import "_blake2"

hash :: proc "contextless" (data: []byte) -> [BLAKE2B_SIZE]byte #no_bounds_check {;

	hash : [BLAKE2B_SIZE]byte = ---;
    ctx : BLAKE2B;
	cfg : BLAKE2_CONFIG;
	cfg.size = BLAKE2B_SIZE;
	blake2_initialize(&ctx, &cfg, false);
    blake2_reset(&ctx, false);
	blake2_write(&ctx, data, false);
	hash = blake2b_final(&ctx);

    return hash;
}