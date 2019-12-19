package blake2s

import b "../_blake2"

hash :: proc "contextless" (data: []byte) -> [b.BLAKE2S_SIZE]byte #no_bounds_check {

	hash : [b.BLAKE2S_SIZE]byte = ---;
    ctx : b.BLAKE2S;
	cfg : b.BLAKE2_CONFIG;
	cfg.size = b.BLAKE2S_SIZE;
	b.blake2_initialize(&ctx, &cfg, true);
    b.blake2_reset(&ctx, true);
	b.blake2_write(&ctx, data, true);
	hash = b.blake2s_final(&ctx);

    return hash;
}