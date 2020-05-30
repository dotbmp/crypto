package blake2b

import b "../_blake2"

hash :: proc (data: []byte) -> [b.BLAKE2B_SIZE]byte #no_bounds_check {;

	hash : [b.BLAKE2B_SIZE]byte = ---;
    ctx : b.BLAKE2B;
	cfg : b.BLAKE2_CONFIG;
	cfg.size = b.BLAKE2B_SIZE;
	b.blake2_initialize(&ctx, &cfg, false);
    b.blake2_reset(&ctx, false);
	b.blake2_write(&ctx, data, false);
	hash = b.blake2b_final(&ctx);

    return hash;
}