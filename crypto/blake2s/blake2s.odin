package blake2s

using import "../_blake2"

hash :: proc "contextless" (data: []byte) -> [BLAKE2S_SIZE]byte #no_bounds_check {

	hash : [BLAKE2S_SIZE]byte = ---;
    ctx : BLAKE2S;
	cfg : BLAKE2_CONFIG;
	cfg.size = BLAKE2S_SIZE;
	blake2_initialize(&ctx, &cfg, true);
    blake2_reset(&ctx, true);
	blake2_write(&ctx, data, true);
	hash = blake2s_final(&ctx);

    return hash;
}