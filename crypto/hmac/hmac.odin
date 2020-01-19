package hmac

// @ref(zh): https://github.com/ogay/hmac/blob/master/hmac_sha2.c
import "core:mem"

/////////////////////////////
// SHA2 HMAC
/////////////////////////////

import "../sha2"

HmacSha224 :: struct {
    ctx_inside: sha2.Sha256,
    ctx_outside: sha2.Sha256,
    ctx_inside_reinit: sha2.Sha256,
    ctx_outside_reinit: sha2.Sha256,
    block_ipad: [sha2.SHA224_BLOCK_SIZE]byte,
    block_opad: [sha2.SHA224_BLOCK_SIZE]byte,
};

HmacSha256 :: struct {
    ctx_inside: sha2.Sha256,
    ctx_outside: sha2.Sha256,
    ctx_inside_reinit: sha2.Sha256,
    ctx_outside_reinit: sha2.Sha256,
    block_ipad: [sha2.SHA256_BLOCK_SIZE]byte,
    block_opad: [sha2.SHA256_BLOCK_SIZE]byte,
};

HmacSha384 :: struct {
    ctx_inside: sha2.Sha512,
    ctx_outside: sha2.Sha512,
    ctx_inside_reinit: sha2.Sha512,
    ctx_outside_reinit: sha2.Sha512,
    block_ipad: [sha2.SHA384_BLOCK_SIZE]byte,
    block_opad: [sha2.SHA384_BLOCK_SIZE]byte,
};

HmacSha512 :: struct {
    ctx_inside: sha2.Sha512,
    ctx_outside: sha2.Sha512,
    ctx_inside_reinit: sha2.Sha512,
    ctx_outside_reinit: sha2.Sha512,
    block_ipad: [sha2.SHA512_BLOCK_SIZE]byte,
    block_opad: [sha2.SHA512_BLOCK_SIZE]byte,
};

hmac_sha2_init :: proc(ctx: ^$T, key: []byte) {
    fill, num: u32;
    key_size := u32(len(key));
    key_used := make([]byte, key_size);

    when T == HmacSha224 {
        block_size  :: sha2.SHA224_BLOCK_SIZE;
        digest_size :: sha2.SHA224_DIGEST_SIZE;
        sizeof      :: size_of(sha2.Sha256);
    } else when T == HmacSha256 {
        block_size  :: sha2.SHA256_BLOCK_SIZE;
        digest_size :: sha2.SHA256_DIGEST_SIZE;
        sizeof      :: size_of(sha2.Sha256);
    } else when T == HmacSha384 {
        block_size  :: sha2.SHA384_BLOCK_SIZE;
        digest_size :: sha2.SHA384_DIGEST_SIZE;
        sizeof      :: size_of(sha2.Sha512);
    } else when T == HmacSha512 {
        block_size  :: sha2.SHA512_BLOCK_SIZE;
        digest_size :: sha2.SHA512_DIGEST_SIZE;
        sizeof      :: size_of(sha2.Sha512);
    }

    key_temp: [digest_size]byte;

    if key_size == block_size {
        key_used = key;
        num = block_size;
    } else {
        if key_size > block_size {
            num = digest_size;
            when      T == HmacSha224 do key_temp = sha2.hash_224(key);
            else when T == HmacSha256 do key_temp = sha2.hash_256(key);
            else when T == HmacSha384 do key_temp = sha2.hash_384(key);
            else when T == HmacSha512 do key_temp = sha2.hash_512(key);
            copy(key_used[:], key_temp[:]);
        } else {
            copy(key_used[:], key[:]);
            num = key_size;
        }
        fill = block_size - num;
        mem.set(rawptr(&(ctx.block_ipad[num:])[0]), 0x36, int(fill));
        mem.set(rawptr(&(ctx.block_opad[num:])[0]), 0x5c, int(fill));
    }

    for i := 0; i < int(num); i += 1 {
        ctx.block_ipad[i] = key_used[i] ~ 0x36;
        ctx.block_opad[i] = key_used[i] ~ 0x5c;
    }

    sha2.sha2_init(&ctx.ctx_inside);
    sha2.sha2_update(&ctx.ctx_inside, ctx.block_ipad[:]);
    sha2.sha2_init(&ctx.ctx_outside);
    sha2.sha2_update(&ctx.ctx_outside, ctx.block_opad[:]);
    mem.copy(&ctx.ctx_inside_reinit, &ctx.ctx_inside, sizeof);
    mem.copy(&ctx.ctx_outside_reinit, &ctx.ctx_outside, sizeof);
}

hmac_sha2_final :: proc(ctx: ^$T, mac: []byte) {
    when      T == HmacSha224 do digest_inside, mac_temp: [sha2.SHA224_DIGEST_SIZE]byte;
    else when T == HmacSha256 do digest_inside, mac_temp: [sha2.SHA256_DIGEST_SIZE]byte;
    else when T == HmacSha384 do digest_inside, mac_temp: [sha2.SHA384_DIGEST_SIZE]byte;
    else when T == HmacSha512 do digest_inside, mac_temp: [sha2.SHA512_DIGEST_SIZE]byte;
    sha2.sha2_final(&ctx.ctx_inside, digest_inside[:]);
    sha2.sha2_update(&ctx.ctx_outside, digest_inside[:]);
    sha2.sha2_final(&ctx.ctx_outside, mac_temp[:]);
    copy(mac[:], mac_temp[:]);
}

sha224 :: proc(data, key: []byte) -> [sha2.SHA224_DIGEST_SIZE]byte {
    mac: [sha2.SHA224_DIGEST_SIZE]byte;
    ctx: HmacSha224;
    ctx.ctx_inside.is224, ctx.ctx_outside.is224 = true, true;
    ctx.ctx_inside_reinit.is224, ctx.ctx_outside_reinit.is224 = true, true;
    hmac_sha2_init(&ctx, key);
    sha2.sha2_update(&ctx.ctx_inside, data);
    hmac_sha2_final(&ctx, mac[:]);
    return mac;
}

sha256 :: proc(data, key: []byte) -> [sha2.SHA256_DIGEST_SIZE]byte {
    mac: [sha2.SHA256_DIGEST_SIZE]byte;
    ctx: HmacSha256;
    hmac_sha2_init(&ctx, key);
    sha2.sha2_update(&ctx.ctx_inside, data);
    hmac_sha2_final(&ctx, mac[:]);
    return mac;
}

sha384 :: proc(data, key: []byte) -> [sha2.SHA384_DIGEST_SIZE]byte {
    mac: [sha2.SHA384_DIGEST_SIZE]byte;
    ctx: HmacSha384;
    ctx.ctx_inside.is384, ctx.ctx_outside.is384 = true, true;
    ctx.ctx_inside_reinit.is384, ctx.ctx_outside_reinit.is384 = true, true;
    hmac_sha2_init(&ctx, key);
    sha2.sha2_update(&ctx.ctx_inside, data);
    hmac_sha2_final(&ctx, mac[:]);
    return mac;
}

sha512 :: proc(data, key: []byte) -> [sha2.SHA512_DIGEST_SIZE]byte {
    mac: [sha2.SHA512_DIGEST_SIZE]byte;
    ctx: HmacSha512;
    hmac_sha2_init(&ctx, key);
    sha2.sha2_update(&ctx.ctx_inside, data);
    hmac_sha2_final(&ctx, mac[:]);
    return mac;
}

/////////////////////////////
// SHA1 HMAC
/////////////////////////////

import "../sha1"

HmacSha1 :: struct {
    ctx_inside: sha1.SHA1_CTX,
    ctx_outside: sha1.SHA1_CTX,
    ctx_inside_reinit: sha1.SHA1_CTX,
    ctx_outside_reinit: sha1.SHA1_CTX,
    block_ipad: [sha1.BLOCK_SIZE]byte,
    block_opad: [sha1.BLOCK_SIZE]byte,
};

hmac_sha1_init :: proc(ctx: ^$T, key: []byte) {
    fill, num: u32;
    key_size := u32(len(key));
    key_used := make([]byte, key_size);
    key_temp: [sha1.DIGEST_SIZE]byte;

    if key_size == sha1.BLOCK_SIZE {
        key_used = key;
        num = sha1.BLOCK_SIZE;
    } else {
        if key_size > sha1.BLOCK_SIZE {
            num = sha1.DIGEST_SIZE;
            key_temp = sha1.hash(key);
            copy(key_used[:], key_temp[:]);
        } else {
            copy(key_used[:], key[:]);
            num = key_size;
        }
        fill = sha1.BLOCK_SIZE - num;
        mem.set(rawptr(&(ctx.block_ipad[num:])[0]), 0x36, int(fill));
        mem.set(rawptr(&(ctx.block_opad[num:])[0]), 0x5c, int(fill));
    }

    for i := 0; i < int(num); i += 1 {
        ctx.block_ipad[i] = key_used[i] ~ 0x36;
        ctx.block_opad[i] = key_used[i] ~ 0x5c;
    }

    sha1.sha1_init(&ctx.ctx_inside);
    sha1.sha1_update(&ctx.ctx_inside, ctx.block_ipad[:]);
    sha1.sha1_init(&ctx.ctx_outside);
    sha1.sha1_update(&ctx.ctx_outside, ctx.block_opad[:]);
    mem.copy(&ctx.ctx_inside_reinit, &ctx.ctx_inside, size_of(sha1.SHA1_CTX));
    mem.copy(&ctx.ctx_outside_reinit, &ctx.ctx_outside, size_of(sha1.SHA1_CTX));
}

hmac_sha1_final :: proc(ctx: ^$T, mac: []byte) {
    digest_inside, mac_temp: [sha1.DIGEST_SIZE]byte;
    sha1.sha1_final(&ctx.ctx_inside, &digest_inside);
    sha1.sha1_update(&ctx.ctx_outside, digest_inside[:]);
    sha1.sha1_final(&ctx.ctx_outside, &mac_temp);
    copy(mac[:], mac_temp[:]);
}

sha1 :: proc(data, key: []byte) -> [sha1.DIGEST_SIZE]byte {
    mac: [sha1.DIGEST_SIZE]byte;
    ctx: HmacSha1;
    hmac_sha1_init(&ctx, key);
    sha1.sha1_update(&ctx.ctx_inside, data);
    hmac_sha1_final(&ctx, mac[:]);
    return mac;
}

/////////////////////////////
// MD5 HMAC
/////////////////////////////

import "../md5"

HmacMd5 :: struct {
    ctx_inside: md5.MD5_CTX,
    ctx_outside: md5.MD5_CTX,
    ctx_inside_reinit: md5.MD5_CTX,
    ctx_outside_reinit: md5.MD5_CTX,
    block_ipad: [md5.BLOCK_SIZE]byte,
    block_opad: [md5.BLOCK_SIZE]byte,
};

hmac_md5_init :: proc(ctx: ^$T, key: []byte) {
    fill, num: u32;
    key_size := u32(len(key));
    key_used := make([]byte, key_size);
    key_temp: [md5.DIGEST_SIZE]byte;

    if key_size == md5.BLOCK_SIZE {
        key_used = key;
        num = md5.BLOCK_SIZE;
    } else {
        if key_size > md5.BLOCK_SIZE {
            num = md5.DIGEST_SIZE;
            key_temp = md5.hash(key);
            copy(key_used[:], key_temp[:]);
        } else {
            copy(key_used[:], key[:]);
            num = key_size;
        }
        fill = md5.BLOCK_SIZE - num;
        mem.set(rawptr(&(ctx.block_ipad[num:])[0]), 0x36, int(fill));
        mem.set(rawptr(&(ctx.block_opad[num:])[0]), 0x5c, int(fill));
    }

    for i := 0; i < int(num); i += 1 {
        ctx.block_ipad[i] = key_used[i] ~ 0x36;
        ctx.block_opad[i] = key_used[i] ~ 0x5c;
    }

    md5.md5_init(&ctx.ctx_inside);
    md5.md5_update(&ctx.ctx_inside, ctx.block_ipad[:]);
    md5.md5_init(&ctx.ctx_outside);
    md5.md5_update(&ctx.ctx_outside, ctx.block_opad[:]);
    mem.copy(&ctx.ctx_inside_reinit, &ctx.ctx_inside, size_of(md5.MD5_CTX));
    mem.copy(&ctx.ctx_outside_reinit, &ctx.ctx_outside, size_of(md5.MD5_CTX));
}

hmac_md5_final :: proc(ctx: ^$T, mac: []byte) {
    digest_inside, mac_temp: [md5.DIGEST_SIZE]byte;
    md5.md5_final(&ctx.ctx_inside, &digest_inside);
    md5.md5_update(&ctx.ctx_outside, digest_inside[:]);
    md5.md5_final(&ctx.ctx_outside, &mac_temp);
    copy(mac[:], mac_temp[:]);
}

md5 :: proc(data, key: []byte) -> [md5.DIGEST_SIZE]byte {
    mac: [md5.DIGEST_SIZE]byte;
    ctx: HmacMd5;
    hmac_md5_init(&ctx, key);
    md5.md5_update(&ctx.ctx_inside, data);
    hmac_md5_final(&ctx, mac[:]);
    return mac;
}