package pbkdf2

import "core:mem"
import "../sha2"
import "../sha1"
import "../md5"
import "../hmac"

// @ref(zh): https://github.com/mycelium-com/pbkdf2/blob/master/src/pbkdf.c
// @ref(zh): https://tools.ietf.org/html/rfc2898

PBKDF2Sha1Ctx :: struct {
    password:   []byte,
    salt:       []byte,
    rounds:     int,
    key_length: int,
};

PBKDF2Sha256Ctx :: struct {
    password:   []byte,
    salt:       []byte,
    rounds:     int,
    key_length: int,
};

PBKDF2Sha512Ctx :: struct {
    password:   []byte,
    salt:       []byte,
    rounds:     int,
    key_length: int,
};

sha1 :: proc(password, salt: []byte, rounds, key_length: int, allocator := context.allocator) -> []byte {
    //@note(zh): Copy the inputs, because they could originate from a string and thus be in the readonly section
    pw := make([]byte, len(password), allocator); defer delete(pw); copy(pw[:], password[:]);
    sa := make([]byte, len(salt),     allocator); defer delete(sa); copy(sa[:], salt[:]);
    ctx := PBKDF2Sha1Ctx{pw, sa, rounds, key_length};
    return _derive_sha(&ctx, allocator);
}

sha256 :: proc(password, salt: []byte, rounds, key_length: int, allocator := context.allocator) -> []byte {
    //@note(zh): Copy the inputs, because they could originate from a string and thus be in the readonly section
    pw := make([]byte, len(password), allocator); defer delete(pw); copy(pw[:], password[:]);
    sa := make([]byte, len(salt),     allocator); defer delete(sa); copy(sa[:], salt[:]);
    ctx := PBKDF2Sha256Ctx{pw, sa, rounds, key_length};
    return _derive_sha(&ctx, allocator);
}

sha512 :: proc(password, salt: []byte, rounds, key_length: int, allocator := context.allocator) -> []byte {
    //@note(zh): Copy the inputs, because they could originate from a string and thus be in the readonly section
    pw := make([]byte, len(password), allocator); defer delete(pw); copy(pw[:], password[:]);
    sa := make([]byte, len(salt),     allocator); defer delete(sa); copy(sa[:], salt[:]);
    ctx := PBKDF2Sha512Ctx{pw, sa, rounds, key_length};
    return _derive_sha(&ctx, allocator);
}

_derive_sha :: proc(ctx: ^$T, allocator := context.allocator) -> []byte {
    buf := make([]byte, ctx.key_length, allocator);
    ivec: [4]byte;

    when T == PBKDF2Sha256Ctx {
        DIGEST_SIZE :: sha2.SHA256_DIGEST_SIZE;
        CTX_SIZE    :: size_of(hmac.HmacSha256);
        hctx0, hctx1: hmac.HmacSha256;
        U, TT: [DIGEST_SIZE]byte;
    } else when T == PBKDF2Sha512Ctx {
        DIGEST_SIZE :: sha2.SHA512_DIGEST_SIZE;
        CTX_SIZE    :: size_of(hmac.HmacSha512);
        hctx0, hctx1: hmac.HmacSha512;
        U, TT: [DIGEST_SIZE]byte;
    } else when T == PBKDF2Sha1Ctx {
        DIGEST_SIZE :: sha1.DIGEST_SIZE;
        CTX_SIZE    :: size_of(hmac.HmacSha1);
        hctx0, hctx1: hmac.HmacSha1;
        U, TT: [DIGEST_SIZE]byte;
    }

    when T == PBKDF2Sha256Ctx || T == PBKDF2Sha512Ctx {
        hmac.hmac_sha2_init(&hctx0, ctx.password[:]);
        sha2.sha2_update(&hctx0.ctx_inside, ctx.salt[:]);
    } else when T == PBKDF2Sha1Ctx {
        hmac.hmac_sha1_init(&hctx0, ctx.password[:]);
        sha1.sha1_update(&hctx0.ctx_inside, ctx.salt[:]);
    }

    for i := 0; i * DIGEST_SIZE < ctx.key_length; i += 1 {
        ivec[0] = byte((i + 1) >> 24) & 0xff;
        ivec[1] = byte((i + 1) >> 16) & 0xff;
        ivec[2] = byte((i + 1) >> 8)  & 0xff;
        ivec[3] = byte((i + 1))       & 0xff;

        mem.copy(&hctx1, &hctx0, CTX_SIZE);

        when T == PBKDF2Sha256Ctx || T == PBKDF2Sha512Ctx {
            sha2.sha2_update(&hctx1.ctx_inside, ivec[:]);
            hmac.hmac_sha2_final(&hctx1, U[:]);
        } else when T == PBKDF2Sha1Ctx {
            sha1.sha1_update(&hctx1.ctx_inside, ivec[:]);
            hmac.hmac_sha1_final(&hctx1, U[:]);
        }
        
        copy(TT[:], U[:]);
        for j := 2; j <= ctx.rounds; j += 1 {
            when T == PBKDF2Sha256Ctx || T == PBKDF2Sha512Ctx {
                hmac.hmac_sha2_init(&hctx1, ctx.password[:]);
                sha2.sha2_update(&hctx1.ctx_inside, U[:]);
                hmac.hmac_sha2_final(&hctx1, U[:]);
            } else when T == PBKDF2Sha1Ctx {
                hmac.hmac_sha1_init(&hctx1, ctx.password[:]);
                sha1.sha1_update(&hctx1.ctx_inside, U[:]);
                hmac.hmac_sha1_final(&hctx1, U[:]);
            }
            for k := 0; k < DIGEST_SIZE; k += 1 {
                TT[k] ~= U[k];
            }
        }
        clen := ctx.key_length - i * DIGEST_SIZE;
        if clen > DIGEST_SIZE do clen = DIGEST_SIZE;
        copy(buf[i * DIGEST_SIZE:], TT[:clen]);
    }
    return buf;
}