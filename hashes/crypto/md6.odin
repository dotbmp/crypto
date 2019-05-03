package crypto

import "core:fmt"
import "core:mem"

// Ported from: http://groups.csail.mit.edu/cis/md6/code/md6_c_code-2009-04-15.zip

MD6_STATUS :: enum i32 {
    SUCCESS = 0,
    FAIL, 
    BADHASHLEN,
    NULLSTATE,
    BADKEYLEN,
    STATENOTINIT,
    STACKUNDERFLOW,
    STACKOVERFLOW,
    NULLDATA,
    NULL_N,
    NULL_B,
    BAD_ELL,
    BAD_p,
    NULL_K,
    NULL_Q,
    NULL_C,
    BAD_L,
    BAD_r,
    OUT_OF_MEMORY,
}

when !#defined(md6_w) {
    md6_w :: 64;
}

when md6_w == 64 {
    md6_word :: u64;
    md6_Q := [15]md6_word {
        0x7311c2812425cfa0,
        0x6432286434aac8e7, 
        0xb60450e9ef68b7c1, 
        0xe8fb23908d9f06f1, 
        0xdd2e76cba691e5bf, 
        0x0cd0d63b2c30bc41, 
        0x1f8ccf6823058f8a, 
        0x54e5ed5b88e3775d, 
        0x4ad12aae0a6d6031, 
        0x3e7f16bb88222e0d, 
        0x8af8671d3fb50c2c, 
        0x995ad1178bd25c31, 
        0xc878c1dd04c4b633, 
        0x3b72066c7a1552ac, 
        0x0d6f3522631effcb,
    };
} else
when md6_w == 32 {
    md6_word :: u32;
    md6_Q := [30]md6_word {
        0x7311c281, 0x2425cfa0,
        0x64322864, 0x34aac8e7, 
        0xb60450e9, 0xef68b7c1, 
        0xe8fb2390, 0x8d9f06f1, 
        0xdd2e76cb, 0xa691e5bf, 
        0x0cd0d63b, 0x2c30bc41, 
        0x1f8ccf68, 0x23058f8a, 
        0x54e5ed5b, 0x88e3775d, 
        0x4ad12aae, 0x0a6d6031, 
        0x3e7f16bb, 0x88222e0d, 
        0x8af8671d, 0x3fb50c2c, 
        0x995ad117, 0x8bd25c31, 
        0xc878c1dd, 0x04c4b633, 
        0x3b72066c, 0x7a1552ac, 
        0x0d6f3522, 0x631effcb, 
  };
} else
when md6_w == 16 {
    md6_word :: u16;
    md6_Q := [60]md6_word {
        0x7311, 0xc281, 0x2425, 0xcfa0,
        0x6432, 0x2864, 0x34aa, 0xc8e7, 
        0xb604, 0x50e9, 0xef68, 0xb7c1, 
        0xe8fb, 0x2390, 0x8d9f, 0x06f1, 
        0xdd2e, 0x76cb, 0xa691, 0xe5bf, 
        0x0cd0, 0xd63b, 0x2c30, 0xbc41, 
        0x1f8c, 0xcf68, 0x2305, 0x8f8a, 
        0x54e5, 0xed5b, 0x88e3, 0x775d, 
        0x4ad1, 0x2aae, 0x0a6d, 0x6031, 
        0x3e7f, 0x16bb, 0x8822, 0x2e0d, 
        0x8af8, 0x671d, 0x3fb5, 0x0c2c, 
        0x995a, 0xd117, 0x8bd2, 0x5c31, 
        0xc878, 0xc1dd, 0x04c4, 0xb633, 
        0x3b72, 0x066c, 0x7a15, 0x52ac, 
        0x0d6f, 0x3522, 0x631e, 0xffcb, 
  };
} else
when md6_w == 8 {
    md6_word :: u8;
    md6_Q := [120]md6_word {
        0x73, 0x11, 0xc2, 0x81, 0x24, 0x25, 0xcf, 0xa0,
        0x64, 0x32, 0x28, 0x64, 0x34, 0xaa, 0xc8, 0xe7, 
        0xb6, 0x04, 0x50, 0xe9, 0xef, 0x68, 0xb7, 0xc1, 
        0xe8, 0xfb, 0x23, 0x90, 0x8d, 0x9f, 0x06, 0xf1, 
        0xdd, 0x2e, 0x76, 0xcb, 0xa6, 0x91, 0xe5, 0xbf, 
        0x0c, 0xd0, 0xd6, 0x3b, 0x2c, 0x30, 0xbc, 0x41, 
        0x1f, 0x8c, 0xcf, 0x68, 0x23, 0x05, 0x8f, 0x8a, 
        0x54, 0xe5, 0xed, 0x5b, 0x88, 0xe3, 0x77, 0x5d, 
        0x4a, 0xd1, 0x2a, 0xae, 0x0a, 0x6d, 0x60, 0x31, 
        0x3e, 0x7f, 0x16, 0xbb, 0x88, 0x22, 0x2e, 0x0d, 
        0x8a, 0xf8, 0x67, 0x1d, 0x3f, 0xb5, 0x0c, 0x2c, 
        0x99, 0x5a, 0xd1, 0x17, 0x8b, 0xd2, 0x5c, 0x31, 
        0xc8, 0x78, 0xc1, 0xdd, 0x04, 0xc4, 0xb6, 0x33, 
        0x3b, 0x72, 0x06, 0x6c, 0x7a, 0x15, 0x52, 0xac, 
        0x0d, 0x6f, 0x35, 0x22, 0x63, 0x1e, 0xff, 0xcb, 
  };
}
else {
    #assert("Invalid md6_w size");
}

MD6_S0 : md6_word;
MD6_Smask : md6_word;

md6_n :: 89; 
md6_c :: 16;
md6_max_r :: 255;

md6_control_word :: u64;
md6_nodeID :: u64;

md6_q :: 15;
md6_k :: 8;
md6_u : i32 = (64 / md6_w);
md6_v : i32 = (64 / md6_w);
md6_b :: 64;
md6_default_L :: 64;
md6_max_stack_height :: 29;

md6_t0 :: 17;
md6_t1 :: 18;
md6_t2 :: 21;
md6_t3 :: 31;
md6_t4 :: 67;
md6_t5 :: 89;

MD6_LITTLE_ENDIAN : bool;
MD6_BIG_ENDIAN : bool;

md6_state :: struct {
    d : i32,
    hashbitlen : i32,
    hashval : []byte,
    hexhashval : []byte,
    initialized : i32,
    bits_processed : u64,
    compression_calls : u64,
    finalized : i32,
    K : [md6_k]md6_word,
    keylen : i32,
    L : i32,
    r : i32,
    top : i32,
    B : [md6_max_stack_height][md6_b]md6_word,
    bits : [md6_max_stack_height]i32,
    i_for_level : [md6_max_stack_height]i32,
}

md6_loop_body :: inline proc "contextless"(rs, ls, step, i : i32, A : []md6_word, S : md6_word) {
    x := S;
    x ~= A[i + step - md6_t5];                   
    x ~= A[i + step - md6_t0];                   
    x ~= A[i + step - md6_t1] & A[i + step - md6_t2]; 
    x ~= A[i + step - md6_t3] & A[i + step - md6_t4]; 
    x ~= (x >> u32(rs));                       
    A[i + step] = x ~ (x << u32(ls)); 
}

md6_loop_body_64 :: inline proc "contextless"(i : i32, A : []md6_word, S : md6_word) {
    md6_loop_body(10,11, 0, i, A[:], S);
    md6_loop_body( 5,24, 1, i, A[:], S);
    md6_loop_body(13, 9, 2, i, A[:], S);
    md6_loop_body(10,16, 3, i, A[:], S);
    md6_loop_body(11,15, 4, i, A[:], S);
    md6_loop_body(12, 9, 5, i, A[:], S);
    md6_loop_body( 2,27, 6, i, A[:], S);
    md6_loop_body( 7,15, 7, i, A[:], S);
    md6_loop_body(14, 6, 8, i, A[:], S);
    md6_loop_body(15, 2, 9, i, A[:], S);
    md6_loop_body( 7,29,10, i, A[:], S);
    md6_loop_body(13, 8,11, i, A[:], S);
    md6_loop_body(11,15,12, i, A[:], S);
    md6_loop_body( 7, 5,13, i, A[:], S);
    md6_loop_body( 6,31,14, i, A[:], S);
    md6_loop_body(12, 9,15, i, A[:], S);
}

md6_loop_body_32 :: inline proc "contextless"(i : i32, A : []md6_word, S : md6_word) {
    md6_loop_body( 5, 4, 0, i, A[:], S);
    md6_loop_body( 3, 7, 1, i, A[:], S);
    md6_loop_body( 6, 7, 2, i, A[:], S);
    md6_loop_body( 5, 9, 3, i, A[:], S);
    md6_loop_body( 4,13, 4, i, A[:], S);
    md6_loop_body( 6, 8, 5, i, A[:], S);
    md6_loop_body( 7, 4, 6, i, A[:], S);
    md6_loop_body( 3,14, 7, i, A[:], S);
    md6_loop_body( 5, 7, 8, i, A[:], S);
    md6_loop_body( 6, 4, 9, i, A[:], S);
    md6_loop_body( 5, 8,10, i, A[:], S);
    md6_loop_body( 5,11,11, i, A[:], S);
    md6_loop_body( 4, 5,12, i, A[:], S);
    md6_loop_body( 6, 8,13, i, A[:], S);
    md6_loop_body( 7, 2,14, i, A[:], S);
    md6_loop_body( 5,11,15, i, A[:], S);
}

md6_loop_body_16 :: inline proc "contextless"(i : i32, A : []md6_word, S : md6_word) {
    md6_loop_body( 5, 6, 0, i, A[:], S);
    md6_loop_body( 4, 7, 1, i, A[:], S);
    md6_loop_body( 3, 2, 2, i, A[:], S);
    md6_loop_body( 5, 4, 3, i, A[:], S);
    md6_loop_body( 7, 2, 4, i, A[:], S);
    md6_loop_body( 5, 6, 5, i, A[:], S);
    md6_loop_body( 5, 3, 6, i, A[:], S);
    md6_loop_body( 2, 7, 7, i, A[:], S);
    md6_loop_body( 4, 5, 8, i, A[:], S);
    md6_loop_body( 3, 7, 9, i, A[:], S);
    md6_loop_body( 4, 6,10, i, A[:], S);
    md6_loop_body( 3, 5,11, i, A[:], S);
    md6_loop_body( 4, 5,12, i, A[:], S);
    md6_loop_body( 7, 6,13, i, A[:], S);
    md6_loop_body( 7, 4,14, i, A[:], S);
    md6_loop_body( 2, 3,15, i, A[:], S);
}

md6_loop_body_8 :: inline proc "contextless"(i : i32, A : []md6_word, S : md6_word) {
    md6_loop_body( 3, 2, 0, i, A[:], S);
    md6_loop_body( 3, 4, 1, i, A[:], S);
    md6_loop_body( 3, 2, 2, i, A[:], S);
    md6_loop_body( 4, 3, 3, i, A[:], S);
    md6_loop_body( 3, 2, 4, i, A[:], S);
    md6_loop_body( 3, 2, 5, i, A[:], S);
    md6_loop_body( 3, 2, 6, i, A[:], S);
    md6_loop_body( 3, 4, 7, i, A[:], S);
    md6_loop_body( 2, 3, 8, i, A[:], S);
    md6_loop_body( 2, 3, 9, i, A[:], S);
    md6_loop_body( 3, 2,10, i, A[:], S);
    md6_loop_body( 2, 3,11, i, A[:], S);
    md6_loop_body( 2, 3,12, i, A[:], S);
    md6_loop_body( 3, 4,13, i, A[:], S);
    md6_loop_body( 2, 3,14, i, A[:], S);
    md6_loop_body( 3, 4,15, i, A[:], S);
}

md6_detect_byte_order :: inline proc "contextless"() {
    if ODIN_ENDIAN != "little" {
        MD6_BIG_ENDIAN = false;
        MD6_LITTLE_ENDIAN = true;
        
    } else {
        MD6_BIG_ENDIAN = true;
        MD6_LITTLE_ENDIAN = false;
    }
}

md6_reverse_little_endian :: inline proc "contextless" (x: []md6_word) {
    if MD6_LITTLE_ENDIAN {
        for i : i32 = 0; i < i32(len(x)); i += 1 {
            x[i] = md6_byte_reverse(x[i]);
        }
    }
}

md6_reverse_little_endian_byte :: inline proc "contextless" (x: []byte) {
    if MD6_LITTLE_ENDIAN {
        for i : i32 = 0; i < i32(len(x)); i += 1 {
            x[i] = md6_byte_reverse_byte(x[i]);
        }
    }
}

md6_byte_reverse :: inline proc "contextless"(x : md6_word) -> md6_word {

    mask8 : md6_word = 0x00ff00ff00ff00ff;
    mask16 : md6_word = 0x0000ffff0000ffff;

    if md6_w == 64 {
        x = (x << 32) | (x >> 32);
    } else if md6_w >= 32 {
        x = ((x & mask16) << 16) | ((x & ~mask16) >> 16);
    } else if md6_w > 16{
        x = ((x & mask8) << 8) | ((x & ~mask8) >> 8);
    }

    return x;
}

md6_byte_reverse_byte :: inline proc "contextless"(x : byte) -> byte {
    
    mask8 : md6_word = 0x00ff00ff00ff00ff;
    mask16 : md6_word = 0x0000ffff0000ffff;

    if md6_w == 64 {
        x = (x << 32) | (x >> 32);
    } else if md6_w >= 32 {
        x = ((x & u8(mask16)) << 16) | ((x & ~u8(mask16)) >> 16);
    } else if md6_w > 16{
        x = ((x & u8(mask8)) << 8) | ((x & ~u8(mask8)) >> 8);
    }

    return x;
}

md6_default_r :: inline proc "contextless" (d, keylen : i32) -> i32 {

    r : i32 = 40 + (d / 4);
    if keylen > 0 do r = max(80, r);

    return r;
}

md6_main_compression_loop :: proc(A : []md6_word, r : i32) {

    j, i : i32;

    S := MD6_S0;
    for j, i = 0, md6_n; j < r * md6_c; j += 1 {
        
        md6_loop_body_64(i, A[:], S);

        S = (S << 1) ~ (S >> (md6_w - 1)) ~ (S & MD6_Smask);
        i += 16;
    }

}

md6_compress :: proc(C, N : []md6_word, r : i32, A : []md6_word) -> MD6_STATUS {

    A_as_given := A;

    if N == nil do return MD6_STATUS.NULL_N;
    if C == nil do return MD6_STATUS.NULL_C;
    if (r < 0) | (r > md6_max_r) do return MD6_STATUS.BAD_r;

    //if ( A == NULL) A = calloc(r*c+n,sizeof(md6_word));
    //if ( A == NULL) return MD6_OUT_OF_MEMORY;

    //memcpy( A, N, n*sizeof(md6_word) );    /* copy N to front of A */

    md6_main_compression_loop(A[:], r);

    //memcpy( C, A+(r-1)*c+n, c*sizeof(md6_word) ); /* output into C */
    //if ( A_as_given == NULL )           /* zero and free A if nec. */
    //{ memset(A,0,(r*c+n)*sizeof(md6_word)); /* contains key info */
    //  free(A);           
    //}

    return MD6_STATUS.SUCCESS;
}

md6_make_control_word :: proc(r, L, z, p, keylen, d : i32) -> md6_control_word {
    return md6_control_word(0) << 60 | md6_control_word(r << 48) | md6_control_word(L) << 40 |
           md6_control_word(z) << 36 | md6_control_word(p << 20) | md6_control_word(keylen) << 12 |
           md6_control_word(d);
}

md6_make_nodeID :: proc(ell, i : i32) -> md6_nodeID {
    return (md6_nodeID(ell) << 56) | md6_nodeID(i);
}

md6_pack :: proc(N, Q, K : []md6_word, ell, i, r, L, z, p, keylen, d : i32, B : []md6_word) {

    j : i32;
    ni : i32 = 0;

    for j = 0; j < md6_q; i += 1 do N[ni] = Q[j]; ni += 1;
    for j = 0; j < md6_k; i += 1 do N[ni] = K[j]; ni += 1;

    U := md6_make_nodeID(ell, i);
    //  memcpy((unsigned char *)&N[ni], &U,min(u*(w/8),sizeof(md6_nodeID)));
    ni += md6_u;

    V := md6_make_control_word(r, L, z, p, keylen, d);
    //   memcpy((unsigned char *)&N[ni],&V, min(v*(w/8),sizeof(md6_control_word)));
    ni += md6_v;

    //memcpy(N+ni,B,b*sizeof(md6_word));      /* B: data words    25--88 */
}

md6_standard_compress :: proc(C, Q, K : []md6_word, ell, i, r, L, z, p, keylen, d : i32, B : []md6_word) -> MD6_STATUS {

    N : [md6_n]md6_word;
    A : [5000]md6_word;

    if C == nil do return MD6_STATUS.NULL_C;
    if B == nil do return MD6_STATUS.NULL_B;
    if (r < 0) | (r > md6_max_r) do return MD6_STATUS.BAD_r;
    if (L < 0) | (L > 255) do return MD6_STATUS.BAD_L;
    if ell < 0 || ell > 255 do return MD6_STATUS.BAD_ELL;
    if p < 0 || p > (md6_b * md6_w) do return MD6_STATUS.BAD_p;
    if d <= 0 || d > (md6_c * md6_w / 2) do return MD6_STATUS.BADHASHLEN;
    if K == nil do return MD6_STATUS.NULL_K;
    if Q == nil do return MD6_STATUS.NULL_Q;

    md6_pack(N[:], Q[:], K[:], ell, i, r, L, z, p, keylen, d, B[:]);

    /*
    if compression_hook != nil {
        compression_hook(C, Q, K, ell, i, r, L, z, p, keylen, d, B);
    } */

    return md6_compress(C[:], N[:], r, A[:]);
}

md6_init :: proc(st : ^md6_state, d : i32) -> MD6_STATUS {
    return md6_full_init(st, d, nil, 0, md6_default_L, md6_default_r(d,0));
}

md6_full_init :: proc(st : ^md6_state, d : i32, key : ^[]byte, keylen, L, r : i32) -> MD6_STATUS {

    if st == nil do return MD6_STATUS.NULLSTATE;
    if key != nil && (keylen < 0 || keylen > md6_k * (md6_w / 8)) do return MD6_STATUS.BADKEYLEN;
    if d < 1 || d > 512 || d > md6_w * md6_c / 2 do return MD6_STATUS.BADHASHLEN;

    md6_detect_byte_order();
    st^ = {};
    st.d = d;

    if key != nil && keylen > 0 {
        mem.copy(&st.K, key, int(keylen));
        //memcpy(st->K,key,keylen);  
        st.keylen = keylen;
        md6_reverse_little_endian(st.K[:]);
    } else {
        st.keylen = 0;
    }

    if (L < 0) | (L > 255) do return MD6_STATUS.BAD_L;
    if (r < 0) | (r > 255) do return MD6_STATUS.BAD_r;

    st.L = L;
    st.r = r;
    st.initialized = 1;  
    st.top = 1;

    if L == 0 do st.bits[1] = md6_c * md6_w;

    //compression_hook = nil;

    return MD6_STATUS.SUCCESS;
}

md6_trim_hashval :: proc(st : ^md6_state) {

    full_or_partial_bytes, bits : i32;

    full_or_partial_bytes = (st.d + 7) / 8;
    bits = st.d % 8;

    for i : i32 = 0; i < full_or_partial_bytes; i += 1 {
        st.hashval[i] = st.hashval[md6_c * (md6_w / 8) - full_or_partial_bytes + i];
    }

    for i : i32 = full_or_partial_bytes; i < md6_c * (md6_w / 8); i += 1 {
        st.hashval[i] = 0;
    }

    if bits > 0 {
        for i : i32 = 0; i < full_or_partial_bytes; i += 1 {
            st.hashval[i] = st.hashval[i] << (8 - u32(bits));
            if i + 1 < md6_c * (md6_w / 8) do st.hashval[i] |= st.hashval[i + 1] >> u32(bits);
        }
    }
}

md6_compute_hex_hashval :: proc(st : ^md6_state) -> MD6_STATUS{

    hex_digits : []byte = {0,1,2,3,4,5,6,7,8,9,'a','b','c','d','e','f'};

    if st == nil do return MD6_STATUS.NULLSTATE;

    for i : i32 = 0; i < (st.d + 7) / 8; i += 1 {
        st.hexhashval[2 * i] = hex_digits[(st.hashval[i] >> 4) & 0xf];
        st.hexhashval[2 * i + 1] = hex_digits[(st.hashval[i]) & 0xf];
    }

    st.hexhashval[(st.d + 3) / 4] = 0;

    return MD6_STATUS.SUCCESS;
}

md6_append_bits :: proc(dest : ^[md6_b]md6_word, destlen : i32 , src : []byte, srclen : i32) {

    if srclen == 0 do return;

    accum : u16 = 0;
    accumlen : i32 = 0;

    if destlen % 8 != 0 {
        accumlen = destlen % 8;
        accum = u16(dest[destlen / 8]);
        accum = accum >> (8 - u32(accumlen));
    }
    di : i32 = destlen / 8;

    srcbytes : i32 = (srclen + 7) / 8;
    for i : i32 = 0; i < srcbytes; i += 1 {
        if i != srcbytes - 1 {
            accum = (accum << 8) ~ u16(src[i]);  
	        accumlen += 8;
        } else {
            newbits : i32;
            if srclen % 8 == 0 {
                newbits = 8;
            } else {
                newbits = srclen % 8;
                accum = (u16(accum) << u16(newbits)) | (u16(src[i]) >> (8 - u16(newbits)));
                accumlen += newbits;
            } 
        }

        for (i != srcbytes - 1) & (accumlen >= 8) || (i == srcbytes - 1) & (accumlen > 0) {
            numbits : i32 = min(8, accumlen);
            bits : u8 = u8(accum) >> (u8(accumlen) - u8(numbits));
            bits = bits << (8 - u32(numbits));
            bits &= (0xff00 >> u32(numbits));
            dest[di] = u64(bits);
            di += 1;
            accumlen -= numbits; 
        }
    }
}

md6_compress_block :: proc(C : []md6_word, st : ^md6_state, ell, z : i32) -> MD6_STATUS {

    if st == nil do return MD6_STATUS.NULLSTATE;
    if st.initialized == 0 do return MD6_STATUS.STATENOTINIT;
    if ell < 0 do return MD6_STATUS.STACKUNDERFLOW;
    if ell >= md6_max_stack_height - 1 do return MD6_STATUS.STACKOVERFLOW;

    st.compression_calls += 1;

    if ell == 1 {
        if ell < st.L + 1 {
            md6_reverse_little_endian(st.B[ell][0:md6_b]);
        } else {
            md6_reverse_little_endian(st.B[ell][md6_c:md6_b]);
        }
    }

    p := md6_b * md6_w - st.bits[ell];

    err := md6_standard_compress(C[:], md6_Q[:], st.K[:], ell, st.i_for_level[ell], st.r, st.L, z, p, st.keylen, st.d, st.B[ell][:]); 
    if err != MD6_STATUS.SUCCESS do return MD6_STATUS.SUCCESS;

    st.bits[ell] = 0;
    st.i_for_level[ell] += 1;

    mem.set(&st.B[ell][0], 0, md6_b * size_of (md6_word));
    //memset(&(st->B[ell][0]),0,b*sizeof(md6_word)); 
    return MD6_STATUS.SUCCESS;
}

md6_process :: proc(st : ^md6_state, ell, final : i32) -> MD6_STATUS {

    err : MD6_STATUS;
    z, next_level : i32;
    C : [md6_c]md6_word;

    if st == nil do return MD6_STATUS.NULLSTATE;
    if st.initialized == 0 do return MD6_STATUS.STATENOTINIT;
    if final == 0 {
        if st.bits[ell] < (md6_b * md6_w) do return MD6_STATUS.SUCCESS;
    } else {
        if ell == st.top {
            if ell == (st.L + 1) {
                if st.bits[ell] == (md6_c * md6_w) && st.i_for_level[ell] > 0 {
                    return MD6_STATUS.SUCCESS;
                } else {
                    if ell > 1 && st.bits[ell] == (md6_c * md6_w) do return MD6_STATUS.SUCCESS;
                }
            }
        }
    }

    z = 0;
    if final != 0 && ell == st.top do z = 1;
    if err = md6_compress_block(C[:], st, ell, z); err != MD6_STATUS.SUCCESS do return err;
    if z == 1 {
        mem.copy(&st.hashval, &C, md6_c * (md6_w / 8));
        //memcpy( st->hashval, C, md6_c*(w/8) );
        return MD6_STATUS.SUCCESS;
    }

    next_level = min(ell + 1, st.L + 1);
    if next_level == st.L + 1 && st.i_for_level[next_level] == 0 {
        st.bits[next_level] = md6_c * md6_w;
       // memcpy((char *)st->B[next_level] + st->bits[next_level]/8, C, c*(w/8));
        st.bits[next_level] += md6_c * md6_w; 
    }
    if next_level > st.top do st.top = next_level;

    return md6_process(st, next_level, final);
}

md6_update :: proc(st : ^md6_state, data : ^[]byte, databitlen : u64) -> MD6_STATUS {

    if st == nil do return MD6_STATUS.NULLSTATE;
    if st.initialized == 0 do return MD6_STATUS.STATENOTINIT;
    if data == nil do return MD6_STATUS.NULLDATA;

    j : u64 = 0;
    for j < databitlen {
        
        portion_size := min(i32(databitlen - j), md6_b * md6_w - (st.bits[1])); 

        if (portion_size % 8 == 0) && (st.bits[1] % 8 == 0) && (j % 8 == 0) {
            //memcpy((char *)st->B[1] + st->bits[1]/8, &(data[j/8]), portion_size/8);
        } else {
            // append_bits((unsigned char *)st->B[1], st->bits[1], &(data[j/8]), portion_size); 
            // md6_append_bits(&st.B[1], st.bits[1], data[0:(j / 8)], portion_size);
        }

        j += u64(portion_size);
        st.bits[1] += portion_size;
        st.bits_processed += u64(portion_size);

        if (st.bits[1] == md6_b * md6_w) && (j < databitlen) {
            if err := md6_process(st, 1, 0); err != MD6_STATUS.SUCCESS do return err;
        }
    }

    return MD6_STATUS.SUCCESS;
}

md6_final :: proc(st : ^md6_state, hashval : ^[]byte) -> MD6_STATUS {

    ell : i32;

    if st == nil do return MD6_STATUS.NULLSTATE;
    if st.initialized == 0 do return MD6_STATUS.STATENOTINIT;
    if st.initialized == 1 do return MD6_STATUS.SUCCESS;
    if st.top == 1 {
        ell = 0;
    } else {
        for ell = 1; ell <= st.top; ell += 1 {
            if st.bits[ell] > 0 do break;
        }
    }

    if err := md6_process(st, ell, 1); err != MD6_STATUS.SUCCESS do return err;

    md6_reverse_little_endian_byte(st.hashval[:]);
    md6_trim_hashval(st);
    //if hashval != nil do memcpy( hashval, st->hashval, (st->d+7)/8 );

    md6_compute_hex_hashval(st);
    st.finalized = 1;

    return MD6_STATUS.SUCCESS;
}

md6_full_hash :: proc(d : i32, data : ^[]byte, databitlen : u64, key : ^[]byte, keylen, L, r : i32, hashval : ^[]byte) -> MD6_STATUS {
    
    st : md6_state;
    err: MD6_STATUS = ---;

    if err = md6_full_init(&st, d, key, keylen, L, r); err != MD6_STATUS.SUCCESS do return err;
    if err = md6_update(&st, data, databitlen); err != MD6_STATUS.SUCCESS do return err;
    if err = md6_final(&st, hashval); err != MD6_STATUS.SUCCESS do return err;

    return MD6_STATUS.SUCCESS;
}

md6_hash :: proc(d : i32, data : ^[]byte, hashval : ^[]byte) -> MD6_STATUS {

    if err := md6_full_hash(d, data, u64(len(data)), nil, 0, md6_default_L, md6_default_r(d, 0), hashval); err != MD6_STATUS.SUCCESS do return err;

    return MD6_STATUS.SUCCESS;
}

md6_128 :: proc(data: []byte) -> []byte {

    hash : []byte;

    md6_hash(128, &data, &hash);

    return hash;
}

md6_256 :: proc(data: []byte) -> []byte {

    hash : []byte;

    md6_hash(256, &data, &hash);

    return hash;
}

md6_512 :: proc(data: []byte) -> []byte {

    hash : []byte;

    md6_hash(512, &data, &hash);

    return hash;
}