package crypto

// @ref(bp): https://github.com/mjosaarinen/tiny_sha3


KECCAKF_ROUNDS :: 24;

ROTL64 :: inline proc "contextless" (x, y: u64) -> u64 {
    return ((x << y) | (x >> (64 - y)));
}

Sha3_Context :: struct {
    st: struct #raw_union {
        b: [200]u8,
        q: [25]u64,
    },
    pt: i32,
    rsiz: i32,
    mdlen: i32,
}

sha3_keccakf :: proc "contextless" (st: ^[25]u64) {
    keccakf_rndc := [?]u64 {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };

    keccakf_rotc := [?]i32 {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44,
    };

    keccakf_piln := [?]i32 {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1,
    };

    i, j, r: i32 = ---, ---, ---;
    t: u64 = ---;
    bc: [5]u64 = ---;

    when ODIN_ENDIAN != "little" {
        v: uintptr = ---;
        for i = 0; i < 25; i += 1 {
            v := uintptr(&st[i]);
            st[i] = u64((^u8)(v + 0)^ << 0)  | u64((^u8)(v + 1)^ << 8)  |
                    u64((^u8)(v + 2)^ << 16) | u64((^u8)(v + 3)^ << 24) |
                    u64((^u8)(v + 4)^ << 32) | u64((^u8)(v + 5)^ << 40) |
                    u64((^u8)(v + 6)^ << 48) | u64((^u8)(v + 7)^ << 56);
        }
    }

    for r = 0; r < KECCAKF_ROUNDS; r += 1 {
        // theta
        for i = 0; i < 5; i += 1 {
            bc[i] = st[i] ~ st[i + 5] ~ st[i + 10] ~ st[i + 15] ~ st[i + 20];
        }

        for i = 0; i < 5; i += 1 {
            t = bc[(i + 4) % 5] ~ ROTL64(bc[(i + 1) % 5], 1);
            for j = 0; j < 25; j += 5 {
                st[j + i] ~= t;
            }
        }

        // rho pi
        t = st[1];
        for i = 0; i < 24; i += 1 {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, u64(keccakf_rotc[i]));
            t = bc[0];
        }

        // chi
        for j = 0; j < 25; j += 5 {
            for i = 0; i < 5; i += 1 {
                bc[i] = st[j + i];
            }
            for i = 0; i < 5; i += 1 {
                st[j + i] ~= ~bc[(i + 1) % 5] & bc[(i + 2) % 5];
            }
        }

        st[0] ~= keccakf_rndc[r];
    }

    when ODIN_ENDIAN != "little" {
        for i = 0; i < 25; i += 1 {
            v = uintptr(&st[i]);
            t = st[i];
            (^u8)(v+0)^ = (t >> 0)  & 0xFF;
            (^u8)(v+1)^ = (t >> 8)  & 0xFF;
            (^u8)(v+2)^ = (t >> 16) & 0xFF;
            (^u8)(v+3)^ = (t >> 24) & 0xFF;
            (^u8)(v+4)^ = (t >> 32) & 0xFF;
            (^u8)(v+5)^ = (t >> 40) & 0xFF;
            (^u8)(v+6)^ = (t >> 48) & 0xFF;
            (^u8)(v+7)^ = (t >> 56) & 0xFF;
        }
    }
}

sha3_init :: proc "contextless" (c: ^Sha3_Context, mdlen: i32) {
    for i: i32 = 0; i < 25; i += 1 {
        c.st.q[i] = 0;
    }

    c.mdlen = mdlen;
    c.rsiz  = 200 - 2 * mdlen;
    c.pt    = 0;
}

sha3_update :: proc "contextless" (c: ^Sha3_Context, data: []byte) {
    j := c.pt;
    for i := 0; i < len(data); i += 1 {
        c.st.b[j] ~= data[i];
        j += 1;
        if j >= c.rsiz {
            sha3_keccakf(&c.st.q);
            j = 0;
        }
    }
    c.pt = j;
}

sha3_final :: proc "contextless" (c: ^Sha3_Context, md: []byte) {
    c.st.b[c.pt]       ~= 0x06;
    c.st.b[c.rsiz - 1] ~= 0x80;
    sha3_keccakf(&c.st.q);

    for i: i32 = 0; i < c.mdlen; i += 1 {
        md[i] = c.st.b[i];
    }
}

sha3 :: proc "contextless" (input, md: []byte) -> []byte {
    sha3: Sha3_Context;
    inline sha3_init(&sha3, i32(len(md)));
    inline sha3_update(&sha3, input);
    inline sha3_final(&sha3, md);
    return md;
}

sha3_256 :: proc "contextless" (input: []byte) -> [32]byte {
    output: [32]byte = ---;
    sha3: Sha3_Context = ---;
    inline sha3_init(&sha3, 32);
    inline sha3_update(&sha3, input);
    inline sha3_final(&sha3, output[:]);
    return output;
}

sha3_512 :: proc "contextless" (input: []byte) -> [64]byte {
    output: [64]byte = ---;
    sha3: Sha3_Context = ---;
    inline sha3_init(&sha3, 64);
    inline sha3_update(&sha3, input);
    inline sha3_final(&sha3, output[:]);
    return output;
}

shake_xof :: proc "contextless" (c: ^Sha3_Context) {
    c.st.b[c.pt]       ~= 0x1F;
    c.st.b[c.rsiz - 1] ~= 0x80;
    sha3_keccakf(&c.st.q);
    c.pt = 0;
}

shake_out :: proc "contextless" (c: ^Sha3_Context, out: []byte) {
    j := c.pt;
    for i := 0; i < len(out); i += 1 {
        if j >= c.rsiz {
            sha3_keccakf(&c.st.q);
            j = 0;
        }
        out[i] = c.st.b[j];
        j += 1;
    }
    c.pt = j;
}


// @todo(bp): make an API to cover comparisons and file hashing that accepts hash functions as callbacks

import "core:os"
import "core:mem"

sha3_256_file :: proc(file_path: string) -> ([32]byte, bool) {
    bytes, ok := os.read_entire_file(file_path);
    if !ok do return ---, false;
    defer delete(bytes);

    return sha3_256(bytes), true;
}

sha3_512_file :: proc(file_path: string) -> ([64]byte, bool) {
    bytes, ok := os.read_entire_file(file_path);
    if !ok do return ---, false;
    defer delete(bytes);

    return sha3_512(bytes), true;
}


sha3_256_compare :: proc(a, b: []byte) -> bool {
    if len(a) != len(b) || len(a) == 0 do return false;
    chk1 := sha3_256(a);
    chk2 := sha3_256(b);
    return mem.compare(chk1[:], chk2[:]) == 0;
}

sha3_512_compare :: proc(a, b: []byte) -> bool {
    if len(a) != len(b) || len(a) == 0 do return false;
    chk1 := sha3_512(a);
    chk2 := sha3_512(b);
    return mem.compare(chk1[:], chk2[:]) == 0;
}


sha3_256_file_compare :: proc(a, b: string) -> bool {
    if len(a) != len(b) || len(a) == 0 do return false;
    chk1, ok1 := sha3_256_file(a);
    chk2, ok2 := sha3_256_file(b);
    if !ok1 || !ok2 do return false;
    return mem.compare(chk1[:], chk2[:]) == 0;
}

sha3_512_file_compare :: proc(a, b: string) -> bool {
    if len(a) != len(b) || len(a) == 0 do return false;
    chk1, ok1 := sha3_512_file(a);
    chk2, ok2 := sha3_512_file(b);
    if !ok1 || !ok2 do return false;
    return mem.compare(chk1[:], chk2[:]) == 0;
}


sha3_256_checksum :: inline proc(input: []byte, allocator := context.temp_allocator) -> string {
    chk := sha3_256(input);
    return hex_string(chk[:], allocator);
}

sha3_512_checksum :: inline proc(input: []byte, allocator := context.temp_allocator) -> string {
    chk := sha3_512(input);
    return hex_string(chk[:], allocator);
}


sha3_256_file_checksum :: inline proc(file_path: string, allocator := context.temp_allocator) -> (string, bool) {
    chk, ok := sha3_256_file(file_path);
    if !ok do return ---, false;
    return hex_string(chk[:], allocator), true;
}

sha3_512_file_checksum :: inline proc(file_path: string, allocator := context.temp_allocator) -> (string, bool) {
    chk, ok := sha3_512_file(file_path);
    if !ok do return ---, false;
    return hex_string(chk[:], allocator), true;
}


// @todo(bp): make a separate package for encodings

hex_string :: proc(bytes: []byte, allocator := context.temp_allocator) -> string {
    lut: [16]byte = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    buf := make([]byte, len(bytes)*2, allocator);
    for i: i32 = 0; i < i32(len(bytes)); i += 1 {
        buf[i*2+0] = lut[bytes[i] >> 4 & 0xF];
        buf[i*2+1] = lut[bytes[i]      & 0xF];
    }
    return string(buf);
}

unhex_string :: proc(str: string, allocator := context.temp_allocator) -> []byte {
    buf := make([]byte, len(str)/2, allocator);
    for i: i32 = 0; i < i32(len(buf)); i += 1 {
        c1 := str[i*2+0];
        c2 := str[i*2+1];
        switch {
        case c1 >= '0' && c1 <= '9': buf[i] = c1 - '0';
        case c1 >= 'A' && c1 <= 'F': buf[i] = c1 - 'A' + 10;
        case c1 >= 'a' && c1 <= 'f': buf[i] = c1 - 'a' + 10;
        }
        buf[i] <<= 4;
        switch {
        case c2 >= '0' && c2 <= '9': buf[i] |= c2 - '0';
        case c2 >= 'A' && c2 <= 'F': buf[i] |= c2 - 'A' + 10;
        case c2 >= 'a' && c2 <= 'f': buf[i] |= c2 - 'a' + 10;
        }
    }
    return buf;
}

unhex_string_buf :: proc(str: string, buf: ^[$N]byte) -> int {
    assert(len(str)/2 <= N);
    for i: i32 = 0; i < i32(len(buf)); i += 1 {
        c1 := str[i*2+0];
        c2 := str[i*2+1];
        switch {
        case c1 >= '0' && c1 <= '9': buf[i] = c1 - '0';
        case c1 >= 'A' && c1 <= 'F': buf[i] = c1 - 'A' + 10;
        case c1 >= 'a' && c1 <= 'f': buf[i] = c1 - 'a' + 10;
        }
        buf[i] <<= 4;
        switch {
        case c2 >= '0' && c2 <= '9': buf[i] |= c2 - '0';
        case c2 >= 'A' && c2 <= 'F': buf[i] |= c2 - 'A' + 10;
        case c2 >= 'a' && c2 <= 'f': buf[i] |= c2 - 'a' + 10;
        }
    }
    return len(str)/2;
}
