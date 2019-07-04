package test_encryption

import "core:fmt"
using import "../crypto/blowfish"

hex_string :: proc(bytes: []byte, allocator := context.temp_allocator) -> string {
    lut: [16]byte = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    buf := make([]byte, len(bytes)*2, allocator);
    for i: i32 = 0; i < i32(len(bytes)); i += 1 {
        buf[i*2+0] = lut[bytes[i] >> 4 & 0xF];
        buf[i*2+1] = lut[bytes[i]      & 0xF];
    }
    return string(buf);
}

main :: proc() {
    L := u64(1);
    R := u64(2);

    ctx: BLOWFISH;

    blowfish_init(&ctx, ([]byte)("TESTKEY"));
    blowfish_encrypt(&ctx, &L, &R);
    fmt.printf("%08x %08x\n", L, R);
    if L == 0xdf333fd2 && R == 0x30a71bb4 {
        fmt.println("Yeaa");
    } else {
        fmt.println("fuck");
    }

    blowfish_decrypt(&ctx, &L, &R);
    if L == 1 && R == 2 {
        fmt.println("Yeaa");
    } else {
        fmt.println("fuck");
    }
}