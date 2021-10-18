//+ignore
package util

/*
    Copyright 2021 zhibog
    Made available under the BSD-2 license.

    List of contributors:
        zhibog: Initial creation.
        dotbmp: String hex implementation.

    Utilities for testing the crypto library.
*/

TestHash :: struct {
    hash: string,
    str:  string,
}

TestMac :: struct {
    mac: string,
    str: string,
    key: string,
}

hex_string :: proc(bytes: []byte, allocator := context.temp_allocator) -> string {
    lut: [16]byte = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
    buf := make([]byte, len(bytes) * 2, allocator)
    for i := 0; i < len(bytes); i += 1 {
        buf[i * 2 + 0] = lut[bytes[i] >> 4 & 0xf]
        buf[i * 2 + 1] = lut[bytes[i]      & 0xf]
    }
    return string(buf)
}

check_hash :: #force_inline proc "contextless" (computed, hash: string) -> bool {
    if computed != hash {
        return false
    }
    return true
}
