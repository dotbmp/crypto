package crypto

// @ref(bp): https://github.com/tarequeh/DES

DES_PC1 := [?]byte {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
};

permute :: proc(key: u64) -> u64 {
    nkey: u64 = ---;
    for i :byte= 0; i < 8; i += 1 {
        nkey |= (key & (1 << DES_PC1[i*7+0])) >> (DES_PC1[i*7+0] - (i+0));
        nkey |= (key & (1 << DES_PC1[i*7+1])) >> (DES_PC1[i*7+1] - (i+1));
        nkey |= (key & (1 << DES_PC1[i*7+2])) >> (DES_PC1[i*7+2] - (i+2));
        nkey |= (key & (1 << DES_PC1[i*7+3])) >> (DES_PC1[i*7+3] - (i+3));
        nkey |= (key & (1 << DES_PC1[i*7+4])) >> (DES_PC1[i*7+4] - (i+4));
        nkey |= (key & (1 << DES_PC1[i*7+5])) >> (DES_PC1[i*7+5] - (i+5));
        nkey |= (key & (1 << DES_PC1[i*7+6])) >> (DES_PC1[i*7+6] - (i+6));
        //nkey |= (key & (1 << DES_PC1[i*7+7])) >> (DES_PC1[i*7+7] - (i+7));
    }
    return nkey;
}

import "core:fmt"

main :: proc() {
    fmt.printf("%b\n", permute(0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001));
}