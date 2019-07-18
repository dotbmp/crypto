package bcrypt

// @ref(zh): https://github.com/rg3/libbcrypt
// reference implementation:
// @ref(bp): ./bcrypt-1.1.tar.gz

HASHSIZE :: 64;

gensalt :: proc(workfactor: int) -> [HASHSIZE]byte {
    salt: [HASHSIZE]byte;

    return salt;
}

hashpw :: proc(password: string, salt: [HASHSIZE]byte) -> [HASHSIZE]byte {
    hash: [HASHSIZE]byte;

    return hash;
}

checkpw :: proc(password, hash: string) -> bool {
    return false;
}