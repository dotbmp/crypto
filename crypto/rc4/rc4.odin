package rc4

import "../util"

// @ref(zh): https://gist.github.com/rverton/a44fc8ca67ab9ec32089

N :: 256;

ksa :: proc(key, S: []byte) {
    key_len := len(key);
    for i := 0; i < N; i += 1 do S[i] = u8(i);
    j := 0;
    for i := 0; i < N; i += 1 {
        j = (j + int(S[i]) + int(key[i % key_len])) % N;
        tmp := S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
}

prga :: proc(S, plaintext, ciphertext: []byte) {
    i, j := 0, 0;
    msg_len := len(plaintext);
    for n := 0; n < msg_len; n += 1 {
        i = (i + 1) % N;
        j = (j + int(S[i])) % N;
        tmp := S[i];
        S[i] = S[j];
        S[j] = tmp;
        rnd := S[int((S[i] + S[j])) % N];
        ciphertext[n] = rnd ~ plaintext[n];
    }
}

encrypt :: proc(key, plaintext: []byte) -> []byte {
    ciphertext := make([]byte, len(plaintext));
    S: [N]byte;
    ksa(key, S[:]);
    prga(S[:], plaintext, ciphertext);
    return ciphertext;
}

decrypt :: proc(key, ciphertext: []byte) -> []byte {
    plaintext := make([]byte, len(ciphertext));
    S: [N]byte;
    ksa(key, S[:]);
    prga(S[:], ciphertext, plaintext);
    return plaintext;
}