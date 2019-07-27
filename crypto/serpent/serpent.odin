package serpent

// @ref(zh): https://github.com/aead/serpent

BLOCK_SIZE :: 16;
PHI :: 0x9e3779b9;

linear :: inline proc "contextless"(v0, v1, v2, v3: u32) -> (u32, u32, u32, u32) {
	v0, v1, v2, v3 := v0, v1, v2, v3;
    t0 := ((v0 << 13) | (v0 >> (32 - 13)));
	t2 := ((v2 << 3) | (v2 >> (32 - 3)));
	t1 := v1 ~ t0 ~ t2;
	t3 := v3 ~ t2 ~ (t0 << 3);
	v1 = (t1 << 1) | (t1 >> (32 - 1));
	v3 = (t3 << 7) | (t3 >> (32 - 7));
	t0 ~= v1 ~ v3;
	t2 ~= v3 ~ (v1 << 7);
	v0 = (t0 << 5) | (t0 >> (32 - 5));
	v2 = (t2 << 22) | (t2 >> (32 - 22));
    return v0, v1, v2, v3;
}

linear_inv :: inline proc "contextless"(v0, v1, v2, v3: u32) -> (u32, u32, u32, u32) {
	v0, v1, v2, v3 := v0, v1, v2, v3;
	t2 := (v2 >> 22) | (v2 << (32 - 22));
	t0 := (v0 >> 5) | (v0 << (32 - 5));
	t2 ~= v3 ~ (v1 << 7);
	t0 ~= v1 ~ v3;
	t3 := (v3 >> 7) | (v3 << (32 - 7));
	t1 := (v1 >> 1) | (v1 << (32 - 1));
	v3 = t3 ~ t2 ~ (t0 << 3);
	v1 = t1 ~ t0 ~ t2;
	v2 = (t2 >> 3) | (t2 << (32 - 3));
	v0 = (t0 >> 13) | (t0 << (32 - 13));
    return v0, v1, v2, v3;
}

sb0 :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	t0 := r0 ~ r3;
	t1 := r2 ~ t0;
	t2 := r1 ~ t1;
	r3 = (r0 & r3) ~ t2;
	t3 := r0 ~ (r1 & t0);
	r2 = t2 ~ (r2 | t3);
	t4 := r3 & (t1 ~ t3);
	r1 = (~t1) ~ t4;
	r0 = t4 ~ (~t3);
    return r0, r1, r2, r3;
}

sb0_inv :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	t0 := ~(r0);
	t1 := r0 ~ r1;
	t2 := r3 ~ (t0 | t1);
	t3 := r2 ~ t2;
	r2 = t1 ~ t3;
	t4 := t0 ~ (r3 & t1);
	r1 = t2 ~ (r2 & t4);
	r3 = (r0 & t2) ~ (t3 | r1);
	r0 = r3 ~ (t3 ~ t4);
    return r0, r1, r2, r3;
}

sb1 :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	t0 := r1 ~ (~(r0));
	t1 := r2 ~ (r0 | t0);
	r2 = r3 ~ t1;
	t2 := r1 ~ (r3 | t0);
	t3 := t0 ~ r2;
	r3 = t3 ~ (t1 & t2);
	t4 := t1 ~ t2;
	r1 = r3 ~ t4;
	r0 = t1 ~ (t3 & t4);
    return r0, r1, r2, r3;
}

sb1_inv :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	t0 := r1 ~ r3;
	t1 := r0 ~ (r1 & t0);
	t2 := t0 ~ t1;
	r3 = r2 ~ t2;
	t3 := r1 ~ (t0 & t1);
	t4 := r3 | t3;
	r1 = t1 ~ t4;
	t5 := ~(r1);
	t6 := r3 ~ t3;
	r0 = t5 ~ t6;
	r2 = t2 ~ (t5 | t6);
    return r0, r1, r2, r3;
}

sb2 :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v0 := r0;
	v3 := r3;
	t0 := ~v0;
	t1 := r1 ~ v3;
	t2 := r2 & t0;
	r0 = t1 ~ t2;
	t3 := r2 ~ t0;
	t4 := r2 ~ r0;
	t5 := r1 & t4;
	r3 = t3 ~ t5;
	r2 = v0 ~ ((v3 | t5) & (r0 | t3));
	r1 = (t1 ~ r3) ~ (r2 ~ (v3 | t0));
    return r0, r1, r2, r3;
}

sb2_inv :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v0 := r0;
	v3 := r3;
	t0 := r1 ~ v3;
	t1 := ~t0;
	t2 := v0 ~ r2;
	t3 := r2 ~ t0;
	t4 := r1 & t3;
	r0 = t2 ~ t4;
	t5 := v0 | t1;
	t6 := v3 ~ t5;
	t7 := t2 | t6;
	r3 = t0 ~ t7;
	t8 := ~t3;
	t9 := r0 | r3;
	r1 = t8 ~ t9;
	r2 = (v3 & t8) ~ (t2 ~ t9);
    return r0, r1, r2, r3;
}

sb3 :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v1 := r1 ;
	v3 := r3 ;
	t0 := r0 ~ r1;
	t1 := r0 & r2;
	t2 := r0 | r3;
	t3 := r2 ~ r3;
	t4 := t0 & t2;
	t5 := t1 | t4;
	r2 = t3 ~ t5;
	t6 := r1 ~ t2;
	t7 := t5 ~ t6;
	t8 := t3 & t7;
	r0 = t0 ~ t8;
	t9 := r2 & r0;
	r1 = t7 ~ t9;
	r3 = (v1 | v3) ~ (t3 ~ t9);
    return r0, r1, r2, r3;
}

sb3_inv :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	t0 := r0 | r1;
	t1 := r1 ~ r2;
	t2 := r1 & t1;
	t3 := r0 ~ t2;
	t4 := r2 ~ t3;
	t5 := r3 | t3;
	r0 = t1 ~ t5;
	t6 := t1 | t5;
	t7 := r3 ~ t6;
	r2 = t4 ~ t7;
	t8 := t0 ~ t7;
	t9 := r0 & t8;
	r3 = t3 ~ t9;
	r1 = r3 ~ (r0 ~ t8);
    return r0, r1, r2, r3;
}

sb4 :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v0 := r0;
	t0 := v0 ~ r3;
	t1 := r3 & t0;
	t2 := r2 ~ t1;
	t3 := r1 | t2;
	r3 = t0 ~ t3;
	t4 := ~(r1);
	t5 := t0 | t4;
	r0 = t2 ~ t5;
	t6 := v0 & r0;
	t7 := t0 ~ t4;
	t8 := t3 & t7;
	r2 = t6 ~ t8;
	r1 = (v0 ~ t2) ~ (t7 & r2);
    return r0, r1, r2, r3;
}

sb4_inv :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v3 := r3 ;
	t0 := r2 | v3;
	t1 := r0 & t0;
	t2 := r1 ~ t1;
	t3 := r0 & t2;
	t4 := r2 ~ t3;
	r1 = v3 ~ t4;
	t5 := ~(r0);
	t6 := t4 & r1;
	r3 = t2 ~ t6;
	t7 := r1 | t5;
	t8 := v3 ~ t7;
	r0 = r3 ~ t8;
	r2 = (t2 & t8) ~ (r1 ~ t5);
    return r0, r1, r2, r3;
}

sb5 :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v1 := r1 ;
	t0 := ~(r0);
	t1 := r0 ~ v1;
	t2 := r0 ~ r3;
	t3 := r2 ~ t0;
	t4 := t1 | t2;
	r0 = t3 ~ t4;
	t5 := r3 & r0;
	t6 := t1 ~ r0;
	r1 = t5 ~ t6;
	t7 := t0 | r0;
	t8 := t1 | t5;
	t9 := t2 ~ t7;
	r2 = t8 ~ t9;
	r3 = (v1 ~ t5) ~ (r1 & t9);
    return r0, r1, r2, r3;
}

sb5_inv :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v0 := r0 ;
	v1 := r1 ;
	v3 := r3 ;
	t0 := ~(r2);
	t1 := v1 & t0;
	t2 := v3 ~ t1;
	t3 := v0 & t2;
	t4 := v1 ~ t0;
	r3 = t3 ~ t4;
	t5 := v1 | r3;
	t6 := v0 & t5;
	r1 = t2 ~ t6;
	t7 := v0 | v3;
	t8 := t0 ~ t5;
	r0 = t7 ~ t8;
	r2 = (v1 & t7) ~ (t3 | (v0 ~ r2));
    return r0, r1, r2, r3;
}

sb6 :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	t0 := ~(r0);
	t1 := r0 ~ r3;
	t2 := r1 ~ t1;
	t3 := t0 | t1;
	t4 := r2 ~ t3;
	r1 = r1 ~ t4;
	t5 := t1 | r1;
	t6 := r3 ~ t5;
	t7 := t4 & t6;
	r2 = t2 ~ t7;
	t8 := t4 ~ t6;
	r0 = r2 ~ t8;
	r3 = (~t4) ~ (t2 & t8);
    return r0, r1, r2, r3;
}

sb6_inv :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v1 := r1;
	v3 := r3;
	t0 := ~(r0);
	t1 := r0 ~ v1;
	t2 := r2 ~ t1;
	t3 := r2 | t0;
	t4 := v3 ~ t3;
	r1 = t2 ~ t4;
	t5 := t2 & t4;
	t6 := t1 ~ t5;
	t7 := v1 | t6;
	r3 = t4 ~ t7;
	t8 := v1 | r3;
	r0 = t6 ~ t8;
	r2 = (v3 & t0) ~ (t2 ~ t8);
    return r0, r1, r2, r3;
}

sb7 :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	t0 := r1 ~ r2;
	t1 := r2 & t0;
	t2 := r3 ~ t1;
	t3 := r0 ~ t2;
	t4 := r3 | t0;
	t5 := t3 & t4;
	r1 = r1 ~ t5;
	t6 := t2 | r1;
	t7 := r0 & t3;
	r3 = t0 ~ t7;
	t8 := t3 ~ t6;
	t9 := r3 & t8;
	r2 = t2 ~ t9;
	r0 = (~t8) ~ (r3 & r2);
    return r0, r1, r2, r3;
}

sb7_inv :: inline proc "contextless"(r0, r1, r2, r3: u32) -> (u32, u32, u32, u32) {
	r0, r1, r2, r3 := r0, r1, r2, r3;
	v0 := r0;
	v3 := r3;
	t0 := r2 | (v0 & r1);
	t1 := v3 & (v0 | r1);
	r3 = t0 ~ t1;
	t2 := ~v3;
	t3 := r1 ~ t1;
	t4 := t3 | (r3 ~ t2);
	r1 = v0 ~ t4;
	r0 = (r2 ~ t3) ~ (v3 | r1);
	r2 = (t0 ~ r1) ~ (r0 ~ (v0 & r3));
    return r0, r1, r2, r3;
}

key_schedule :: proc(key: []byte) -> [132]u32 {
    s: [132]u32;

    k: [16]u32;
    j := 0;
    for i := 0; i + 4 <= len(key); i += 4 {
        k[j] = u32(key[i]) | u32(key[i + 1]) << 8 | u32(key[i + 2]) << 16 | u32(key[i + 3]) << 24;
        j += 1;
    }

    if j < 8 do k[j] = 1;
    
    for i := 8; i < 16; i += 1 {
        x := k[i - 8] ~ k[i - 5] ~ k[i - 3] ~ k[i - 1] ~ PHI ~ u32(i - 8);
		k[i] = (x << 11) | (x >> 21);
		s[i - 8] = k[i];
    }
    
    for i := 8; i < 132; i += 1 {
        x := s[i - 8] ~ s[i - 5] ~ s[i - 3] ~ s[i - 1] ~ PHI ~ u32(i);
		s[i] = (x << 11) | (x >> 21);
    }
    
    s[0], s[1], s[2], s[3]     = sb3(s[0], s[1], s[2], s[3]);
    s[4], s[5], s[6], s[7]     = sb2(s[4], s[5], s[6], s[7]);
    s[8], s[9], s[10], s[11]   = sb1(s[8], s[9], s[10], s[11]);
    s[12], s[13], s[14], s[15] = sb0(s[12], s[13], s[14], s[15]);
    s[16], s[17], s[18], s[19] = sb7(s[16], s[17], s[18], s[19]);
    s[20], s[21], s[22], s[23] = sb6(s[20], s[21], s[22], s[23]);
    s[24], s[25], s[26], s[27] = sb5(s[24], s[25], s[26], s[27]);
    s[28], s[29], s[30], s[31] = sb4(s[28], s[29], s[30], s[31]);

    s[32], s[33], s[34], s[35] = sb3(s[32], s[33], s[34], s[35]);
    s[36], s[37], s[38], s[39] = sb2(s[36], s[37], s[38], s[39]);
    s[40], s[41], s[42], s[43] = sb1(s[40], s[41], s[42], s[43]);
    s[44], s[45], s[46], s[47] = sb0(s[44], s[45], s[46], s[47]);
    s[48], s[49], s[50], s[51] = sb7(s[48], s[49], s[50], s[51]);
    s[52], s[53], s[54], s[55] = sb6(s[52], s[53], s[54], s[55]);
    s[56], s[57], s[58], s[59] = sb5(s[56], s[57], s[58], s[59]);
    s[60], s[61], s[62], s[63] = sb4(s[60], s[61], s[62], s[63]);

    s[64], s[65], s[66], s[67] = sb3(s[64], s[65], s[66], s[67]);
    s[68], s[69], s[70], s[71] = sb2(s[68], s[69], s[70], s[71]);
    s[72], s[73], s[74], s[75] = sb1(s[72], s[73], s[74], s[75]);
    s[76], s[77], s[78], s[79] = sb0(s[76], s[77], s[78], s[79]);
    s[80], s[81], s[82], s[83] = sb7(s[80], s[81], s[82], s[83]);
    s[84], s[85], s[86], s[87] = sb6(s[84], s[85], s[86], s[87]);
    s[88], s[89], s[90], s[91] = sb5(s[88], s[89], s[90], s[91]);
    s[92], s[93], s[94], s[95] = sb4(s[92], s[93], s[94], s[95]);

    s[96], s[97], s[98], s[99]     = sb3(s[96], s[97], s[98], s[99]);
    s[100], s[101], s[102], s[103] = sb2(s[100], s[101], s[102], s[103]);
    s[104], s[105], s[106], s[107] = sb1(s[104], s[105], s[106], s[107]);
    s[108], s[109], s[110], s[111] = sb0(s[108], s[109], s[110], s[111]);
    s[112], s[113], s[114], s[115] = sb7(s[112], s[113], s[114], s[115]);
    s[116], s[117], s[118], s[119] = sb6(s[116], s[117], s[118], s[119]);
    s[120], s[121], s[122], s[123] = sb5(s[120], s[121], s[122], s[123]);
    s[124], s[125], s[126], s[127] = sb4(s[124], s[125], s[126], s[127]);

    s[128], s[129], s[130], s[131] = sb3(s[128], s[129], s[130], s[131]);

    return s;
}

encrypt :: proc(key, plaintext: []byte) -> []byte {
    sk := key_schedule(key);

	r0 := u32(plaintext[0])  | u32(plaintext[1]) << 8  | u32(plaintext[2]) << 16  | u32(plaintext[3]) << 24;
	r1 := u32(plaintext[4])  | u32(plaintext[5]) << 8  | u32(plaintext[6]) << 16  | u32(plaintext[7]) << 24;
	r2 := u32(plaintext[8])  | u32(plaintext[9]) << 8  | u32(plaintext[10]) << 16 | u32(plaintext[11]) << 24;
	r3 := u32(plaintext[12]) | u32(plaintext[13]) << 8 | u32(plaintext[14]) << 16 | u32(plaintext[15]) << 24;

    r0, r1, r2, r3 = r0 ~ sk[0], r1 ~ sk[1], r2 ~ sk[2], r3 ~ sk[3];
	r0, r1, r2, r3 = sb0(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[4], r1 ~ sk[5], r2 ~ sk[6], r3 ~ sk[7];
	r0, r1, r2, r3 = sb1(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[8], r1 ~ sk[9], r2 ~ sk[10], r3 ~ sk[11];
	r0, r1, r2, r3 = sb2(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[12], r1 ~ sk[13], r2 ~ sk[14], r3 ~ sk[15];
	r0, r1, r2, r3 = sb3(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[16], r1 ~ sk[17], r2 ~ sk[18], r3 ~ sk[19];
	r0, r1, r2, r3 = sb4(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[20], r1 ~ sk[21], r2 ~ sk[22], r3 ~ sk[23];
	r0, r1, r2, r3 = sb5(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[24], r1 ~ sk[25], r2 ~ sk[26], r3 ~ sk[27];
	r0, r1, r2, r3 = sb6(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[28], r1 ~ sk[29], r2 ~ sk[30], r3 ~ sk[31];
	r0, r1, r2, r3 = sb7(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);

	r0, r1, r2, r3 = r0 ~ sk[32], r1 ~ sk[33], r2 ~ sk[34], r3 ~ sk[35];
	r0, r1, r2, r3 = sb0(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[36], r1 ~ sk[37], r2 ~ sk[38], r3 ~ sk[39];
	r0, r1, r2, r3 = sb1(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[40], r1 ~ sk[41], r2 ~ sk[42], r3 ~ sk[43];
	r0, r1, r2, r3 = sb2(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[44], r1 ~ sk[45], r2 ~ sk[46], r3 ~ sk[47];
	r0, r1, r2, r3 = sb3(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[48], r1 ~ sk[49], r2 ~ sk[50], r3 ~ sk[51];
	r0, r1, r2, r3 = sb4(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[52], r1 ~ sk[53], r2 ~ sk[54], r3 ~ sk[55];
	r0, r1, r2, r3 = sb5(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[56], r1 ~ sk[57], r2 ~ sk[58], r3 ~ sk[59];
	r0, r1, r2, r3 = sb6(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[60], r1 ~ sk[61], r2 ~ sk[62], r3 ~ sk[63];
	r0, r1, r2, r3 = sb7(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);

	r0, r1, r2, r3 = r0 ~ sk[64], r1 ~ sk[65], r2 ~ sk[66], r3 ~ sk[67];
	r0, r1, r2, r3 = sb0(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[68], r1 ~ sk[69], r2 ~ sk[70], r3 ~ sk[71];
	r0, r1, r2, r3 = sb1(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[72], r1 ~ sk[73], r2 ~ sk[74], r3 ~ sk[75];
	r0, r1, r2, r3 = sb2(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[76], r1 ~ sk[77], r2 ~ sk[78], r3 ~ sk[79];
	r0, r1, r2, r3 = sb3(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[80], r1 ~ sk[81], r2 ~ sk[82], r3 ~ sk[83];
	r0, r1, r2, r3 = sb4(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[84], r1 ~ sk[85], r2 ~ sk[86], r3 ~ sk[87];
	r0, r1, r2, r3 = sb5(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[88], r1 ~ sk[89], r2 ~ sk[90], r3 ~ sk[91];
	r0, r1, r2, r3 = sb6(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[92], r1 ~ sk[93], r2 ~ sk[94], r3 ~ sk[95];
	r0, r1, r2, r3 = sb7(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);

	r0, r1, r2, r3 = r0 ~ sk[96], r1 ~ sk[97], r2 ~ sk[98], r3 ~ sk[99];
	r0, r1, r2, r3 = sb0(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[100], r1 ~ sk[101], r2 ~ sk[102], r3 ~ sk[103];
	r0, r1, r2, r3 = sb1(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[104], r1 ~ sk[105], r2 ~ sk[106], r3 ~ sk[107];
	r0, r1, r2, r3 = sb2(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[108], r1 ~ sk[109], r2 ~ sk[110], r3 ~ sk[111];
	r0, r1, r2, r3 = sb3(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[112], r1 ~ sk[113], r2 ~ sk[114], r3 ~ sk[115];
	r0, r1, r2, r3 = sb4(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[116], r1 ~ sk[117], r2 ~ sk[118], r3 ~ sk[119];
	r0, r1, r2, r3 = sb5(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[120], r1 ~ sk[121], r2 ~ sk[122], r3 ~ sk[123];
	r0, r1, r2, r3 = sb6(r0, r1, r2, r3);
	r0, r1, r2, r3 = linear(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[124], r1 ~ sk[125], r2 ~ sk[126], r3 ~ sk[127];
	r0, r1, r2, r3 = sb7(r0, r1, r2, r3);

    r0 ~= sk[128];
	r1 ~= sk[129];
	r2 ~= sk[130];
	r3 ~= sk[131];

    ciphertext := make([]byte, BLOCK_SIZE);

	ciphertext[ 0] = byte(r0);
	ciphertext[ 1] = byte(r0 >> 8);
	ciphertext[ 2] = byte(r0 >> 16);
	ciphertext[ 3] = byte(r0 >> 24);
	ciphertext[ 4] = byte(r1);
	ciphertext[ 5] = byte(r1 >> 8);
	ciphertext[ 6] = byte(r1 >> 16);
	ciphertext[ 7] = byte(r1 >> 24);
	ciphertext[ 8] = byte(r2);
	ciphertext[ 9] = byte(r2 >> 8);
	ciphertext[10] = byte(r2 >> 16);
	ciphertext[11] = byte(r2 >> 24);
	ciphertext[12] = byte(r3);
	ciphertext[13] = byte(r3 >> 8);
	ciphertext[14] = byte(r3 >> 16);
	ciphertext[15] = byte(r3 >> 24);

    return ciphertext;
}

decrypt :: proc(key, ciphertext: []byte) -> []byte {
    sk := key_schedule(key);

    r0 := u32(ciphertext[0])  | u32(ciphertext[1])<<8  | u32(ciphertext[2])<<16  | u32(ciphertext[3])<<24;
	r1 := u32(ciphertext[4])  | u32(ciphertext[5])<<8  | u32(ciphertext[6])<<16  | u32(ciphertext[7])<<24;
	r2 := u32(ciphertext[8])  | u32(ciphertext[9])<<8  | u32(ciphertext[10])<<16 | u32(ciphertext[11])<<24;
	r3 := u32(ciphertext[12]) | u32(ciphertext[13])<<8 | u32(ciphertext[14])<<16 | u32(ciphertext[15])<<24;

	r0 ~= sk[128];
	r1 ~= sk[129];
	r2 ~= sk[130];
	r3 ~= sk[131];

    r0, r1, r2, r3 = sb7_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[124], r1 ~ sk[125], r2 ~ sk[126], r3 ~ sk[127];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb6_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[120], r1 ~ sk[121], r2 ~ sk[122], r3 ~ sk[123];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb5_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[116], r1 ~ sk[117], r2 ~ sk[118], r3 ~ sk[119];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb4_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[112], r1 ~ sk[113], r2 ~ sk[114], r3 ~ sk[115];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb3_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[108], r1 ~ sk[109], r2 ~ sk[110], r3 ~ sk[111];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb2_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[104], r1 ~ sk[105], r2 ~ sk[106], r3 ~ sk[107];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb1_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[100], r1 ~ sk[101], r2 ~ sk[102], r3 ~ sk[103];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb0_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[96], r1 ~ sk[97], r2 ~ sk[98], r3 ~ sk[99];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);

	r0, r1, r2, r3 = sb7_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[92], r1 ~ sk[93], r2 ~ sk[94], r3 ~ sk[95];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb6_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[88], r1 ~ sk[89], r2 ~ sk[90], r3 ~ sk[91];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb5_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[84], r1 ~ sk[85], r2 ~ sk[86], r3 ~ sk[87];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb4_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[80], r1 ~ sk[81], r2 ~ sk[82], r3 ~ sk[83];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb3_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[76], r1 ~ sk[77], r2 ~ sk[78], r3 ~ sk[79];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb2_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[72], r1 ~ sk[73], r2 ~ sk[74], r3 ~ sk[75];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb1_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[68], r1 ~ sk[69], r2 ~ sk[70], r3 ~ sk[71];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb0_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[64], r1 ~ sk[65], r2 ~ sk[66], r3 ~ sk[67];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);

	r0, r1, r2, r3 = sb7_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[60], r1 ~ sk[61], r2 ~ sk[62], r3 ~ sk[63];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb6_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[56], r1 ~ sk[57], r2 ~ sk[58], r3 ~ sk[59];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb5_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[52], r1 ~ sk[53], r2 ~ sk[54], r3 ~ sk[55];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb4_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[48], r1 ~ sk[49], r2 ~ sk[50], r3 ~ sk[51];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb3_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[44], r1 ~ sk[45], r2 ~ sk[46], r3 ~ sk[47];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb2_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[40], r1 ~ sk[41], r2 ~ sk[42], r3 ~ sk[43];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb1_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[36], r1 ~ sk[37], r2 ~ sk[38], r3 ~ sk[39];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb0_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[32], r1 ~ sk[33], r2 ~ sk[34], r3 ~ sk[35];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);

	r0, r1, r2, r3 = sb7_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[28], r1 ~ sk[29], r2 ~ sk[30], r3 ~ sk[31];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb6_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[24], r1 ~ sk[25], r2 ~ sk[26], r3 ~ sk[27];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb5_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[20], r1 ~ sk[21], r2 ~ sk[22], r3 ~ sk[23];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb4_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[16], r1 ~ sk[17], r2 ~ sk[18], r3 ~ sk[19];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb3_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[12], r1 ~ sk[13], r2 ~ sk[14], r3 ~ sk[15];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb2_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[8], r1 ~ sk[9], r2 ~ sk[10], r3 ~ sk[11];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb1_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = r0 ~ sk[4], r1 ~ sk[5], r2 ~ sk[6], r3 ~ sk[7];
	r0, r1, r2, r3 = linear_inv(r0, r1, r2, r3);
	r0, r1, r2, r3 = sb0_inv(r0, r1, r2, r3);

    r0 ~= sk[0];
	r1 ~= sk[1];
	r2 ~= sk[2];
	r3 ~= sk[3];

    plaintext := make([]byte, BLOCK_SIZE);

	plaintext[ 0] = byte(r0);
	plaintext[ 1] = byte(r0 >> 8);
	plaintext[ 2] = byte(r0 >> 16);
	plaintext[ 3] = byte(r0 >> 24);
	plaintext[ 4] = byte(r1);
	plaintext[ 5] = byte(r1 >> 8);
	plaintext[ 6] = byte(r1 >> 16);
	plaintext[ 7] = byte(r1 >> 24);
	plaintext[ 8] = byte(r2);
	plaintext[ 9] = byte(r2 >> 8);
	plaintext[10] = byte(r2 >> 16);
	plaintext[11] = byte(r2 >> 24);
	plaintext[12] = byte(r3);
	plaintext[13] = byte(r3 >> 8);
	plaintext[14] = byte(r3 >> 16);
	plaintext[15] = byte(r3 >> 24);

    return plaintext;
}