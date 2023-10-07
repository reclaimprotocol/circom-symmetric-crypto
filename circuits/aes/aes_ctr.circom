// Copyright © 2022, Electron Labs
pragma circom 2.0.0;

include "aes_256_key_expansion.circom";
include "aes_256_encrypt.circom";
include "aes_256_ctr.circom";

template AES_CTR(n_bits_msg)
{
    var msg_len = n_bits_msg/8;
    assert(msg_len%16 == 0);
    signal input K1[256];
    signal input CTR[128];
    signal input MSG[n_bits_msg];
    signal output CT[n_bits_msg];

    var ks[1920];
    var i;

    component key_expansion_1 = AES256KeyExpansion();
    for(i=0; i<256; i++) key_expansion_1.key[i] <== K1[i];
    ks = key_expansion_1.w;

    component aes_256_ctr = AES256CTR(n_bits_msg);
    for(i=0; i<128; i++) aes_256_ctr.ctr[i] <== CTR[i];
    for(i=0; i<1920; i++) aes_256_ctr.ks[i] <== ks[i];
    for(i=0; i<n_bits_msg; i++) aes_256_ctr.in[i] <== MSG[i];

    for(i=0; i<msg_len*8; i++) CT[i] <== aes_256_ctr.out[i];
}