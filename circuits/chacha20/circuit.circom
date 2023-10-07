pragma circom 2.0.0;

include "./chacha20-bits.circom";

component main{public [in]} = ChaCha20(16, 32);