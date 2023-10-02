pragma circom 2.0.0;

include "aes_ctr.circom";

/**
 * This circuit takes in the encryption keys &
 * an N byte AES-CTR ciphertext and verifies that
 * it decrypts to some plaintext
 */
template Main (N) {
   // the key, iv & startCounter are private inputs
   // they must be specified by the client 
   signal input encKey[256];
   signal input iv[128];
   // the ciphertext is public input
   // so the witness can check the right data was sent to the circuit
   signal input ciphertext[N*8];
   signal output plaintext[N*8];


   // AES CTR decryption

   component aes = AES_CTR(N*8);
   for(var i = 0; i < 256; i++) {
        aes.K1[i] <== encKey[i];
   }
   for(var i = 0; i < 128; i++) {
        aes.CTR[i] <== iv[i];
   }

   for(var i = 0; i < N*8; i++) {
        aes.MSG[i] <== ciphertext[i];
   }

    for(var i = 0; i < N*8; i++) {
         plaintext[i] <== aes.CT[i];
    }

}

component main{public [ciphertext]} = Main(64); //in bytes divisible by 16