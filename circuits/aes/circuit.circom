pragma circom 2.0.0;

include "aes_ctr.circom";

/**
 * This circuit takes in the encryption keys &
 * an N byte AES-CTR ciphertext and verifies that
 * it decrypts to some plaintext
 * BITS_PER_WORD = 8
 */
template Main(N, BITS_PER_WORD) {
   // the key, iv & startCounter are private inputs
   // they must be specified by the client 
   signal input key[32 * BITS_PER_WORD];
   signal input nonce[12 * BITS_PER_WORD];
   signal input counter[4 * BITS_PER_WORD];
   // the ciphertext is public input
   // so the witness can check the right data was sent to the circuit
   signal input in[N*8];
   signal output out[N*8];

   // AES CTR decryption

   component aes = AES_CTR(N*8);
   for(var i = 0; i < 32 * BITS_PER_WORD; i++) {
        aes.K1[i] <== key[i];
   }

   // set counter
   for(var i = 0; i < 12 * BITS_PER_WORD; i++) {
        aes.CTR[i] <== nonce[i];
   }
   for(var i = 0; i < 4 * BITS_PER_WORD; i++) {
        aes.CTR[i + 12*BITS_PER_WORD] <== counter[i];
   }

   for(var i = 0; i < N*8; i++) {
        aes.MSG[i] <== in[i];
   }
   
   for(var i = 0; i < N*8; i++) {
     out[i] <== aes.CT[i];
     }

}

component main{public [in]} = Main(64, 8); //in bytes divisible by 16