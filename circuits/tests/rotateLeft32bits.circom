pragma circom 2.0.0;

include "../generics.circom";

/**
* Rotate in all directions required by
* the ChaCha20 cipher
*/
template _RotateLeft32Bits() {
	signal input in;
	signal output out[4];

	component rotl1 = RotateLeft32Bits(16);
	rotl1.in <== in;
	out[0] <== rotl1.out;

	component rotl2 = RotateLeft32Bits(12);
	rotl2.in <== in;
	out[1] <== rotl2.out;

	component rotl3 = RotateLeft32Bits(8);
	rotl3.in <== in;
	out[2] <== rotl3.out;

	component rotl4 = RotateLeft32Bits(7);
	rotl4.in <== in;
	out[3] <== rotl4.out;
}

component main = _RotateLeft32Bits();