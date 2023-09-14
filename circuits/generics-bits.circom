pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/binsum.circom";

/**
 * Add N bits together
 */
template AddBits(BITS) {
	signal input a[BITS];
	signal input b[BITS];
	signal output out[BITS];
	
	component adder = BinSum(BITS, 2);
    for(var i = 0;i < BITS;i++) {
        adder.in[0][i] <== a[BITS - i - 1];
        adder.in[1][i] <== b[BITS - i - 1];
    }

	for(var i = 0;i < BITS;i++) {
		out[BITS - i - 1] <== adder.out[i];
	}
}

/**
 * Rotate left a BITS bit integer L bits
 */
template RotateLeftBits(BITS, L) {
	signal input in[BITS];
    signal output out[BITS];
    for (var i = 0; i < BITS; i++) {
        out[i] <== in[(i + L) % BITS];
    }
}

/**
 * XOR N M-bit words
*/
template XorBits(BITS) {
	signal input a[BITS];
    signal input b[BITS];
    signal output out[BITS];
    var mid[BITS];

    for (var k=0; k<BITS; k++) {
        mid[k] = a[k]*b[k];
        out[k] <== a[k] + b[k] - 2*mid[k];
    }
}