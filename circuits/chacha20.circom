pragma circom 2.0.0;

include "./generics.circom";

/** ChaCha20 in counter mode */
template ChaCha20(N) {
	// key => 8 32-bit words = 32 bytes
	signal input key[8];
	// nonce => 3 32-bit words = 12 bytes
	signal input nonce[3];
	// counter => 32-bit word to apply w nonce
	signal input counter;
	// in => N 32-bit words => N 4 byte words
	signal input in[N];
	// out => N 32-bit words => N 4 byte words
	signal output out[N];

	var tmp[16] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], counter, nonce[0], nonce[1], nonce[2]];
	var i = 0;
	var j = 0;

	component block[N/16];
	component xors[N];
	for(i = 0; i < N/16; i++) {
		block[i] = ChaCha20Block();
		block[i].in <== tmp;
		// XOR block with input
		for(j = 0; j < 16; j++) {
			xors[i*16 + j] = XorWords(1, 32);
			xors[i*16 + j].a[0] <== in[i*16 + j];
			xors[i*16 + j].b[0] <== block[i].out[j];
			out[i*16 + j] <== xors[i*16 + j].out[0];
		}
		// increment the counter
		tmp[12] = tmp[12] + 1;
	}
}

template ChaCha20Block() {
	// in => 16 32-bit words
	signal input in[16];
	// out => 16 32-bit words
	signal output out[16];

	var tmp[16] = in;

	component rounds[10 * 8];
	component finalAdd[16];
	// i-th round
	var i = 0;
	// col loop counter
	var j = 0;
	// counter for the rounds array
	var k = 0;
	for(i = 0; i < 10; i++) {
		// columns of the matrix in a loop
		// 0, 4, 8, 12
		// 1, 5, 9, 13
		// 2, 6, 10, 14
		// 3, 7, 11, 15
		for(j = 0; j < 4; j++) {
			rounds[k] = QR();
			rounds[k].in[0] <== tmp[j];
			rounds[k].in[1] <== tmp[j + 4];
			rounds[k].in[2] <== tmp[j + 8];
			rounds[k].in[3] <== tmp[j + 12];

			tmp[j] = rounds[k].out[0];
			tmp[j + 4] = rounds[k].out[1];
			tmp[j + 8] = rounds[k].out[2];
			tmp[j + 12] = rounds[k].out[3];

			k ++;
		}

		// 4 diagnals
		// 0, 5, 10, 15
		rounds[k] = QR();
		rounds[k].in[0] <== tmp[0];
		rounds[k].in[1] <== tmp[5];
		rounds[k].in[2] <== tmp[10];
		rounds[k].in[3] <== tmp[15];

		tmp[0] = rounds[k].out[0];
		tmp[5] = rounds[k].out[1];
		tmp[10] = rounds[k].out[2];
		tmp[15] = rounds[k].out[3];

		k ++;

		// 1, 6, 11, 12
		rounds[k] = QR();
		rounds[k].in[0] <== tmp[1];
		rounds[k].in[1] <== tmp[6];
		rounds[k].in[2] <== tmp[11];
		rounds[k].in[3] <== tmp[12];

		tmp[1] = rounds[k].out[0];
		tmp[6] = rounds[k].out[1];
		tmp[11] = rounds[k].out[2];
		tmp[12] = rounds[k].out[3];

		k ++;

		// 2, 7, 8, 13
		rounds[k] = QR();
		rounds[k].in[0] <== tmp[2];
		rounds[k].in[1] <== tmp[7];
		rounds[k].in[2] <== tmp[8];
		rounds[k].in[3] <== tmp[13];

		tmp[2] = rounds[k].out[0];
		tmp[7] = rounds[k].out[1];
		tmp[8] = rounds[k].out[2];
		tmp[13] = rounds[k].out[3];

		k ++;

		// 3, 4, 9, 14
		rounds[k] = QR();
		rounds[k].in[0] <== tmp[3];
		rounds[k].in[1] <== tmp[4];
		rounds[k].in[2] <== tmp[9];
		rounds[k].in[3] <== tmp[14];

		tmp[3] = rounds[k].out[0];
		tmp[4] = rounds[k].out[1];
		tmp[9] = rounds[k].out[2];
		tmp[14] = rounds[k].out[3];

		k ++;
	}

	// add the result to the input
	for(i = 0; i < 16; i++) {
		finalAdd[i] = Add32BitsUnsafe();
		finalAdd[i].a <== tmp[i];
		finalAdd[i].b <== in[i];
		tmp[i] = finalAdd[i].out;
	}

	out <== tmp;
}

// ChaCha quarter round
template QR() {
	signal input in[4];
	signal output out[4];

	var tmp[4] = in;

	// a += b
	component add1 = Add32BitsUnsafe();
	add1.a <== tmp[0];
	add1.b <== tmp[1];
	tmp[0] = add1.out;

	// d ^= a
	component xor1 = XorWords(1, 32);
	xor1.a[0] <== tmp[3];
	xor1.b[0] <== tmp[0];
	tmp[3] = xor1.out[0];

	// d = RotateLeft32BitsUnsafe(d, 16)
	component rot1 = RotateLeft32BitsUnsafe(16);
	rot1.in <== tmp[3];
	tmp[3] = rot1.out;

	// c += d
	component add2 = Add32BitsUnsafe();
	add2.a <== tmp[2];
	add2.b <== tmp[3];
	tmp[2] = add2.out;

	// b ^= c
	component xor2 = XorWords(1, 32);
	xor2.a[0] <== tmp[1];
	xor2.b[0] <== tmp[2];
	tmp[1] = xor2.out[0];

	// b = RotateLeft32BitsUnsafe(b, 12)
	component rot2 = RotateLeft32BitsUnsafe(12);
	rot2.in <== tmp[1];
	tmp[1] = rot2.out;
	
	// a += b
	component add3 = Add32BitsUnsafe();
	add3.a <== tmp[0];
	add3.b <== tmp[1];
	tmp[0] = add3.out;

	// d ^= a
	component xor3 = XorWords(1, 32);
	xor3.a[0] <== tmp[3];
	xor3.b[0] <== tmp[0];
	tmp[3] = xor3.out[0];

	// d = RotateLeft32BitsUnsafe(d, 8)
	component rot3 = RotateLeft32BitsUnsafe(8);
	rot3.in <== tmp[3];
	tmp[3] = rot3.out;

	// c += d
	component add4 = Add32BitsUnsafe();
	add4.a <== tmp[2];
	add4.b <== tmp[3];
	tmp[2] = add4.out;

	// b ^= c
	component xor4 = XorWords(1, 32);
	xor4.a[0] <== tmp[1];
	xor4.b[0] <== tmp[2];
	tmp[1] = xor4.out[0];

	// b = RotateLeft32BitsUnsafe(b, 7)
	component rot4 = RotateLeft32BitsUnsafe(7);
	rot4.in <== tmp[1];
	tmp[1] = rot4.out;

	out <== tmp;
}