pragma circom 2.0.0;

/**
 * Add two 32-bit integers
 * Note: a and b must already be 32-bit constrained integers
 */
template Add32BitsUnsafe() {
	signal input a;
	signal input b;
	signal output out;

	// hold the 32nd bit of a + b
	signal tmp;

	// check if 32nd bit is 1
	tmp <-- (a + b) >= (0xFFFFFFFF + 1) ? 1 : 0;
	tmp * (tmp - 1) === 0;

	// if a and b are greater than 32 bit int max
	// then the 32nd bit will be 1
	// which means tmp = 1
	// so, if we subtract 0xFFFFFFFF + 1 from a + b
	// we'll get the correct result
	// which is (a + b) & 2**32
	out <== (a + b) - (tmp * (0xFFFFFFFF + 1));
	// ensure that the tmp bit was correctly calculated
	// if tmp is maliciously = 1 and (a + b) < 2**32 then
	// (a+b) - out = 0, but tmp * (0xFFFFFFFF + 1) = 2**32
	// hence condition below will fail
	// if tmp is maliciously = 0 and (a + b) > 2**32 then
	// (a+b) - out = 2**32, but tmp * (0xFFFFFFFF + 1) = 0
	(a + b) - out === tmp * (0xFFFFFFFF + 1);
}

/**
 * Rotate left a 32-bit integer by L bits
 * Note: "in" must already be a constrained 32-bit integer
 * 
 */
template RotateLeft32BitsUnsafe(L) {
	signal input in;
	signal output out;
	// get the most significant L bits
	// and shift them to the least significant L bits
	// eg. if L = 3, and instead of 32 bits it's 10 bits,
	// in = 0101011001, then part1 = 010
	signal part1 <-- in >> (32 - L);
	// get the least significant 32 - L bits
	// from the above example,
	// in = 0101011001, part1 = 010,
	// tmp = part1 * 2**(32 - L) = 0100000000
	// part2Tmp = in - tmp = 0101011001 - 0100000000 = 0001011001
	// part2 = part2Tmp * 2**L = 01011001000
	signal part2 <== (in - (part1 * 2**(32 - L))) * 2**L;
	// now, the rotated number is simply part1 + part2
	out <== part1 + part2;
	// constraint to ensure that the rotation is correct
	(part2 / 2**L) + (part1 * 2**(32-L)) === in;
}

/**
 * XOR N M-bit words
*/
template XorWords(N, M) {
	signal input a[N];
	signal input b[N];
	signal output out[N];

	signal abits[M*N];
	signal bbits[M*N];
	signal xors[M*N];

	var ain;
	var bin;
	var out2;
	var i = 0;
	var j = 0;
	var l = 0;

	for(i = 0;i < N;i++) {
		ain = a[i];
		bin = b[i];
		out2 = 0;
		for(j = 2 ** (M-1);j >= 1;j /= 2) {
			abits[l] <-- ain >= j ? 1 : 0;
			bbits[l] <-- bin >= j ? 1 : 0;
			// ensure abits[l] and bbits[l] are either 0 or 1
			// below should be uncommented in prod?
			abits[l] * (abits[l] - 1) === 0;
			bbits[l] * (bbits[l] - 1) === 0;
			xors[l] <== abits[l] + bbits[l] - 2 * abits[l] * bbits[l];

			ain -= abits[l] * j;
			bin -= bbits[l] * j;
			out2 += xors[l] * j;

			l ++;
		}

		ain === 0;
		bin === 0;
		out[i] <== out2;
	}
}