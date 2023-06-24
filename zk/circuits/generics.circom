pragma circom 2.0.0;

/**
 * Add two 32-bit integers
 */
template Add32Bits() {
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
}

template RotateLeft32Bits(L) {
	signal input in;
	signal output out;
	// TODO: check if this constraint is enough?
	signal part1 <-- (in << L) & 0xFFFFFFFF;
	signal part2 <-- in >> (32 - L);
	out <-- part1 | part2;
	(part1 / 2**L) + (part2 * 2**(32-L)) === in;
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
			// abits[l] * (abits[l] - 1) === 0;
			// bbits[l] * (bbits[l] - 1) === 0;
			xors[l] <== abits[l] + bbits[l] - 2 * abits[l] * bbits[l];

			ain -= abits[l] * j;
			bin -= bbits[l] * j;
			out2 += xors[l] * j;

			l ++;
		}

		ain * a[i] === 0;
		bin * b[i] === 0;
		out[i] <== out2;
	}
}