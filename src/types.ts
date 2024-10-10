export type EncryptionAlgorithm = 'aes-256-ctr'
	| 'aes-128-ctr'
	| 'chacha20'

// the Array type used in the circuit
// it's a Uint32Array, as all ChaCha20 operations
// are done on 32-bit words
export type UintArray = Uint32Array

export type Proof = {
	algorithm: EncryptionAlgorithm
	/** serialised SnarkJS proof */
	proofJson: string
	/**
	 * the plaintext obtained as an output
	 * of the ZK circuit
	 */
	plaintext: Uint8Array
}

/**
 * provide Uint8array for file data loaded into memory
 * or string, that is the path to load said file
 * */
type ZKInput = Uint8Array | string

export type VerificationKey = {
	/** binary data for .zkey file */
	data: ZKInput
	json?: any
}

export type CircuitWasm = Uint8Array | string

export type GenerateProofOpts = {
	/**
	 * the algorithm to use for the encryption
	 * circuit. Used to correctly slice the
	 * IV, counters etc.
	 */
	algorithm: EncryptionAlgorithm
	/**
	 * private input to the circuit
	 * * will include the key, iv, and counter 
	 */
	privateInput: PrivateInput
	/**
	 * public input to the circuit,
	 * i.e. the ciphertext to decrypt
	 */
	publicInput: PublicInput
	/**
	 * Operator to use for proving the circuit
	 */
	operator: ZKOperator
	logger?: Logger
}

export type VerifyProofOpts = {
	/** JSON proof generated by "generateProof" fn */
	proof: Proof
	publicInput: PublicInput
	operator: ZKOperator
	logger?: Logger
}

type ZKProof = { [_: string]: any } | string

type ZKProofOutput = {
	proof: ZKProof
	publicSignals: number[]
}

type ZKInputItem = number[] | number[][]

type ZKProofInput = {
	key: ZKInputItem
	nonce: ZKInputItem
	counter: ZKInputItem
	in: ZKInputItem
}

/**
 * the operator to use for proving and verifying the groth16
 * proof of the ChaCha20 circuit
 * 
 * this generic interface is allow
 * for different implementations
 */
export type ZKOperator = {
	generateWitness(input: ZKProofInput, logger?: Logger): Promise<Uint8Array>
	groth16Prove(witness: Uint8Array, logger?: Logger): Promise<ZKProofOutput>
	groth16Verify(
		publicSignals: number[],
		proof: ZKProof,
		logger?: Logger
	): Promise<boolean>
	/**
	 * Release any used resources. The operator
	 * should still be usable after this call.
	 *
	 * This is useful for releasing any resources
	 * in case ZK operations are not going to be
	 * used for a while.
	 */
	release?(): void
}

export type ZKParams = {
	getZkey: () => Promise<VerificationKey> | VerificationKey
	getCircuitWasm: () => Promise<CircuitWasm> | CircuitWasm
}

export type PrivateInput = {
	/** 256 bit ChaCha20 key to decrypt ciphertext */
	key: Uint8Array
}

export type PublicInput = {
	/** the ciphertext to decrypt */
	ciphertext: Uint8Array

	/** 192 bit IV for the ciphertext decryption */
	iv: Uint8Array
	/**
	 * decryption offset in chunks
	 * Specify 0 for the first chunk
	 * @default 0
	 * */
	offset: number
}

export type Logger = Pick<typeof console, 'info' | 'trace' | 'debug' | 'error' | 'warn'>

export interface EncryptionConfig {
    chunkSize: number; // Size of each chunk in bytes
    bitsPerWord: number; // Number of bits in a word
    keySizeBytes: number; // Key size in bytes
    ivSizeBytes: number; // Initialization vector size in bytes
    startCounter: number; // Starting counter for encryption
    blocksPerChunk: number; // Number of blocks per chunk
    isLittleEndian: boolean; // Indicates if little-endian encoding is used
    uint8ArrayToBits: (arr: Uint8Array) => number[] | number[][]; // Function to convert Uint8Array to bits
    bitsToUint8Array: (bits: number[]) => Uint8Array; // Function to convert bits to Uint8Array
}