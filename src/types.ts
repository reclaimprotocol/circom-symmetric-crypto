// the Array type used in the circuit
// it's a Uint32Array, as all ChaCha20 operations
// are done on 32-bit words
export type UintArray = Uint32Array

export type Proof = {
	/** serialised SnarkJS proof */
	proofJson: string
	/**
	 * the plaintext obtained as an output
	 * of the ZK circuit
	 */
	plaintext: UintArray
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

type ZKProof = any

type ZKProofOutput = {
	proof: ZKProof,
	publicSignals: number[]
}

/**
 * the operator to use for proving and verifying the groth16
 * proof of the ChaCha20 circuit
 * 
 * this generic interface is allow
 * for different implementations
 */
export type ZKOperator = {
	groth16FullProve<T>(input: T): Promise<ZKProofOutput>
	groth16Verify(
		publicSignals: number[],
		proof: ZKProof
	): Promise<boolean>
}

export type ZKParams = {
	zkey: VerificationKey
	circuitWasm: ZKInput
}

export type PrivateInput = {
	/** 256 bit ChaCha20 key to decrypt ciphertext */
	key: Uint8Array
	/** 192 bit IV for the ciphertext decryption */
	iv: Uint8Array
	/**
	 * counter to start decryption from
	 * @minimum 1
	 * */
	startCounter: number
}

export type PublicInput = {
	/** the ciphertext to decrypt */
	ciphertext: Uint8Array
}