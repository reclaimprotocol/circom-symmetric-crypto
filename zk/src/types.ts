

// the Array type used in the circuit
export type UintArray = Uint32Array

export type Proof = {
	/** serialised SnarkJS proof */
	proofJson: string
	/**
	 * the decrypted text that is
	 * congruent with the redacted plaintext
	 */
	decryptedRedactedCiphertext: UintArray
}

/**
 * either loaded in memory Uint8array or string,
 * to load from file
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
 * the operator to use for proving and verifying a ZK proof
 * this is generic to allow for different implementations
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

export type Redaction = {
	startIndex: number
	endIndex: number
}

export type PrivateInput = {
	/** AES-256-CTR key to decrypt ciphertext */
	key: Uint8Array
	/** IV for the ciphertext decryption */
	iv: Uint8Array
	/** counter to start decryption from */
	startCounter: number
}

export type PublicInput = {
	/** the ciphertext to decrypt */
	ciphertext: Uint8Array
	/** the redacted plaintext */
	redactedPlaintext: Uint8Array
}