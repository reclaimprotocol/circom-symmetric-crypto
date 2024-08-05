/**
 * Represents a zero-knowledge proof
 */
export interface Proof {
    /** Serialized SnarkJS proof */
    proofJson: string;
    /** Decrypted plaintext */
    plaintext: Uint8Array;
}

/**
 * Represents a verification key for zero-knowledge proofs
 */
export interface VerificationKey {
    /** Binary data for .zkey file */
    data: Uint8Array;
    /** JSON representation of the verification key */
    json?: unknown;
}

/**
 * Represents a redaction range in the plaintext
 */
export interface Redaction {
    /** Starting index of the redaction */
    startIndex: number;
    /** Ending index of the redaction */
    endIndex: number;
}

/**
 * Represents the private input for encryption
 */
export interface PrivateInput {
    /** AES-256-CTR key to decrypt ciphertext */
    key: Uint8Array;
    /** Initialization Vector (IV) for the ciphertext decryption */
    iv: Uint8Array;
}

/**
 * Represents the public input for encryption
 */
export interface PublicInput {
    /** The ciphertext to decrypt */
    ciphertext: Uint8Array;
    // Commented out as per original file
    // /** The redacted plaintext */
    // redactedPlaintext: Uint8Array;
}
