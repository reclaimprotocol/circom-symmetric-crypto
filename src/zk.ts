import { EncryptionAlgorithm, GenerateProofOpts, Proof, VerifyProofOpts } from "./types";
import { CONFIG } from "./config";
import { getCounterForChunk } from "./utils";

/**
 * Generate ZK proof for CHACHA20-CTR encryption.
 * Circuit proves that the ciphertext is a valid encryption of the given plaintext.
 * The plaintext can be partially redacted.
 * @param opts - Options for generating the proof
 * @returns A Promise resolving to the generated Proof
 */
export async function generateProof({ algorithm, operator, logger, privateInput, publicInput }: GenerateProofOpts): Promise<Proof> {
    const { bitsPerWord, chunkSize, bitsToUint8Array } = CONFIG[algorithm];
    const witness = await generateZkWitness({ algorithm, operator, privateInput, publicInput });
    const { proof, publicSignals } = await operator.groth16Prove(witness, logger);

    const totalBits = chunkSize * bitsPerWord;

    return {
        algorithm,
        proofJson: typeof proof === 'string' ? proof : JSON.stringify(proof),
        plaintext: bitsToUint8Array(publicSignals.slice(0, totalBits).map(Number))
    };
}

/**
 * Generate a ZK witness for the symmetric encryption circuit.
 * This witness can then be used to generate a ZK proof,
 * using the operator's groth16Prove function.
 * @param opts - Options for generating the ZK witness
 * @returns A Promise resolving to the generated witness
 */
export async function generateZkWitness({
    algorithm,
    privateInput: { key, iv, offset },
    publicInput: { ciphertext },
    operator
}: GenerateProofOpts): Promise<any> {
    const { keySizeBytes, ivSizeBytes, isLittleEndian, uint8ArrayToBits } = CONFIG[algorithm];
    
    // Validate input sizes
    if (key.length !== keySizeBytes) throw new Error(`key must be ${keySizeBytes} bytes`);
    if (iv.length !== ivSizeBytes) throw new Error(`iv must be ${ivSizeBytes} bytes`);

    const startCounter = getCounterForChunk(algorithm, offset);
    const ciphertextArray = padCiphertextToChunkSize(algorithm, ciphertext);
    
    // Generate and return the witness
    return operator.generateWitness({
        key: uint8ArrayToBits(key),
        nonce: uint8ArrayToBits(iv),
        counter: serialiseCounter(),
        in: uint8ArrayToBits(ciphertextArray),
    });

    /**
     * Helper function to serialize the counter
     * @returns An array of bits representing the serialized counter
     */
    function serialiseCounter(): number[] {
        const counterArr = new Uint8Array(4);
        new DataView(counterArr.buffer).setUint32(0, startCounter, isLittleEndian);
        return uint8ArrayToBits(counterArr).flat();
    }
}

/**
 * Verify a ZK proof for CHACHA20-CTR encryption.
 * @param proof - The proof to verify
 * @param publicInput - The public input used for verification
 * @param operator - The operator used for verification
 * @param logger - The logger to use
 * @throws Error if the proof is invalid
 */
export async function verifyProof({
    proof: { algorithm, plaintext, proofJson },
    publicInput: { ciphertext },
    operator,
    logger
}: VerifyProofOpts): Promise<void> {
    const { uint8ArrayToBits } = CONFIG[algorithm];
    const ciphertextArray = padCiphertextToChunkSize(algorithm, ciphertext);
    
    // Ensure ciphertext and plaintext have the same length
    if (ciphertextArray.length !== plaintext.length) {
        throw new Error('ciphertext and plaintext must be the same length');
    }
    
    // Prepare public inputs for verification
    const pubInputs = [...uint8ArrayToBits(plaintext), ...uint8ArrayToBits(ciphertextArray)].flat();
    const verified = await operator.groth16Verify(pubInputs, JSON.parse(proofJson));

    if (!verified) throw new Error('invalid proof');
}

/**
 * Pad the ciphertext to the required chunk size for the given algorithm
 * @param alg - The encryption algorithm
 * @param ciphertext - The ciphertext to pad
 * @returns The padded ciphertext
 * @throws Error if the ciphertext is too large
 */
function padCiphertextToChunkSize(alg: EncryptionAlgorithm, ciphertext: Uint8Array): Uint8Array {
    const { chunkSize, bitsPerWord } = CONFIG[alg];
    const expectedSizeBytes = (chunkSize * bitsPerWord) / 8;

    if (ciphertext.length > expectedSizeBytes) {
        throw new Error(`ciphertext must be <= ${expectedSizeBytes}b`);
    }

    if (ciphertext.length < expectedSizeBytes) {
        const arr = new Uint8Array(expectedSizeBytes);
        arr.set(ciphertext);
        return arr;
    }

    return ciphertext;
}
