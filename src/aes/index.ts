import * as snarkjs from "snarkjs";
import { PrivateInput, Proof, PublicInput, VerificationKey } from "./types";
import { bitsToUint8Array } from "../utils";

const CIRCUIT_WASM_PATH = "./resources/aes/circuit.wasm";

/**
 * Generates a zero-knowledge proof
 * @param privateInput - The private input for the proof
 * @param publicInput - The public input for the proof
 * @param zkey - The verification key
 * @returns A Promise resolving to the generated Proof
 */
export async function generateProof(
    privateInput: PrivateInput,
    publicInput: PublicInput,
    zkey: VerificationKey
): Promise<Proof> {
    const { key, iv } = privateInput;
    const { ciphertext } = publicInput;

    const encKey = bufferToBits(Buffer.from(key));
    const ivCounter = bufferToBits(Buffer.from(iv));
    const ct = bufferToBits(Buffer.from(ciphertext));

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        {
            encKey,
            iv: ivCounter,
            ciphertext: ct,
        },
        CIRCUIT_WASM_PATH,
        zkey.data
    );

    return {
        proofJson: JSON.stringify(proof),
        plaintext: bitsToUint8Array(publicSignals.slice(0, ct.length * 8))
    };
}

/**
 * Verifies a zero-knowledge proof
 * @param proof - The proof to verify
 * @param publicInput - The public input used for verification
 * @param zkey - The verification key
 * @returns A Promise resolving to a boolean indicating if the proof is valid
 */
export async function verifyProof(
    proof: Proof,
    publicInput: PublicInput,
    zkey: VerificationKey
): Promise<boolean> {
    if (!zkey.json) {
        zkey.json = await snarkjs.zKey.exportVerificationKey(zkey.data);
    }

    const pubInputs = getSerializedPublicInputs(publicInput);
    return snarkjs.groth16.verify(
        zkey.json,
        pubInputs,
        JSON.parse(proof.proofJson)
    );
}

/**
 * Serializes public inputs to an array of numbers for the ZK circuit
 * @param input - The public input to serialize
 * @returns An array of numbers representing the serialized public input
 */
function getSerializedPublicInputs(input: PublicInput): number[] {
    return bufferToBits(Buffer.from(input.ciphertext));
}

/**
 * Converts a Buffer to an array of bits
 * @param buffer - The Buffer to convert
 * @returns An array of numbers (0 or 1) representing the bits
 */
function bufferToBits(buffer: Buffer): number[] {
    return Array.from(buffer).flatMap(byte => 
        Array.from({length: 8}, (_, i) => (byte >> (7 - i)) & 1)
    );
}
