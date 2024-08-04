import { 
    bitsToUint8Array, 
    bitsToUintArray, 
    toUint8Array, 
    toUintArray, 
    uint8ArrayToBits, 
    uintArrayToBits 
} from "./utils";

import { EncryptionAlgorithm } from "./types";

/**
 * Configuration for encryption algorithms
 */
export const CONFIG: Record<EncryptionAlgorithm, EncryptionConfig> = {
    'chacha20': {
        chunkSize: 16,
        bitsPerWord: 32,
        keySizeBytes: 32,
        ivSizeBytes: 12,
        startCounter: 1,
        blocksPerChunk: 1,
        isLittleEndian: true,
        uint8ArrayToBits: (arr: Uint8Array) => uintArrayToBits(toUintArray(arr)),
        bitsToUint8Array: (bits: number[]) => toUint8Array(bitsToUintArray(bits)),
    },
    'aes-256-ctr': {
        chunkSize: 64,
        bitsPerWord: 8,
        keySizeBytes: 32,
        ivSizeBytes: 12,
        startCounter: 2,
        blocksPerChunk: 4,
        isLittleEndian: false,
        uint8ArrayToBits: (arr: Uint8Array) => [uint8ArrayToBits(arr)],
        bitsToUint8Array,
    },
    'aes-128-ctr': {
        chunkSize: 64,
        bitsPerWord: 8,
        keySizeBytes: 16,
        ivSizeBytes: 12,
        startCounter: 2,
        blocksPerChunk: 4,
        isLittleEndian: false,
        uint8ArrayToBits: (arr: Uint8Array) => [uint8ArrayToBits(arr)],
        bitsToUint8Array,
    }
};

/**
 * Type definition for encryption configuration
 */
interface EncryptionConfig {
    /** Size of each chunk in words */
    chunkSize: number;
    /** Number of bits in each word */
    bitsPerWord: number;
    /** Size of the encryption key in bytes */
    keySizeBytes: number;
    /** Size of the initialization vector in bytes */
    ivSizeBytes: number;
    /** Starting value for the counter */
    startCounter: number;
    /** Number of blocks processed in each chunk */
    blocksPerChunk: number;
    /** Whether the algorithm uses little-endian encoding */
    isLittleEndian: boolean;
    /** Function to convert Uint8Array to bits */
    uint8ArrayToBits: (arr: Uint8Array) => number[][];
    /** Function to convert bits to Uint8Array */
    bitsToUint8Array: (bits: number[]) => Uint8Array;
}
