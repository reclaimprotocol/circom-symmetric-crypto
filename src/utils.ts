import { CONFIG } from "./config";
import { EncryptionAlgorithm, UintArray } from "./types";

export const BITS_PER_WORD = 32;
export const REDACTION_CHAR_CODE = '*'.charCodeAt(0);

/**
 * Convert a Uint8Array to a Uint32Array
 * @param buf - Input Uint8Array
 * @returns Uint32Array
 */
export function toUintArray(buf: Uint8Array): Uint32Array {
    const arr = new Uint32Array(buf.length / 4);
    const arrView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    for (let i = 0; i < arr.length; i++) {
        arr[i] = arrView.getUint32(i * 4, true);
    }
    return arr;
}

/**
 * Create a Uint32Array from a number or array of numbers
 * @param init - Initial value or array
 * @returns Uint32Array
 */
export function makeUintArray(init: number | number[]): Uint32Array {
    return typeof init === 'number' ? new Uint32Array(init) : Uint32Array.from(init);
}

/**
 * Convert a UintArray (uint32array) to a Uint8Array
 * @param buf - Input UintArray
 * @returns Uint8Array
 */
export function toUint8Array(buf: UintArray): Uint8Array {
    const arr = new Uint8Array(buf.length * 4);
    const arrView = new DataView(arr.buffer);
    buf.forEach((value, i) => arrView.setUint32(i * 4, value, true));
    return arr;
}

/**
 * Pad a Uint8Array to a multiple of 4 bytes
 * @param buf - Input Uint8Array
 * @returns Padded Uint8Array
 */
export function padU8ToU32Array(buf: Uint8Array): Uint8Array {
    if (buf.length % 4 === 0) return buf;
    const paddingLength = 4 - (buf.length % 4);
    return new Uint8Array([...buf, ...new Array(paddingLength).fill(REDACTION_CHAR_CODE)]);
}

/**
 * Create a Uint8Array from a number or array of numbers
 * @param init - Initial value or array
 * @returns Uint8Array
 */
export function makeUint8Array(init: number | number[]): Uint8Array {
    return typeof init === 'number' ? new Uint8Array(init) : Uint8Array.from(init);
}

/**
 * Pad a UintArray to a specified size
 * @param buf - Input UintArray
 * @param size - Desired size
 * @returns Padded UintArray
 */
export function padArray(buf: UintArray, size: number): UintArray {
    if (buf.length >= size) return buf;
    return makeUintArray([...Array.from(buf), ...new Array(size - buf.length).fill(REDACTION_CHAR_CODE)]);
}

/**
 * Converts a Uint8Array to an array of bits in BE order
 * @param buff - Input Uint8Array or number array
 * @returns Array of bits
 */
export function uint8ArrayToBits(buff: Uint8Array | number[]): number[] {
    return Array.from(buff).flatMap(byte => 
        Array.from({length: 8}, (_, i) => (byte >> (7 - i)) & 1)
    );
}

/**
 * Converts an array of bits to a Uint8Array (BE order)
 * @param bits - Input array of bits
 * @returns Uint8Array
 */
export function bitsToUint8Array(bits: number[]): Uint8Array {
    const arr = new Uint8Array(bits.length / 8);
    for (let i = 0; i < bits.length; i += 8) {
        arr[i / 8] = bitsToNum(bits.slice(i, i + 8));
    }
    return arr;
}

/**
 * Converts a Uint32Array to an array of bits in LE order
 * @param uintArray - Input UintArray or number array
 * @returns Array of arrays of bits
 */
export function uintArrayToBits(uintArray: UintArray | number[]): number[][] {
    return Array.from(uintArray).map(numToBitsNumerical);
}

/**
 * Converts an array of bits to a Uint32Array
 * @param bits - Input array of bits
 * @returns Uint32Array
 */
export function bitsToUintArray(bits: number[]): Uint32Array {
    const uintArray = new Uint32Array(bits.length / BITS_PER_WORD);
    for (let i = 0; i < bits.length; i += BITS_PER_WORD) {
        uintArray[i / BITS_PER_WORD] = bitsToNum(bits.slice(i, i + BITS_PER_WORD));
    }
    return uintArray;
}

/**
 * Converts a number to an array of bits
 * @param num - Input number
 * @param bitCount - Number of bits (default: BITS_PER_WORD)
 * @returns Array of bits
 */
function numToBitsNumerical(num: number, bitCount = BITS_PER_WORD): number[] {
    return Array.from({length: bitCount}, (_, i) => (num & (1 << (bitCount - 1 - i))) ? 1 : 0);
}

/**
 * Converts an array of bits to a number
 * @param bits - Input array of bits
 * @returns Number
 */
function bitsToNum(bits: number[]): number {
    return bits.reduce((num, bit, index) => num + (bit << (bits.length - 1 - index)), 0);
}

/**
 * Combines a 12 byte nonce with a 4 byte counter to make a 16 byte IV
 * @param nonce - 12 byte nonce
 * @param counter - 4 byte counter
 * @returns 16 byte IV
 */
export function getFullCounterIv(nonce: Uint8Array, counter: number): Buffer {
    const iv = Buffer.alloc(16);
    iv.set(nonce, 0);
    iv.writeUInt32BE(counter, 12);
    return iv;
}

/**
 * Get the counter to use for a given chunk
 * @param algorithm - Encryption algorithm
 * @param offsetInChunks - Offset in chunks
 * @returns Counter for the chunk
 */
export function getCounterForChunk(
    algorithm: EncryptionAlgorithm,
    offsetInChunks: number
): number {
    const { startCounter, blocksPerChunk } = CONFIG[algorithm];
    return startCounter + offsetInChunks * blocksPerChunk;
}
