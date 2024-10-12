import { CONFIG } from "./config";
import { EncryptionAlgorithm, UintArray } from "./types";

export const BITS_PER_WORD = 32;
export const REDACTION_CHAR_CODE = '*'.charCodeAt(0);

/**
 * Converts a Uint8Array to a Uint32Array.
 * Uses DataView for optimized memory access.
 */
export function toUintArray(buf: Uint8Array): UintArray {
    const length = buf.length / 4;
    const arr = new Uint32Array(length);
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    for (let i = 0; i < length; i++) {
        arr[i] = view.getUint32(i * 4, true);
    }
    return arr;
}

/**
 * Converts a Uint32Array to a Uint8Array.
 */
export function toUint8Array(buf: UintArray): Uint8Array {
    const arr = new Uint8Array(buf.length * 4);
    const view = new DataView(arr.buffer);
    for (let i = 0; i < buf.length; i++) {
        view.setUint32(i * 4, buf[i], true);
    }
    return arr;
}

/**
 * Pads a Uint8Array to ensure its length is a multiple of 4.
 */
export function padU8ToU32Array(buf: Uint8Array): Uint8Array {
    const paddingLength = (4 - (buf.length % 4)) % 4;
    if (paddingLength === 0) return buf;

    const paddedArray = new Uint8Array(buf.length + paddingLength);
    paddedArray.set(buf);
    paddedArray.fill(REDACTION_CHAR_CODE, buf.length);
    return paddedArray;
}

/**
 * Pads a UintArray to the specified size with REDACTION_CHAR_CODE.
 */
export function padArray(buf: UintArray, size: number): UintArray {
    if (buf.length >= size) return buf;
    const paddedArray = new Uint32Array(size);
    paddedArray.set(buf);
    paddedArray.fill(REDACTION_CHAR_CODE, buf.length);
    return paddedArray;
}

/**
 * Converts a Uint8Array to an array of bits in BE order.
 */
export function uint8ArrayToBits(buf: Uint8Array): number[] {
    const bits: number[] = [];
    for (const byte of buf) {
        for (let i = 7; i >= 0; i--) {
            bits.push((byte >> i) & 1);
        }
    }
    return bits;
}

/**
 * Converts an array of bits to a Uint8Array in BE order.
 */
export function bitsToUint8Array(bits: number[]): Uint8Array {
    const length = bits.length / 8;
    const arr = new Uint8Array(length);
    for (let i = 0; i < bits.length; i += 8) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            byte = (byte << 1) | bits[i + j];
        }
        arr[i / 8] = byte;
    }
    return arr;
}

/**
 * Converts a UintArray to an array of bits in LE order.
 */
export function uintArrayToBits(buf: UintArray): number[] {
    const bits: number[] = [];
    for (const uint of buf) {
        for (let i = 0; i < BITS_PER_WORD; i++) {
            bits.push((uint >> i) & 1);
        }
    }
    return bits;
}

/**
 * Converts an array of bits to a UintArray in LE order.
 */
export function bitsToUintArray(bits: number[]): UintArray {
    const length = bits.length / BITS_PER_WORD;
    const arr = new Uint32Array(length);
    for (let i = 0; i < bits.length; i += BITS_PER_WORD) {
        let uint = 0;
        for (let j = BITS_PER_WORD - 1; j >= 0; j--) {
            uint = (uint << 1) | bits[i + j];
        }
        arr[i / BITS_PER_WORD] = uint;
    }
    return arr;
}

/**
 * Combines a 12-byte nonce with a 4-byte counter to form a 16-byte IV.
 */
export function getFullCounterIv(nonce: Uint8Array, counter: number): Buffer {
    const iv = Buffer.alloc(16);
    iv.set(nonce, 0);
    iv.writeUInt32BE(counter, 12);
    return iv;
}

/**
 * Computes the counter value for a given chunk.
 */
export function getCounterForChunk(
    algorithm: EncryptionAlgorithm,
    offsetInChunks: number
): number {
    const { startCounter, blocksPerChunk } = CONFIG[algorithm];
    return startCounter + offsetInChunks * blocksPerChunk;
}
