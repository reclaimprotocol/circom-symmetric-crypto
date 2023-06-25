import { UintArray } from "./types"

export function toUintArray(buf: Uint8Array | Buffer) {
	buf = Buffer.isBuffer(buf) ? buf : Buffer.from(buf)
	const arr = makeUintArray(buf.length / 4)
	for(let i = 0;i < arr.length;i++) {
		arr[i] = (buf as Buffer).readUInt32LE(i * 4)
	}
	return arr
}

export function makeUintArray(init: number | number[]) {
	return typeof init === 'number'
		? new Uint32Array(init)
		: Uint32Array.from(init)
}

/**
 * Convert a UintArray (uint32array) to a Uint8Array
 */
export function toUint8Array(buf: UintArray) {
	const arr = Buffer.alloc(buf.length * 4)
	for(let i = 0;i < buf.length;i++) {
		arr.writeUInt32LE(buf[i], i * 4)
	}
	return arr
}