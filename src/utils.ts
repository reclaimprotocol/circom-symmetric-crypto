import { UintArray } from "./types"

// we use this to pad the ciphertext
export const REDACTION_CHAR_CODE = '*'.charCodeAt(0)

export function toUintArray(buf: Uint8Array) {
	const arr = makeUintArray(buf.length / 4)
	const arrView = new DataView(arr.buffer, arr.byteOffset, arr.byteLength)
	for(let i = 0;i < arr.length;i++) {
		arr[i] = arrView.getUint32(i * 4)
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
	const arr = new Uint8Array(buf.length * 4)
	const arrView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
	for(let i = 0;i < buf.length;i++) {
		arrView.setUint32(i * 4, buf[i])
	}
	return arr
}


export function padU8ToU32Array(buf: Uint8Array): Uint8Array {

	if(buf.length % 4 === 0) {
		return buf
	}

	return makeUint8Array(
		[
			...Array.from(buf),
			...new Array(4 - buf.length % 4).fill(REDACTION_CHAR_CODE)
		]
	)
}

export function makeUint8Array(init: number | number[]) {
	return typeof init === 'number'
		? new Uint8Array(init)
		: Uint8Array.from(init)
}

export function padArray(buf: UintArray, size: number): UintArray {
	return makeUintArray(
		[
			...Array.from(buf),
			...new Array(size - buf.length).fill(REDACTION_CHAR_CODE)
		]
	)
}