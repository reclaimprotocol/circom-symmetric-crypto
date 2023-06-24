import { createCipheriv } from "crypto"

export function encryptData(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array) {
	// chacha20 encrypt
	const cipher = createCipheriv(
		'chacha20-poly1305',
		key,
		iv,
	)
	return Buffer.concat([
		cipher.update(plaintext),
		cipher.final()
	])
}

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