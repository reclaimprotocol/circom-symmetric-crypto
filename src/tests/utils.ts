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