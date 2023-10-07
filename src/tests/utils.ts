import { wasm as WasmTester } from 'circom_tester'
import { createCipheriv } from "crypto"
import { join } from "path"
import { EncryptionAlgorithm } from '../types'

export function encryptData(
	algorithm: EncryptionAlgorithm,
	plaintext: Uint8Array,
	key: Uint8Array,
	iv: Uint8Array
) {
	// chacha20 encrypt
	const cipher = createCipheriv(
		algorithm === 'chacha20'
			? 'chacha20-poly1305'
			: 'aes-256-gcm',
		key,
		iv,
	)
	return Buffer.concat([
		cipher.update(plaintext),
		cipher.final()
	])
}

export function loadCircuit(name: string) {
	return WasmTester(join(__dirname, `../../circuits/tests/${name}.circom`))
}