import { createCipheriv } from "crypto"
import { uint8ArrayToBits } from "../utils"
import { loadCircuit } from "./utils"

describe('AES circuits Tests', () => {

	it('should encrypt an AES-256-CTR block', async() => {
		const circuit = await loadCircuit('aes-256-ctr')

		const vectors = [
			{
				keyBytes: Buffer.from(
					[
						0x00, 0x01, 0x02, 0x03,
						0x04, 0x05, 0x06, 0x07,
						0x08, 0x09, 0x0a, 0x0b,
						0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13,
						0x14, 0x15, 0x16, 0x17,
						0x18, 0x19, 0x1a, 0x1b,
						0x1c, 0x1d, 0x1e, 0x1f
					]
				),
				nonceBytes: Buffer.from(
					[
						0x01, 0x02, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x4a,
						0x00, 0x00, 0x00, 0x09,
					]
				),
				counter: 2,
				plaintextBytes: Buffer.from(
					[
						0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
						0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
					]
				),
			}
		]

		for(const {
			keyBytes,
			nonceBytes,
			plaintextBytes,
			counter
		} of vectors) {
			const cipher = createCipheriv('aes-256-gcm', keyBytes, nonceBytes)
			const ciphertextBytes = Buffer.concat([
				cipher.update(plaintextBytes),
				cipher.final()
			])

			const ciphertextBits = uint8ArrayToBits(ciphertextBytes)
			const plaintextBits = uint8ArrayToBits(plaintextBytes)
			const iv = getFullIv(nonceBytes, counter)
			const w = await circuit.calculateWitness({
				K1: uint8ArrayToBits(keyBytes),
				CTR: uint8ArrayToBits(iv),
				MSG: ciphertextBits,
			})
			
			await circuit.checkConstraints(w)
			await circuit.assertOut(w, {
				CT: plaintextBits
			})
		}
	})

	function getFullIv(nonce: Uint8Array, counter: number) {
		const iv = Buffer.alloc(16)
		iv.set(nonce, 0)
		iv.writeUInt32BE(counter, 12)

		return iv
	}
})