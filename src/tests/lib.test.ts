import {
	PrivateInput,
	ZK_CIRCUIT_CHUNK_SIZE,
	generateProof,
	makeSnarkJsZKOperator,
	verifyProof,
	toUint8Array
} from '../index'
import { encryptData } from "./utils";

const OPERATOR = makeSnarkJsZKOperator()

const ENC_LENGTH = 45

jest.setTimeout(20_000)

describe('Library Tests', () => {

	it('should verify encrypted data', async() => {
		const plaintext = Buffer.alloc(ENC_LENGTH, 1)

		const privInputs: PrivateInput = {
			key: Buffer.alloc(32, 2),
			iv: Buffer.alloc(12, 3),
			startCounter: 1,
		}

		const ciphertext = encryptData(plaintext, privInputs.key, privInputs.iv)

		const pubInputs = {
			ciphertext,
			redactedPlaintext: plaintext,
		}

		const proof = await generateProof(privInputs, pubInputs, OPERATOR)
		// client will send proof to witness
		// witness would verify proof
		await verifyProof(proof, pubInputs, OPERATOR)
	})

	it('should fail to verify incorrect data', async() => {
		const plaintext = Buffer.alloc(ENC_LENGTH, 1)

		const privInputs: PrivateInput = {
			key: Buffer.alloc(32, 2),
			iv: Buffer.alloc(12, 3),
			startCounter: 1,
		}

		const ciphertext = encryptData(plaintext, privInputs.key, privInputs.iv)
		const pubInputs = { ciphertext }

		const proof = await generateProof(privInputs, pubInputs, OPERATOR)
		proof.plaintext = new Uint32Array(ZK_CIRCUIT_CHUNK_SIZE)

		await expect(
			verifyProof(proof, pubInputs, OPERATOR)
		).rejects.toHaveProperty('message', 'invalid proof')
	})


	it('decrypted data should match plaintext', async() => {
		const plaintext = Buffer.from('My cool API secret is "')
		const privInputs: PrivateInput = {
			key: Buffer.alloc(32, 2),
			iv: Buffer.alloc(12, 3),
			startCounter: 1,
		}
		const ciphertext = encryptData(plaintext, privInputs.key, privInputs.iv)
		const pubInputs = {
			ciphertext,
			redactedPlaintext: plaintext,
		}
		const proof = await generateProof(privInputs, pubInputs, OPERATOR)
		await verifyProof(proof, pubInputs, OPERATOR)
		expect(plaintext).toEqual(Buffer.from(toUint8Array(proof.plaintext)).subarray(0,plaintext.length))
	})
})