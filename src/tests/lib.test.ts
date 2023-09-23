import {
	PrivateInput,
	ZK_CIRCUIT_CHUNK_SIZE,
	generateProof,
	makeLocalSnarkJsZkOperator,
	verifyProof,
	toUint8Array,
	ZKOperator,
	toUintArray
} from '../index'
import { encryptData } from "./utils";

const ENC_LENGTH = 45

jest.setTimeout(20_000)

describe('Library Tests', () => {

	let operator: ZKOperator
	beforeAll(async() => {
		operator = await makeLocalSnarkJsZkOperator()
	})

	it('should verify encrypted data', async() => {
		const plaintext = new Uint8Array(ENC_LENGTH)
			.fill(1)

		const privInputs: PrivateInput = {
			key: Buffer.alloc(32, 2),
			iv: Buffer.alloc(12, 3),
			startCounter: 1,
		}

		const ciphertext = encryptData(plaintext, privInputs.key, privInputs.iv)

		const pubInputs = { ciphertext }
		const proof = await generateProof(privInputs, pubInputs, operator)
		expect(
			toUint8Array(proof.plaintext)
				.slice(0, plaintext.length)
		).toEqual(
			plaintext
		)
		// client will send proof to witness
		// witness would verify proof
		await verifyProof(proof, pubInputs, operator)
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

		const proof = await generateProof(privInputs, pubInputs, operator)
		proof.plaintext = new Uint32Array(ZK_CIRCUIT_CHUNK_SIZE)

		await expect(
			verifyProof(proof, pubInputs, operator)
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
		const pubInputs = { ciphertext }
		const proof = await generateProof(privInputs, pubInputs, operator)
		await verifyProof(proof, pubInputs, operator)
		expect(
			plaintext
		).toEqual(
			Buffer.from(toUint8Array(proof.plaintext))
				.subarray(0, plaintext.length)
		)
	})
})