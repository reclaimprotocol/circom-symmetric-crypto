import { randomBytes } from 'crypto';
import {
	PrivateInput,
	generateProof,
	makeLocalSnarkJsZkOperator,
	verifyProof,
	ZKOperator,
	EncryptionAlgorithm,
	CONFIG,
} from '../index'
import { encryptData } from "./utils";

jest.setTimeout(20_000)

const ALL_ALGOS: EncryptionAlgorithm[] = [
	'chacha20',
	'aes-256-ctr',
	'aes-128-ctr',
]

const ALG_TEST_CONFIG = {
	'chacha20': {
		encLength: 45,
	},
	'aes-256-ctr': {
		encLength: 44,
	},
	'aes-128-ctr': {
		encLength: 44,
	},
}

describe.each(ALL_ALGOS)('%s Lib Tests', (algorithm) => {

	const {
		encLength,
	} = ALG_TEST_CONFIG[algorithm]
	const {
		bitsPerWord,
		chunkSize,
		keySizeBytes
	} = CONFIG[algorithm]

	const chunkSizeBytes = chunkSize * bitsPerWord / 8

	let operator: ZKOperator
	beforeAll(async() => {
		operator = await makeLocalSnarkJsZkOperator(algorithm)
	})

	it('should verify encrypted data', async() => {
		const plaintext = new Uint8Array(randomBytes(encLength))

		const privInputs: PrivateInput = {
			key: Buffer.alloc(keySizeBytes, 2),
			iv: Buffer.alloc(12, 3),
			offset: 0,
		}

		const ciphertext = encryptData(
			algorithm,
			plaintext,
			privInputs.key,
			privInputs.iv
		)

		const pubInputs = { ciphertext }
		const proof = await generateProof(
			algorithm, privInputs,
			pubInputs, operator
		)
		// ensure the ZK decrypted data matches the plaintext
		expect(
			proof.plaintext
				.slice(0, plaintext.length)
		).toEqual(
			plaintext
		)
		// client will send proof to witness
		// witness would verify proof
		await verifyProof(proof, pubInputs, operator)
	})

	it('should verify encrypted data with another counter', async() => {
		const totalPlaintext = new Uint8Array(randomBytes(chunkSizeBytes * 5))
		// use a chunk in the middle
		const offset = 2
		const plaintext = totalPlaintext
			.subarray(chunkSizeBytes*offset, chunkSizeBytes * (offset + 1))

		const privInputs: PrivateInput = {
			key: Buffer.alloc(keySizeBytes, 2),
			iv: Buffer.alloc(12, 3),
			offset,
		}

		const totalCiphertext = encryptData(
			algorithm,
			totalPlaintext,
			privInputs.key,
			privInputs.iv
		)
		const ciphertext = totalCiphertext
			.subarray(chunkSizeBytes*offset, chunkSizeBytes * (offset + 1))

		const pubInputs = { ciphertext }
		const proof = await generateProof(algorithm, privInputs, pubInputs, operator)
		// ensure the ZK decrypted data matches the plaintext
		expect(
			proof.plaintext
				.slice(0, plaintext.length)
		).toEqual(
			plaintext
		)
	})

	it('should fail to verify incorrect data', async() => {
		const plaintext = Buffer.alloc(encLength, 1)

		const privInputs: PrivateInput = {
			key: Buffer.alloc(keySizeBytes, 2),
			iv: Buffer.alloc(12, 3),
			offset: 0,
		}

		const ciphertext = encryptData(
			algorithm,
			plaintext,
			privInputs.key,
			privInputs.iv
		)
		const pubInputs = { ciphertext }

		const proof = await generateProof(algorithm, privInputs, pubInputs, operator)
		// fill output with 0s
		for(let i = 0;i < proof.plaintext.length;i++) {
			proof.plaintext[i] = 0
		}

		await expect(
			verifyProof(proof, pubInputs, operator)
		).rejects.toHaveProperty('message', 'invalid proof')
	})
})