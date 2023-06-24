import { randomBytes } from "crypto";
import { PrivateInput } from '../types'
import {generateProof, makeZKOperatorFromLocalFiles, REDACTION_CHAR_CODE, verifyProof} from '../index'
import { encryptData } from "../utils";

const OPERATOR = makeZKOperatorFromLocalFiles()

const ENC_LENGTH = 128

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

	it('should verify redacted data', async() => {
		const plaintext = Buffer.alloc(ENC_LENGTH, 1)

		const privInputs: PrivateInput = {
			key: Buffer.alloc(32, 2),
			iv: Buffer.alloc(12, 3),
			startCounter: 1,
		}

		const ciphertext = encryptData(plaintext, privInputs.key, privInputs.iv)

		// redact last 10 bytes
		const pubInputs = {
			ciphertext: Buffer.concat([
				ciphertext.subarray(0, ENC_LENGTH - 10),
				Buffer.alloc(10, REDACTION_CHAR_CODE)
			]),
			redactedPlaintext: Buffer.concat([
				plaintext.subarray(0, ENC_LENGTH - 10),
				Buffer.alloc(10, REDACTION_CHAR_CODE)
			]),
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

		// redact last 10 bytes
		const pubInputs = {
			ciphertext,
			redactedPlaintext: randomBytes(ENC_LENGTH),
		}

		const proof = await generateProof(privInputs, pubInputs, OPERATOR)
		await expect(
			verifyProof(proof, pubInputs, OPERATOR)
		).rejects.toHaveProperty('message', 'redacted ciphertext (0) not congruent')
	})
})