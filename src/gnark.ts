import {EncryptionAlgorithm, ZKOperator} from "./types";
import {join} from "path";

let koffi = require('koffi');


let verify:(...args: any[]) => any
let free:(...args: any[]) => any
let prove:(...args: any[]) => any
let initAlgorithm:(...args: any[]) => any

let initDone = false

try {
	if(koffi?.version){
		koffi.reset() //otherwise tests will fail

		// define object GoSlice to map to:
		// C type struct { void *data; GoInt len; GoInt cap; }
		const GoSlice = koffi.struct('GoSlice', {
			data: 'void *',
			len:  'longlong',
			cap: 'longlong'
		})

		const ProveReturn = koffi.struct('ProveReturn', {
			r0: 'void *',
			r1:  'longlong',
		})


		const resFolder = `../resources/gnark`

		const arch = process.arch

		const libVerifyPath = join(
			__dirname,
			`${resFolder}/${arch}/libverify.so`
		)

		const libProvePath = join(
			__dirname,
			`${resFolder}/${arch}/libprove.so`
		)

		const libVerify = koffi.load(libVerifyPath)
		const libProve = koffi.load(libProvePath)

		verify = libVerify.func('Verify', 'unsigned char', [GoSlice])
		free = libProve.func('Free', 'void', ['void *'])
		prove = libProve.func('Prove', ProveReturn, [GoSlice])
		initAlgorithm = libProve.func('InitAlgorithm', 'unsigned char', ['unsigned char', GoSlice, GoSlice])
	}
} catch (e){
	koffi = undefined
	console.log("Gnark is only supported on linux x64 & ARM64.", e.toString())
}


export async function makeLocalGnarkZkOperator(cipher: EncryptionAlgorithm): Promise<ZKOperator> {

	if(koffi){

		async function initGnark(){
			const { join } = await import('path')

			const fs = require('fs')

			const folder = `../resources/gnark`

			let keyPath = join(__dirname,`${folder}/pk.chacha20`)
			let keyFile = fs.readFileSync(keyPath)

			let r1Path = join(__dirname,`${folder}/r1cs.chacha20`)
			let r1File = fs.readFileSync(r1Path)

			let f1 = {
				data: Buffer.from(keyFile),
				len:keyFile.length,
				cap:keyFile.length
			}
			let f2 = {
				data: Buffer.from(r1File),
				len:r1File.length,
				cap:r1File.length
			}

			initAlgorithm(0,f1, f2)


			keyPath = join(__dirname,`${folder}/pk.aes128`)
			keyFile = fs.readFileSync(keyPath)

			r1Path = join(__dirname,`${folder}/r1cs.aes128`)
			r1File = fs.readFileSync(r1Path)

			f1 = {
				data: Buffer.from(keyFile),
				len:keyFile.length,
				cap:keyFile.length
			}
			f2 = {
				data: Buffer.from(r1File),
				len:r1File.length,
				cap:r1File.length
			}

			initAlgorithm(1,f1, f2)


			keyPath = join(__dirname,`${folder}/pk.aes256`)
			keyFile = fs.readFileSync(keyPath)

			r1Path = join(__dirname,`${folder}/r1cs.aes256`)
			r1File = fs.readFileSync(r1Path)

			f1 = {
				data: Buffer.from(keyFile),
				len:keyFile.length,
				cap:keyFile.length
			}
			f2 = {
				data: Buffer.from(r1File),
				len:r1File.length,
				cap:r1File.length
			}

			initAlgorithm(2,f1, f2)
			initDone = true
		}


		return Promise.resolve({

			async generateWitness(input): Promise<Uint8Array> {
				return generateGnarkWitness(cipher, input)
			},

			//used in nodeJS only for tests
			async groth16Prove(witness: Uint8Array) {

				if (!initDone){
					await initGnark()
				}

				const wtns = {
					data: Buffer.from(witness),
					len:witness.length,
					cap:witness.length
				}
				const res = prove(wtns)
				const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString()
				free(res.r0) // Avoid memory leak!
				return Promise.resolve(JSON.parse(resJson))
			},

			async groth16Verify(publicSignals, proof) {
				const proofStr = proof['proofJson']

				const verifyParams = {
					cipher:cipher,
					proof: proofStr,
					publicSignals: publicSignals,
				}

				const paramsJson = JSON.stringify(verifyParams)
				const paramsBuf = strToUint8Array(paramsJson)

				const params = {
					data: paramsBuf,
					len:paramsJson.length,
					cap:paramsJson.length

				}

				return verify(params) === 1
			},

		})
	} else {
		return Promise.resolve({
			async generateWitness(input): Promise<Uint8Array> {
				return generateGnarkWitness(cipher, input)
			},

			async groth16Prove(witness) {
				throw new Error("not supported")
			},

			async groth16Verify(publicSignals, proof) {
				throw new Error("not supported")
			},

		})
	}
}

function generateGnarkWitness(cipher, input){
	//input is already in bits, sometimes groups of bits
	const proofParams = {
		cipher:cipher,
		key: input.key,
		nonce: input.nonce,
		counter: input.counter,
		input: input.in,
	}

	const paramsJson = JSON.stringify(proofParams)
	return strToUint8Array(paramsJson)
}

function strToUint8Array(str: string) {
	return new TextEncoder().encode(str)
}

