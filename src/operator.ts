import { EncryptionAlgorithm, Logger, VerificationKey, ZKOperator, ZKParams } from "./types";

type RemoteSnarkJsOperatorOpts = {
	zkeyUrl: string
	circuitWasmUrl: string
}

type WitnessData = {
	type: 'mem'
	data?: Uint8Array
}

/**
 * Use for browser based environments, where we can't
 * load the WASM and zkey from the filesystem
 */
export async function makeRemoteSnarkJsZkOperator(
	{ zkeyUrl, circuitWasmUrl }: RemoteSnarkJsOperatorOpts,
	logger?: Logger
) {
	const [wasm, zkey] = await Promise.all([
		// the circuit WASM
		fetch(circuitWasmUrl)
			.then((r) => r.arrayBuffer()),
		fetch(zkeyUrl)
			.then((r) => r.arrayBuffer()),
	])

	// snarkjs needs to know that we're
	// in a browser environment
	if(
		typeof window !== 'undefined'
		&& window.process === undefined
	) {
		// @ts-ignore
		window.process = { browser: true }
	}

	return _makeSnarkJsZKOperator(
		{
			getZkey: async() => {
				const rslt = await fetch(zkeyUrl)
				const zkeyBuff = await rslt.arrayBuffer()
				return { data: new Uint8Array(zkeyBuff) }
			},
			getCircuitWasm: async() => {
				const rslt = await fetch(circuitWasmUrl)
				const wasm = await rslt.arrayBuffer()
				return new Uint8Array(wasm)
			}
		},
		logger
	)
}

/**
 * Make a ZK operator from the snarkjs dependency
 * @param logger 
 * @returns 
 */
export async function makeLocalSnarkJsZkOperator(
	type: EncryptionAlgorithm,
	logger?: Logger
) {
	const { join } = await import('path')
	const folder = `../resources/${type}`
	return _makeSnarkJsZKOperator(
		{
			getZkey: () => ({
				data: join(
					__dirname,
					`${folder}/circuit_final.zkey`
				)
			}),
			getCircuitWasm: () => join(
				__dirname,
				`${folder}/circuit.wasm`
			),
		},
		logger
	)
}

function _makeSnarkJsZKOperator(
	{ getCircuitWasm, getZkey }: ZKParams,
	logger?: Logger
): ZKOperator {
	// require here to avoid loading snarkjs in
	// any unsupported environments
	const snarkjs = require('snarkjs')
	let zkey: VerificationKey
	let circuitWasm: Uint8Array | string

	return {
		async generateWitness(input) {
			circuitWasm ||= await getCircuitWasm()
			const wtns: WitnessData = { type: 'mem' }
			await snarkjs.wtns.calculate(input, circuitWasm, wtns, logger)
			return wtns.data!
		},
		async groth16Prove(witness) {
			zkey ||= await getZkey()
			return snarkjs.groth16.prove(zkey.data, witness, logger)
		},
		async groth16Verify(publicSignals, proof) {
			if(!zkey.json) {
				zkey.json = await snarkjs.zKey.exportVerificationKey(zkey.data)
			}

			return snarkjs.groth16.verify(zkey.json!, publicSignals, proof, logger)
		}
	}
}