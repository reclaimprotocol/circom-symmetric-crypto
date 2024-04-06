import { CircuitWasm, EncryptionAlgorithm, Logger, VerificationKey, ZKOperator, ZKParams } from "./types";

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
	let zkey: Promise<VerificationKey> | VerificationKey | undefined
	let circuitWasm: Promise<CircuitWasm> | CircuitWasm | undefined
	let wc: Promise<any> | undefined

	return {
		async generateWitness(input) {
			circuitWasm ||= getCircuitWasm()
			wc ||= (async() => {
				if(!snarkjs.wtns.getWtnsCalculator) {
					return
				}

				return snarkjs.wtns.getWtnsCalculator(
					await circuitWasm,
					logger
				)
			})()

			const wtns: WitnessData = { type: 'mem' }
			if(await wc) {
				await snarkjs.wtns.wtnsCalculateWithCalculator(
					input,
					await wc,
					wtns,
				)
			} else {
				await snarkjs.wtns.calculate(
					input,
					await circuitWasm,
					wtns,
				)
			}
			
			return wtns.data!
		},
		async groth16Prove(witness) {
			zkey ||= getZkey()
			return snarkjs.groth16.prove(
				(await zkey).data,
				witness,
				logger
			)
		},
		async groth16Verify(publicSignals, proof) {
			zkey ||= getZkey()
			const zkeyResult = await zkey
			if(!zkeyResult.json) {
				zkeyResult.json = await snarkjs.zKey
					.exportVerificationKey(zkeyResult.data)
			}

			return snarkjs.groth16.verify(
				zkeyResult.json!,
				publicSignals,
				proof,
				logger
			)
		},
		release() {
			zkey = undefined
			circuitWasm = undefined
			wc = undefined
		}
	}
}