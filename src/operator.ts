import { CircuitWasm, EncryptionAlgorithm, VerificationKey, ZKOperator, ZKParams } from "./types";

type WitnessData = {
	type: 'mem'
	data?: Uint8Array
}

// 5 pages is enough for the witness data
// calculation
const WITNESS_MEMORY_SIZE_PAGES = 5

/**
 * Make a ZK operator from the snarkjs dependency
 * @param logger 
 * @returns 
 */
export async function makeLocalSnarkJsZkOperator(
	type: EncryptionAlgorithm,
) {
	const { join } = await import('path')
	const folder = `../resources/${type}`
	return makeSnarkJsZKOperator(
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
	)
}

/**
 * Make a SnarkJS ZK operator from the provided
 * fns to get the circuit wasm and zkey
 */
export function makeSnarkJsZKOperator(
	{ getCircuitWasm, getZkey }: ZKParams,
): ZKOperator {
	// require here to avoid loading snarkjs in
	// any unsupported environments
	const snarkjs = require('snarkjs')
	let zkey: Promise<VerificationKey> | VerificationKey | undefined
	let circuitWasm: Promise<CircuitWasm> | CircuitWasm | undefined
	let wc: Promise<any> | undefined

	return {
		async generateWitness(input, logger) {
			circuitWasm ||= getCircuitWasm()
			wc ||= (async() => {
				if(!snarkjs.wtns.getWtnsCalculator) {
					return
				}

				// hack to allocate a specific memory size
				// because the Memory size isn't configurable
				// in the circom_runtime package
				const CurMemory = WebAssembly.Memory
				WebAssembly.Memory = class extends WebAssembly.Memory {
					constructor() {
						super({ initial: WITNESS_MEMORY_SIZE_PAGES })
					}
				}

				try {
					const rslt = await snarkjs.wtns.getWtnsCalculator(
						await circuitWasm,
						logger
					)

					return rslt
				} finally {
					WebAssembly.Memory = CurMemory
				}
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
		async groth16Prove(witness, logger) {
			zkey ||= getZkey()
			return snarkjs.groth16.prove(
				(await zkey).data,
				witness,
				logger
			)
		},
		async groth16Verify(publicSignals, proof, logger) {
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