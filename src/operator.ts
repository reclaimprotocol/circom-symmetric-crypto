import { CircuitWasm, EncryptionAlgorithm, Logger, VerificationKey, ZKOperator, ZKParams } from "./types";
import fetchRetry from 'fetch-retry';

type RemoteSnarkJsOperatorOpts = {
	zkeyUrl: string
	circuitWasmUrl: string
}

type WitnessData = {
	type: 'mem'
	data?: Uint8Array
}

// 5 pages is enough for the witness data
// calculation
const WITNESS_MEMORY_SIZE_PAGES = 5

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
			getZkey: async () => {
				const zkeyBuff = await fetchArrayBuffer(zkeyUrl)
				return {data: new Uint8Array(zkeyBuff)}

			},
			getCircuitWasm: async () => {
				const wasm = await fetchArrayBuffer(circuitWasmUrl)
				return new Uint8Array(wasm)
			}
		},
		logger
	)

	async function fetchArrayBuffer(url: string) {
		const retries = 3
		const fetchFunc = fetchRetry(fetch, {
			retryOn: (attempt, error, response) => {
				logger?.info(`Trying to fetch ${url} attempt ${attempt} of ${retries}...`)
				if (error !== null || response && response.status >= 400) {
					return attempt < retries;
				}
				return false;
			}
		})

		let response: Response
		try {
			response = await fetchFunc(url)
		} catch (e) {
			throw new Error(`Failed to fetch ${url} ${JSON.stringify([e, e.stack])}`)
		}
		if (!response.ok) {
			throw new Error(`Failed to fetch ${url} ${JSON.stringify([response.status, response.statusText])}`)
		}
		logger?.info(`Fetched ${url} successfully`)
		return await response.arrayBuffer()
	}
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

				// hack to allocate a specific memory size
				// because the Memory size isn't configurable
				// in the circom_runtime package
				const CurMemory = WebAssembly.Memory
				WebAssembly.Memory = class extends WebAssembly.Memory {
					constructor() {
						console.log('Creating memory')
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