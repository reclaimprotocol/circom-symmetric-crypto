import { EncryptionAlgorithm, Logger, ZKOperator, ZKParams } from "./types";

type RemoteSnarkJsOperatorOpts = {
	zkeyUrl: string
	circuitWasmUrl: string
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
			zkey: { data: new Uint8Array(zkey) },
			circuitWasm: new Uint8Array(wasm)
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
			zkey: {
				data: join(
					__dirname,
					`${folder}/circuit_final.zkey`
				)
			},
			circuitWasm: join(
				__dirname,
				`${folder}/circuit.wasm`
			),
		},
		logger
	)
}

function _makeSnarkJsZKOperator(
	{ circuitWasm, zkey }: ZKParams,
	logger?: Logger
): ZKOperator {
	// require here to avoid loading snarkjs in
	// any unsupported environments
	const snarkjs = require('snarkjs')

	return {
		groth16FullProve(input) {
			return snarkjs.groth16.fullProve(input, circuitWasm, zkey.data, logger)
		},
		async groth16Verify(publicSignals, proof) {
			if(!zkey.json) {
				zkey.json = await snarkjs.zKey.exportVerificationKey(zkey.data)
			}

			return snarkjs.groth16.verify(zkey.json!, publicSignals, proof, logger)
		}
	}
}