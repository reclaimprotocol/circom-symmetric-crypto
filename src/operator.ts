import { Logger, ZKOperator, ZKParams } from "./types";

/**
 * Use for browser based environments, where we can't
 * load the WASM and zkey from the filesystem
 */
export async function makeRemoteSnarkJsZkOperator(logger?: Logger) {
	const [wasm, zkey] = await Promise.all([
		// the circuit WASM
		fetch('https://reclaim-assets.s3.ap-south-1.amazonaws.com/circuit.wasm')
			.then((r) => r.arrayBuffer()),
		fetch('https://reclaim-assets.s3.ap-south-1.amazonaws.com/circuit_final.zkey')
			.then((r) => r.arrayBuffer()),
	])
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
export async function makeLocalSnarkJsZkOperator(logger?: Logger) {
	const { join } = await import('path')
	return _makeSnarkJsZKOperator(
		{
			zkey: {
				data: join(
					__dirname,
					'../resources/circuit_final.zkey'
				)
			},
			circuitWasm: join(
				__dirname,
				'../resources/circuit.wasm'
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