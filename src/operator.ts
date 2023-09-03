import { Logger, ZKOperator, ZKParams } from "./types";

/**
 * Use for browser based environments, where we can't
 * load the WASM and zkey from the filesystem;
 * Also utilises a CDN for the snarkjs dependency
 */
export async function makeRemoteSnarkJsZkOperator(logger?: Logger) {
	const [wasm, zkey, snarkjs] = await Promise.all([
		// the circuit WASM
		fetch('https://reclaim-assets.s3.ap-south-1.amazonaws.com/circuit.wasm')
			.then((r) => r.arrayBuffer()),
		fetch('https://reclaim-assets.s3.ap-south-1.amazonaws.com/circuit_final.zkey')
			.then((r) => r.arrayBuffer()),
		fetch('https://raw.githubusercontent.com/iden3/snarkjs/v0.7.0/build/snarkjs.min.js')
			.then((r) => r.text())
	])
	const snarkjsCode = await eval(snarkjs)

	logger?.debug('loaded snarkjs & params remotely')

	return _makeSnarkJsZKOperator(
		{
			zkey: { data: new Uint8Array(zkey) },
			circuitWasm: new Uint8Array(wasm)
		},
		snarkjsCode,
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
		// require here to avoid loading snarkjs in
		// any unsupported environments
		require('snarkjs/build/snarkjs.min.js'),
		logger
	)
}

function _makeSnarkJsZKOperator(
	{ circuitWasm, zkey }: ZKParams,
	snarkjs: any,
	logger?: Logger
): ZKOperator {
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