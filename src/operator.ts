import type { Logger } from "pino";
import { join } from 'path'
import { ZKOperator, ZKParams } from "./types";

/**
 * Make a ZK operator from the snarkjs dependency
 * @param logger 
 * @returns 
 */
export function makeSnarkJsZKOperator(logger?: Logger) {
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