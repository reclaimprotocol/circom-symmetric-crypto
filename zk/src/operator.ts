import type { Logger } from "pino";
import { join } from 'path'
import { ZKOperator, ZKParams } from "./types";

export function makeZKOperatorFromLocalFiles(logger?: Logger) {
	return makeSnarkJsOperator(
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

export function makeZKOperatorFromJson(logger?: Logger) {
	const json = require('../resources/zk-params.json')
	return makeSnarkJsOperator(
		{
			zkey: {
				data: Buffer.from(json.zkey.data, 'base64')
			},
			circuitWasm: Buffer.from(json.wasm, 'base64')
		},
		logger
	)
}

function makeSnarkJsOperator(
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