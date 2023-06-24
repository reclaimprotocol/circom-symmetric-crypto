const { readFileSync, writeFileSync } = require("fs")

const zkey = readFileSync('resources/circuit_final.zkey')
const wasm = readFileSync('resources/circuit.wasm')

const json = {
	zkey: { data: zkey.toString('base64') },
	wasm: wasm.toString('base64')
}

writeFileSync('resources/zk-params.json', JSON.stringify(json))