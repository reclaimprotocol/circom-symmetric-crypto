# Circom Symmetric Crypto

This library contains circom zero-knowledge proof circuits for symmetric crypto operations. The goal is to enable a user to prove that they have the key to a symmetric encrypted message without revealing the key.

The following algorithms are supported:
- `chacha20`
- `aes-256-ctr`
- `aes-128-ctr`
	- which includes any CTR implementation. For eg. aes-256-gcm
	- note: this is a WIP, and may be insecure (borrowed implementation from [electron labs](https://github.com/Electron-Labs/aes-circom))

It uses the `groth16` implementaion in `snarkjs` to generate the proof.

## Installation

```bash
npm install git+https://github.com/reclaimprotocol/circom-chacha20
```

If using on the browser, or nodejs, you will need to install `snarkjs` as well.

```bash
npm install snarkjs
```

## Usage

### Generating Proof

```ts
import { generateProof, verifyProof, makeLocalSnarkJsZkOperator, toUint8Array } from '@reclaimprotocol/circom-symmetric-crypto'

const key = randomBytes(16)
const iv = randomBytes(12)
const data = 'Hello World!'
const ciphertext = chacha20(key, iv, data)

// the operator is the abstract interface for
// the snarkjs library to generate & verify the proof
const zkOperator = makeLocalSnarkJsZkOperator()
// generate the proof that you have the key to the ciphertext
const {
	// groth16-snarkjs proof as a JSON string
	proofJson,
	// the plaintext, obtained from the output of the circuit
	plaintext,
} = await generateProof(
	'chacha20',
	// key, iv & counter are the private inputs to the circuit
	{
		key,
		iv,
		// this is the counter from which to start
		// the stream cipher. Read about
		// the counter here: https://en.wikipedia.org/wiki/Stream_cipher
		offset: 0
	},
	// the public ciphertext input to the circuit
	{ ciphertext },
	zkOperator
)

// you can check that the plaintext obtained from the circuit
// is the same as the plaintext obtained from the ciphertext
const plaintextBuffer = toUint8Array(plaintext)
	// slice in case the plaintext was padded
	.slice(0, data.length)
	.toString()
console.log(plaintextBuffer) // "Hello World!"
```

### Verifying Proof

Continuing from the above example:

```ts
// will assert the proof is valid,
// otherwise it will throw an error
await verifyProof(
	{ proofJson, plaintext, algorithm: 'chacha20' },
	{ ciphertext },
	zkOperator
)
console.log('proof verified')

```

## Development

1. Clone the repository
2. Install dependencies via: `npm i`
3. Install [circom](https://docs.circom.io/getting-started/installation/)

### Running Tests

Run the tests via `npm run test`

## Building the Circuit

### Prerequisites
curl, jq

Official Ptau file for bn128 with 256k max constraints can be downloaded by running
```bash
npm run download:ptau
```

Build the circuits via `ALG={alg} npm run build:circuit`.
For eg. `ALG=chacha20 npm run build:circuit`
Note: `ALG` is the same as mentioned in the first section of this readme.

### Regenerating the Verification Key

1. Generate bls12-381 parameters via `npm run generate:ptau`
2. Fix `build-circuit.sh` to use `-p bls12381` parameter
   - note: we currently use BN-128 for our circuit, but plan to switch to BLs for greater security
   - zkey and ptau file verification is disabled right now due to a bug in the latest snarkJS version 0.7.0
3. TODO