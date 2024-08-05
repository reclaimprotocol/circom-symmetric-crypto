import { CircuitWasm, EncryptionAlgorithm, VerificationKey, ZKOperator, ZKParams, Logger } from "./types";

/**
 * Represents witness data in memory
 */
type WitnessData = {
    type: 'mem';
    data?: Uint8Array;
};

// 5 pages is enough for the witness data calculation
const WITNESS_MEMORY_SIZE_PAGES = 5;

/**
 * Creates a ZK operator from the snarkjs dependency for a specific encryption algorithm
 * @param type - The encryption algorithm type
 * @returns A Promise resolving to a ZKOperator
 */
export async function makeLocalSnarkJsZkOperator(type: EncryptionAlgorithm): Promise<ZKOperator> {
    const { join } = await import('path');
    const folder = `../resources/${type}`;
    return makeSnarkJsZKOperator({
        getZkey: () => ({
            data: join(__dirname, `${folder}/circuit_final.zkey`)
        }),
        getCircuitWasm: () => join(__dirname, `${folder}/circuit.wasm`),
    });
}

/**
 * Creates a SnarkJS ZK operator from the provided functions to get the circuit wasm and zkey
 * @param param0 - Object containing functions to get circuit wasm and zkey
 * @returns A ZKOperator
 */
export function makeSnarkJsZKOperator({ getCircuitWasm, getZkey }: ZKParams): ZKOperator {
    // Require here to avoid loading snarkjs in any unsupported environments
    const snarkjs = require('snarkjs');
    let zkey: Promise<VerificationKey> | VerificationKey | undefined;
    let circuitWasm: Promise<CircuitWasm> | CircuitWasm | undefined;
    let wc: Promise<any> | undefined;

    return {
        async generateWitness(input, logger) {
            circuitWasm ||= getCircuitWasm();
            wc ||= initializeWitnessCalculator(logger);

            const wtns: WitnessData = { type: 'mem' };
            if (await wc) {
                await snarkjs.wtns.wtnsCalculateWithCalculator(input, await wc, wtns);
            } else {
                await snarkjs.wtns.calculate(input, await circuitWasm, wtns);
            }
            
            return wtns.data!;
        },
        async groth16Prove(witness, logger) {
            zkey ||= getZkey();
            return snarkjs.groth16.prove((await zkey).data, witness, logger);
        },
        async groth16Verify(publicSignals, proof, logger) {
            zkey ||= getZkey();
            const zkeyResult = await zkey;
            if (!zkeyResult.json) {
                zkeyResult.json = await snarkjs.zKey.exportVerificationKey(zkeyResult.data);
            }

            return snarkjs.groth16.verify(zkeyResult.json!, publicSignals, proof, logger);
        },
        release() {
            zkey = undefined;
            circuitWasm = undefined;
            wc = undefined;
        }
    };

    /**
     * Initializes the witness calculator
     * @param logger - The logger object
     * @returns A Promise resolving to the witness calculator or undefined
     */
    async function initializeWitnessCalculator(logger?: Logger): Promise<any | undefined> {
        if (!snarkjs.wtns.getWtnsCalculator) {
            return undefined;
        }

        // Hack to allocate a specific memory size
        // because the Memory size isn't configurable
        // in the circom_runtime package
        const CurMemory = WebAssembly.Memory;
        WebAssembly.Memory = class extends WebAssembly.Memory {
            constructor() {
                super({ initial: WITNESS_MEMORY_SIZE_PAGES });
            }
        };

        try {
            return await snarkjs.wtns.getWtnsCalculator(await circuitWasm, logger);
        } finally {
            WebAssembly.Memory = CurMemory;
        }
    }
}
