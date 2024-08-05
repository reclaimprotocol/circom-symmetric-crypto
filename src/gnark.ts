import { EncryptionAlgorithm, ZKOperator, ZKProofInput } from "./types";
import { join } from "path";

let koffi: any;
let verify: (...args: any[]) => any;
let free: (...args: any[]) => any;
let prove: (...args: any[]) => any;

try {
    koffi = require('koffi');
    if (koffi?.version) {
        koffi.reset(); // Reset to avoid test failures

        const GoSlice = koffi.struct('GoSlice', {
            data: 'void *',
            len: 'longlong',
            cap: 'longlong'
        });

        const ProveReturn = koffi.struct('ProveReturn', {
            r0: 'void *',
            r1: 'longlong',
        });

        const resFolder = '../resources/gnark';
        const arch = process.arch;
        const libVerifyPath = join(__dirname, `${resFolder}/${arch}/libverify.so`);
        const libProvePath = join(__dirname, `${resFolder}/${arch}/libprove.so`);

        const libVerify = koffi.load(libVerifyPath);
        const libProve = koffi.load(libProvePath);

        verify = libVerify.func('Verify', 'unsigned char', [GoSlice]);
        free = libProve.func('Free', 'void', ['void *']);
        prove = libProve.func('Prove', ProveReturn, [GoSlice]);
    }
} catch (e) {
    koffi = undefined;
    console.log("Gnark is only supported on linux x64 & ARM64.", e.toString());
}

export async function makeLocalGnarkZkOperator(cipher: EncryptionAlgorithm): Promise<ZKOperator> {
    if (!koffi) {
        return createUnsupportedOperator();
    }

    return {
        generateWitness: async (input) => generateGnarkWitness(cipher, input),
        groth16Prove: async (witness: Uint8Array) => {
            const wtns = createGoSlice(witness);
            const res = prove(wtns);
            const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString();
            free(res.r0); // Avoid memory leak
            return JSON.parse(resJson);
        },
        groth16Verify: async (publicSignals, proof) => {
            const verifyParams = {
                cipher,
                proof: proof['proofJson'],
                publicSignals,
            };
            const paramsBuf = strToUint8Array(JSON.stringify(verifyParams));
            const params = createGoSlice(paramsBuf);
            return verify(params) === 1;
        },
    };
}

function generateGnarkWitness(cipher: EncryptionAlgorithm, input: ZKProofInput): Uint8Array {
    const proofParams = {
        cipher,
        key: input.key,
        nonce: input.nonce,
        counter: input.counter,
        input: input.in,
    };
    return strToUint8Array(JSON.stringify(proofParams));
}

function strToUint8Array(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

function createGoSlice(data: Uint8Array): any {
    return {
        data: Buffer.from(data),
        len: data.length,
        cap: data.length
    };
}

function createUnsupportedOperator(): ZKOperator {
    const unsupportedError = () => { throw new Error("not supported"); };
    return {
        generateWitness: async (input) => generateGnarkWitness('chacha20', input),
        groth16Prove: unsupportedError,
        groth16Verify: unsupportedError,
    };
}
