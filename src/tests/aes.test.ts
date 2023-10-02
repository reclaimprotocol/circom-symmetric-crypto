import { readFileSync } from 'fs'
import {randomBytes} from "crypto";
import * as CryptoJS from "crypto-js";
import {generateProof, verifyProof} from "../aes";

describe('Aes tests', ()=>{
    it('should decrypt ciphertext', async ()=>{
        // witness will send client this zkey
        const zkey = {
            data: readFileSync('./resources/aes/circuit_final.zkey')
        }

        const keyBytes = randomBytes(32)
        const ivBytes =  randomBytes(16)
        const plaintext = Buffer.from('1234567897890a890abc7890abc7890abc7890abc7890abc78email=test@cre', 'ascii')
        const pubInputs = {
            ciphertext:        plaintext,
        }

        //Encrypt locally with random key & IV
        const key = CryptoJS.enc.Hex.parse(keyBytes.toString('hex'))
        const msg = CryptoJS.enc.Hex.parse(pubInputs.ciphertext.toString('hex'))
        const iv = CryptoJS.enc.Hex.parse(ivBytes.toString('hex'));

        // encrypt with JS AES-CTR
        const aesEncryptor = CryptoJS.algo.AES.createEncryptor(key, {
            mode: CryptoJS.mode.CTR,
            padding: CryptoJS.pad.NoPadding,
            iv:iv,
        });
        const ct = aesEncryptor.finalize(msg);

        //replace plaintext with proper ciphertext
        pubInputs.ciphertext = Buffer.from(ct.toString(CryptoJS.enc.Hex),'hex')

        let start = new Date().getTime();

        // client would generate proof
        const proof = await generateProof(
            {
                key:keyBytes,
                iv:ivBytes,
            },
            pubInputs,
            zkey
        )

        console.log('gen proof took', new Date().getTime() - start)

        // client will send proof to witness
        // which would verify proof

        pubInputs.ciphertext = Buffer.concat([plaintext, pubInputs.ciphertext])
        start = new Date().getTime()
        const verified = await verifyProof(
            proof,
            pubInputs,
            zkey
        )
        console.log('verify ', verified)
        console.log('verify took', new Date().getTime() - start)
    })
})