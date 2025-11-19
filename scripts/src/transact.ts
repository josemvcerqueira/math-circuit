import { main, prove, verify } from '../../rust-circuit/pkg/nodejs/vortex';
import { VORTEX_PACKAGE_ID, VORTEX_POOL_OBJECT_ID } from './utils/constants';
import { Transaction } from '@mysten/sui/transactions';
import { SuiClient, getFullnodeUrl } from '@mysten/sui/client';
import { fromHex } from '@mysten/sui/utils';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { bcs } from '@mysten/sui/bcs';
import dotenv from 'dotenv';

import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Read proving key from the generated hex file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const verificationKeyPath = join(
  __dirname,
  '../../rust-circuit/keys/verification_key.hex'
);
const provingKeyPath = join(
  __dirname,
  '../../rust-circuit/keys/proving_key.hex'
);

import fs from 'fs';

dotenv.config();

export const suiClient = new SuiClient({
  url: getFullnodeUrl('devnet'),
});

export const keypair = Ed25519Keypair.fromSecretKey(
  Uint8Array.from(Buffer.from(process.env.KEY!, 'base64')).slice(1)
);

interface Proof {
  proofA: number[];
  proofB: number[];
  proofC: number[];
  publicInputs: string[];
  proofSerializedHex: string;
  publicInputsSerializedHex: string;
}

// Main execution
(async () => {
  try {
    main();

    const tx = new Transaction();

    const a = 5n;
    const b = 6n;
    const result = a * b;

    const provingKey = fs.readFileSync(provingKeyPath, 'utf8').trim();

    const verificationKey = fs.readFileSync(verificationKeyPath, 'utf8').trim();

    const proofJson = prove(
      JSON.stringify({
        a: a.toString(),
        b: b.toString(),
        c: result.toString(),
      }),
      provingKey
    );
    const proof = JSON.parse(proofJson) as Proof;

    // Verify the proof using the extracted verification key
    const isVerified = verify(proofJson, verificationKey.trim());
    console.log('isVerified', isVerified);
    tx.moveCall({
      package: VORTEX_PACKAGE_ID,
      module: 'vortex',
      function: 'transact',
      arguments: [
        tx.object(VORTEX_POOL_OBJECT_ID),
        tx.pure.vector('u8', fromHex('0x' + proof.proofSerializedHex)),
        tx.pure.u256(result),
      ],
    });
    const txResult = await suiClient.signAndExecuteTransaction({
      transaction: tx,
      signer: keypair,
    });
    console.log(txResult);
  } catch (error) {
    console.error(error);
  }
})();
