import { Connection, PublicKey, Transaction, TransactionInstruction, Keypair } from '@solana/web3.js';
import { readFileSync } from 'fs';
import { homedir } from 'os';

const RPC = 'https://api.devnet.solana.com';
const KEEPER_PUBKEY = new PublicKey('2JaSzRYrf44fPpQBtRJfnCEgThwCmvpFd3FCXi45VXxm');
const SMALL_PROG = new PublicKey('FwfBKZXbYr4vTK23bMFkbgKq3npJ3MSDxEaKmq9Aj4Qn');

const keypairData = JSON.parse(readFileSync(`${homedir()}/.config/solana/percolator-upgrade-authority.json`, 'utf8'));
const admin = Keypair.fromSecretKey(new Uint8Array(keypairData));

// Test with BTC slab
const slabPk = new PublicKey('7eubYRwJiQdJgXsw1VdaNQ7YHvHbgChe7wbPNQw74S23');

const conn = new Connection(RPC, 'confirmed');

// Check slab account info
const info = await conn.getAccountInfo(slabPk);
console.log('Slab owner:', info?.owner?.toBase58());
console.log('Slab data length:', info?.data?.length);

const ixData = new Uint8Array(33);
ixData[0] = 16;
ixData.set(KEEPER_PUBKEY.toBytes(), 1);

// Try with SMALL_PROG
try {
  const ix = new TransactionInstruction({
    programId: SMALL_PROG,
    keys: [
      { pubkey: slabPk, isSigner: false, isWritable: true },
      { pubkey: admin.publicKey, isSigner: true, isWritable: false },
    ],
    data: Buffer.from(ixData),
  });
  
  const tx = new Transaction().add(ix);
  const { blockhash } = await conn.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = admin.publicKey;
  tx.sign(admin);
  
  // Use simulate first
  const sim = await conn.simulateTransaction(tx);
  console.log('Simulation logs:', sim.value.logs?.slice(-10));
  console.log('Simulation err:', sim.value.err);
} catch(e) {
  console.log('Error:', e.message?.substring(0, 200));
  if (e.logs) console.log('Logs:', e.logs);
}
