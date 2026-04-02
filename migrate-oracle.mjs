import { Connection, PublicKey, Transaction, TransactionInstruction, Keypair } from '@solana/web3.js';
import { readFileSync } from 'fs';
import { homedir } from 'os';

const RPC = 'https://api.devnet.solana.com';
const KEEPER_PUBKEY = new PublicKey('2JaSzRYrf44fPpQBtRJfnCEgThwCmvpFd3FCXi45VXxm');
const SMALL_PROG = new PublicKey('FwfBKZXbYr4vTK23bMFkbgKq3npJ3MSDxEaKmq9Aj4Qn');
const MEDIUM_PROG = new PublicKey('g9msRSV3sJmmE3r5Twn9HuBsxzuuRGTjKCVTKudm9in');
const LARGE_PROG = new PublicKey('FxfD37s1AZTeWfFQps9Zpebi2dNQ9QSSDtfMKdbsfKrD');

// Load upgrade authority keypair
const keypairPath = `${homedir()}/.config/solana/percolator-upgrade-authority.json`;
const keypairData = JSON.parse(readFileSync(keypairPath, 'utf8'));
const admin = Keypair.fromSecretKey(new Uint8Array(keypairData));
console.log('Admin:', admin.publicKey.toBase58());

// Slabs that need oracle authority update (oracle_authority = FF7KFfU5)
const SLABS = [
  { slab: 'CixbiFBpC79Xwuq4yd7bqhyPGBHrvSi2GdqHhUPVdrKL', sym: 'WENDYS' },
  { slab: '5qPupXTuiKnwkVBHnhMRVJSj2EZ2Fii3Di5Fp4CPsvUA', sym: 'RIGGED' },
  { slab: 'EeyNDVKYJV2FNbsrpau3oEfTXJXSxDFCDhst383JfeGq', sym: 'SIEVE' },
  { slab: '7eubYRwJiQdJgXsw1VdaNQ7YHvHbgChe7wbPNQw74S23', sym: 'BTC' },
  { slab: 'AB3ZN1vxbBEh8FZRfrL55QQUUaLCwawqvCYzTDpgbuLF', sym: 'BTC2' },
  { slab: 'GGU89iQLmceyXRDK8vgAxVvdi9RJb9JsPhXZ2NoFSENV', sym: 'BTC3' },
  { slab: '8Cg2Jc117eS67TftFdHARwp3c6mXv9rJiNgQr3G6mkXr', sym: 'DARK' },
  { slab: 'ykoRHvTmJRsCmN1guhBCWpdDhRhZb1oTutCZy5EgPEd', sym: 'SMT' },
  { slab: 'DBonukT6AavEuGaTS6yccVNrUkoQMekcazSNwybcaBpR', sym: 'USELESS' },
  { slab: 'D1dHxYSMUfWkkjyFQe5YWGyUMmUrgLNVcGzi7nxysKB5', sym: 'GROKIUS' },
  { slab: 'G6pwRShh2SfcJQpL7GHQGr9ww8xn4J8XrUqaUJSfNGSb', sym: 'Percolator' },
  { slab: 'AWbcen87WbyqfvD3onLYxtRyJi7adtpxC4heZqZbSdLP', sym: 'Percolator2' },
  { slab: 'FnkgNG1J3yo31QjCUBeHfeUYKzRQymkrpFyHwEsa9qJy', sym: 'shitcoin' },
  { slab: '9chA42j7BFRovLQyZZYFAUvHjF6F4urHqvABt5vPK4hx', sym: '6yEiTM4X' },
  { slab: '3wiGU2vYXiz8GftjQqLeMiEt5H1ouprHFCryHydFmrZE', sym: 'FTCW' },
  { slab: 'FrzyATwi84ecScxXseSCmiEBP1pVmQ6zsrm7kqyJTo5C', sym: 'HEY' },
  { slab: '484DG6KQi5eVXuaXzWxaWMWeXDp9LFXyshNi33UnWfxV', sym: 'Percolator3' },
  { slab: '6F86pCA6DcJxx3eY8ZaUteLL6bTw1uAyVGQ71ahGqjtC', sym: 'pump' },
  { slab: 'GDyHCzpiuEsWDkLuji3NEFYJfqbDTzMCKn9ugUzTZqAW', sym: 'Percolator4' },
  { slab: 'F4pA14HBzNyy42W448RV6VK4yFmgqa29Z8RsAfSrdH15', sym: 'Percolator5' },
  { slab: '5MEEy1iQXwda4zeEw2qV1k3vmbTJQMM8jnBx7fosqLGZ', sym: 'Percolator6' },
  { slab: '7emdGeEHsjwoayV8ACM6EJSihz8MNd9CKKShDLKBo6Dr', sym: 'Percolator7' },
  { slab: '4U1ajBLar6yRdQWydG4M6VV2j1DcAWQjQAJRA1hMsB6J', sym: 'Percolator8' },
  { slab: '3CteDuQbeHoPRGHr8z9zapane36bq9RAB6hreTJ3jUkA', sym: '5SX2' },
  { slab: 'Fo2CRdqPaEbLcF4B4wu5KENgpHMAfwe4evuP6TviTvje', sym: '5SX2b' },
  { slab: '7JjoV9CUcJJA2GMsjmpU2tDSUJvn2uwH3YBsxP3c5eDj', sym: 'Percolator9' },
];

// Build SetOracleAuthority instruction data
// Tag 16 + 32 bytes of keeper pubkey
function buildIxData(keeperPk) {
  const buf = new Uint8Array(33);
  buf[0] = 16; // TAG_SET_ORACLE_AUTHORITY
  buf.set(keeperPk.toBytes(), 1);
  return buf;
}

// Try sending instruction with each program ID, succeed on right tier
async function migrateOracle(conn, admin, slabPk, symb) {
  const ixData = buildIxData(KEEPER_PUBKEY);
  
  // Try all 3 tiers
  const programs = [SMALL_PROG, MEDIUM_PROG, LARGE_PROG];
  
  for (const prog of programs) {
    try {
      const ix = new TransactionInstruction({
        programId: prog,
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
      
      const sig = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
      await conn.confirmTransaction(sig, 'confirmed');
      return { success: true, sig, prog: prog.toBase58().substring(0,8) };
    } catch (e) {
      const msg = e.message || '';
      // Custom error 3010 = WrongAdmin, skip to next program
      // Custom error = slab not owned by this program, try next
      if (msg.includes('custom program error') || msg.includes('0xbc2') || msg.includes('invalid account data')) {
        continue;
      }
      return { success: false, error: msg.substring(0, 100) };
    }
  }
  return { success: false, error: 'All 3 programs failed' };
}

async function main() {
  const conn = new Connection(RPC, 'confirmed');
  const balance = await conn.getBalance(admin.publicKey);
  console.log(`Balance: ${(balance / 1e9).toFixed(6)} SOL`);
  
  let passed = 0, failed = 0;
  
  for (const { slab, sym } of SLABS) {
    const slabPk = new PublicKey(slab);
    process.stdout.write(`  ${sym} (${slab.substring(0,8)}...)  `);
    const result = await migrateOracle(conn, admin, slabPk, sym);
    if (result.success) {
      console.log(`✅ sig: ${result.sig.substring(0,12)}...`);
      passed++;
    } else {
      console.log(`❌ ${result.error}`);
      failed++;
    }
    // Small delay to avoid rate limiting
    await new Promise(r => setTimeout(r, 300));
  }
  
  console.log(`\n=== Done: ${passed} passed, ${failed} failed ===`);
}

main().catch(e => { console.error(e.message); process.exit(1); });
