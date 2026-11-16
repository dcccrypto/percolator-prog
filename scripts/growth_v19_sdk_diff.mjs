// Replays the (fn, inputs, program-output) lines written by
//   GROWTHV19_DUMP=/tmp/g19.jsonl cargo test --release --test growth_v19_reference_props
// through the SDK port (percolator-sdk src/abi/growth-v19.ts) and lists every disagreement.
//
//   cd <percolator-sdk checkout> && npx tsx <this file> /tmp/g19.jsonl
//
// Run it from the SDK checkout (so `./src/abi/growth-v19.ts` resolves).
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const dump = process.argv[2];
const sdk = await import(pathToFileURL(path.resolve("src/abi/growth-v19.ts")).href);
const B = (s) => BigInt(s);
const s = (v) => (v === null || v === undefined ? null : String(v));

const fns = {
  isqrt_ceil: ([x]) => s(sdk.isqrtCeil(B(x))),
  ceilingImr: ([e, l]) => s(sdk.ceilingImrBps(B(e), Number(l))),
  imrForLev: ([l]) => s(sdk.imrBpsForLeverageX100(Number(l))),
  levForImr: ([e]) => s(sdk.leverageX100ForImrBps(B(e))),
  nCap: ([c, l, p, sc]) => s(sdk.nCapQ(B(c), B(l), B(p), B(sc))),
  liqNotional: ([c, l]) => s(sdk.liquidityNotionalE6(B(c), B(l))),
  sigmaH: ([v, h]) => s(sdk.sigmaHBps(Number(v), B(h))),
  usersOi: ([oi, lp, long]) => s(sdk.usersSideOiQ(B(oi), B(lp), long === "true")),
  wholeToken: ([d]) => s(sdk.wholeTokenAtoms(Number(d))),
  tierThr: ([a, b, c, d]) => JSON.stringify(sdk.tierThresholdsE6([Number(a), Number(b), Number(c)], Number(d)).map(String)),
  ratchet: ([p, ps, t, f, st, now]) => {
    const r = sdk.ratchetCeilingX100(Number(p), B(ps), Number(t), Number(f), Number(st), B(now));
    return JSON.stringify([String(r.ceilX100), String(r.ceilSlot)]);
  },
  log2q16: ([x]) => s(sdk.log2Q16(B(x))),
};

const counts = {};
const bad = {};
for (const line of fs.readFileSync(dump, "utf8").split("\n")) {
  if (!line) continue;
  const rec = JSON.parse(line);
  const f = fns[rec.f];
  counts[rec.f] = (counts[rec.f] ?? 0) + 1;
  if (!f) continue;
  const want = typeof rec.out === "string" || rec.out === null ? rec.out : JSON.stringify(rec.out);
  let got;
  try {
    got = f(rec.in);
  } catch (e) {
    got = `THROW ${e.message}`;
  }
  if (got !== want) {
    (bad[rec.f] ??= []).push({ in: rec.in, prog: want, sdk: got });
  }
}
for (const [k, n] of Object.entries(counts)) {
  const b = bad[k] ?? [];
  console.log(`${k.padEnd(12)} cases=${n} mismatches=${b.length}`);
  for (const m of b.slice(0, 5)) console.log("   ", JSON.stringify(m));
}
process.exit(Object.keys(bad).length ? 1 : 0);
