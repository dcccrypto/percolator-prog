#!/usr/bin/env python3
"""Read-only devnet fetch of the growth-v19 fork-replay fixtures (no keys used, no sends).
Markets: OTC, Jimothy, STONK, Percolator (devnet relaunch wrapper ETDLAdi.. / matcher EDKKgRaV..).
Usage: fetch.py <out_dir> [rpc]"""
import requests, base64, json, sys, os, base58
OUT = sys.argv[1]
RPC = sys.argv[2] if len(sys.argv) > 2 else "https://api.devnet.solana.com"
W = "ETDLAdiAyWnEUngspYczTXUceT6X8f92eZQvr8nmSkWB"
M = "EDKKgRaVHna6FCxiY1kgMzegD9rpaN1nwJNSzAzeBUBX"
MB = base58.b58decode(M)
def rpc(m, p):
    r = requests.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": m, "params": p}, timeout=60).json()
    if 'error' in r: raise Exception(r['error'])
    return r['result']
mk = {"otc": "6Y4bfYLWrhabgzU4p3onx9CeW1jCKjGjjSCaoCHf2Q9R",
      "jimothy": "CzKxVxPm9gpt7eyQ3xJKh57EMT6i5bep5Swu9NRcpzCh",
      "stonk": sys.argv[3] if len(sys.argv) > 3 else None,
      # Phase 2b (2026-10-05): the flagship, for the "Earn raises N_cap" replay. Its Earn
      # registry and backing ledgers are wrapper PDAs with market_group at offset 16, so the
      # same getProgramAccounts filter returns them alongside the portfolios.
      "percolator": "9EPm8nB8Fs7WcEZgE1WGFPTGc6rAzD6GhFJyMm4dEFHn"}
# FETCH_ONLY=name[,name] restricts the run (re-fetching one market must not move the others).
ONLY = set(filter(None, os.environ.get("FETCH_ONLY", "").split(",")))
for name, a in mk.items():
    if a is None: continue
    if ONLY and name not in ONLY: continue
    res = rpc("getProgramAccounts", [W, {"encoding": "base64", "dataSlice": {"offset": 0, "length": 0},
          "filters": [{"memcmp": {"offset": 16, "bytes": a}}]}])
    keys = [a] + sorted(r['pubkey'] for r in res)
    v = rpc("getMultipleAccounts", [keys[:100], {"encoding": "base64"}])['value']
    ctxs = set()
    for acc in v:
        if acc is None: continue
        d = base64.b64decode(acc['data'][0])
        i = d.find(MB)
        while i >= 0:
            ctxs.add(base58.b58encode(d[i+32:i+64]).decode()); i = d.find(MB, i+1)
    ctxs = [c for c in sorted(ctxs) if c != "11111111111111111111111111111111"]
    allk = (keys + ctxs)[:100]
    r = rpc("getMultipleAccounts", [allk, {"encoding": "base64", "commitment": "confirmed"}])
    slot = r['context']['slot']
    clock = rpc("getAccountInfo", ["SysvarC1ock11111111111111111111111111111111", {"encoding": "base64", "commitment": "confirmed"}])
    accs = []
    for k, acc in zip(allk, r['value']):
        if acc is None: continue
        accs.append({"pubkey": k, "owner": acc['owner'], "lamports": acc['lamports'], "executable": acc['executable'],
                     "rent_epoch": 0, "data_b64": acc['data'][0]})
    fx = {"market": name.upper(), "slab": a, "rpc": RPC.split('?')[0], "fetch_slot": slot,
          "clock_sysvar_b64": clock['value']['data'][0], "clock_context_slot": clock['context']['slot'],
          "wrapper_program": W, "matcher_program": M, "accounts": accs}
    json.dump(fx, open(os.path.join(OUT, f"{name}.json"), "w"), indent=1)
    print(name, slot, len(accs), "ctxs", len(ctxs))
