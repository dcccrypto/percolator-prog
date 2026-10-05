#!/usr/bin/env python3
"""Read-only devnet fetch for the P2b ADL wind-down LiteSVM replay (no keys used, no sends).
Same method as tests/fixtures/growth_fork/fetch.py: getProgramAccounts (memcmp market_group_id
@16) for the portfolios, then ONE getMultipleAccounts (slab + portfolios + extra accounts such as
oracle feeds) at one context slot, plus the Clock sysvar.
Usage: fetch.py <name> <slab> [extra_pubkey ...]"""
import requests, base64, json, sys, os
RPC = "https://api.devnet.solana.com"
W = "ETDLAdiAyWnEUngspYczTXUceT6X8f92eZQvr8nmSkWB"
def rpc(m, p):
    r = requests.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": m, "params": p}, timeout=60).json()
    if 'error' in r: raise Exception(r['error'])
    return r['result']
name, slab, extra = sys.argv[1], sys.argv[2], sys.argv[3:]
res = rpc("getProgramAccounts", [W, {"encoding": "base64", "dataSlice": {"offset": 0, "length": 0},
      "filters": [{"memcmp": {"offset": 16, "bytes": slab}}]}])
keys = [slab] + sorted(r['pubkey'] for r in res) + extra
r = rpc("getMultipleAccounts", [keys[:100], {"encoding": "base64", "commitment": "confirmed"}])
slot = r['context']['slot']
clock = rpc("getAccountInfo", ["SysvarC1ock11111111111111111111111111111111", {"encoding": "base64", "commitment": "confirmed"}])
accs = []
for k, acc in zip(keys, r['value']):
    if acc is None: continue
    accs.append({"pubkey": k, "owner": acc['owner'], "lamports": acc['lamports'], "executable": acc['executable'],
                 "rent_epoch": 0, "data_b64": acc['data'][0]})
fx = {"market": name, "slab": slab, "rpc": RPC, "fetch_slot": slot,
      "clock_sysvar_b64": clock['value']['data'][0], "clock_context_slot": clock['context']['slot'],
      "wrapper_program": W, "accounts": accs}
json.dump(fx, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{name}.json"), "w"), indent=1)
print(name, slot, len(accs))
