#!/usr/bin/env python3
"""Read-only devnet fetch (no keys) of the SPL accounts the P1 fork fixtures omit:
the collateral mint, each Earn LP mint ["lp_vault_mint", market], and each market's vault token account (owner = ["vault", market]
PDA), plus each marketauth's account info (to show whether it is a wallet)."""
import requests, json, sys
RPC="https://api.devnet.solana.com"
MINT="DJ54k4wH92NTtNP8RuHAwG8si1bevXEknzctDdqYN8eC"
LPM={"ansem":"bCAcyJENCnTZBbA5qVMVJxiqyKnc5DZowDmitJDY6Qn","collect":"949bkZHabzcQsrMeG7sguV8fDf1HeetG2KTxbe2j914S","murphy":"3NQVbYkt9iH1FhcF1m4uCUmiwoeLRWow6wG66zF72bVb","textit":"DVgQotopENBN95URALS637uNTTufrySYC2DVe2XNPJL8"}
M={"ansem":("5bVTTMRceF9qEERjPWvqxtrDighE846QkVXSJm4uC8Tk","HAsQLA4tSijKUrSxSXpb8yePeuQQuApCqCsABaadzLFi","8Wqct6dMEXQSJGmPSAKhGNYDhNcodFE6N952QYyxfUPJ"),
   "collect":("3t67LQPdgiSqGvXsYff3Pzv2uHtM1zZ7f29HsnEzb6vJ","EJYa7bPw2kCoiVV6NszMVE8gp7g4a47X46cFjhnoEHsC","GcDbn65kGg6gLX6E4At3KHGMrvp6QuGTXLWB9Ceqp6WV"),
   "murphy":("7h3wNxjzPo6pTfWQ7uiTjDSsprGEeMNh696efmYrpAX2","44jvJJrRXwGnWUAikbcjSfRguFB2L8CwYywwaez9guEX","5JKYWy6k6qcqeQ8J9iyu5LPduF8V5vtvL25YSuGJevpt"),
   "textit":("DnFhDdWzcWkBDxN9JJcmFmtiqqKo56w9JwQEtRKNdjcG","AsQLbFqxq1BW4fS3AdCcErzyPxiKrzBFFGrTFkdUwUNb","3eF4i4phLHMDd9JiMZFhJ3SZiHn46WGwnj4HuZ7vMx7U")}
def rpc(m,p):
    r=requests.post(RPC,json={"jsonrpc":"2.0","id":1,"method":m,"params":p},timeout=30).json()
    if 'error' in r: raise Exception(r['error'])
    return r['result']
def acc(k):
    v=rpc("getAccountInfo",[k,{"encoding":"base64","commitment":"confirmed"}])
    a=v['value']
    return None if a is None else {"pubkey":k,"owner":a['owner'],"lamports":a['lamports'],"executable":a['executable'],"data_b64":a['data'][0]}
out={"rpc":RPC,"mint":acc(MINT),"markets":{}}
for n,(slab,va,auth) in M.items():
    t=rpc("getTokenAccountsByOwner",[va,{"mint":MINT},{"encoding":"base64","commitment":"confirmed"}])
    out["markets"][n]={"slab":slab,"vault_authority":va,"fetch_slot":t['context']['slot'],
        "vault_tokens":[{"pubkey":x['pubkey'],"owner":x['account']['owner'],"lamports":x['account']['lamports'],"executable":False,"data_b64":x['account']['data'][0]} for x in t['value']],
        "marketauth":auth,"marketauth_account":acc(auth),"lp_mint":acc(LPM[n])}
json.dump(out,open(sys.argv[1],"w"),indent=1)
for n,m in out["markets"].items(): print(n,m["fetch_slot"],[v["pubkey"] for v in m["vault_tokens"]],"auth owner:",(m["marketauth_account"] or {}).get("owner"))
