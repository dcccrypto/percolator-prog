#!/usr/bin/env python3
"""Read-only devnet fetch of the P1 fork-regression fixtures (no keys used)."""
import requests, base58, base64, json, sys, os
RPC="https://api.devnet.solana.com"
W="GnwdeQrAh4qzChJeVLrM21CXXWC1akjLH3DiijwzEEYZ"
M="4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT"
MB=base58.b58decode(M)
OUT=sys.argv[1]
def rpc(m,p):
    r=requests.post(RPC,json={"jsonrpc":"2.0","id":1,"method":m,"params":p}).json()
    if 'error' in r: raise Exception(r['error'])
    return r['result']
mk={"collect":"3t67LQPdgiSqGvXsYff3Pzv2uHtM1zZ7f29HsnEzb6vJ","murphy":"7h3wNxjzPo6pTfWQ7uiTjDSsprGEeMNh696efmYrpAX2","textit":"DnFhDdWzcWkBDxN9JJcmFmtiqqKo56w9JwQEtRKNdjcG","ansem":"5bVTTMRceF9qEERjPWvqxtrDighE846QkVXSJm4uC8Tk"}
for name,a in mk.items():
    res=rpc("getProgramAccounts",[W,{"encoding":"base64","dataSlice":{"offset":0,"length":0},"filters":[{"memcmp":{"offset":16,"bytes":a}}]}])
    keys=[a]+sorted(r['pubkey'] for r in res)
    # first pass to discover matcher contexts referenced by portfolios
    v=rpc("getMultipleAccounts",[keys,{"encoding":"base64"}])['value']
    ctxs=set()
    for acc in v:
        d=base64.b64decode(acc['data'][0])
        i=d.find(MB)
        while i>=0:
            ctxs.add(base58.b58encode(d[i+32:i+64]).decode()); i=d.find(MB,i+1)
    ctxs=[c for c in sorted(ctxs) if c!="11111111111111111111111111111111"]
    allk=keys+ctxs
    r=rpc("getMultipleAccounts",[allk,{"encoding":"base64","commitment":"confirmed"}])
    slot=r['context']['slot']
    clock=rpc("getAccountInfo",["SysvarC1ock11111111111111111111111111111111",{"encoding":"base64","commitment":"confirmed"}])
    accs=[]
    for k,acc in zip(allk,r['value']):
        if acc is None: continue
        accs.append({"pubkey":k,"owner":acc['owner'],"lamports":acc['lamports'],"executable":acc['executable'],"rent_epoch":0,"data_b64":acc['data'][0]})
    cd=base64.b64decode(clock['value']['data'][0])
    fx={"market":name.upper(),"slab":a,"rpc":RPC,"fetch_slot":slot,"clock_sysvar_b64":clock['value']['data'][0],"clock_context_slot":clock['context']['slot'],
        "wrapper_program":W,"matcher_program":M,"accounts":accs}
    json.dump(fx,open(os.path.join(OUT,f"{name}.json"),"w"),indent=1)
    print(name,slot,len(accs),"ctxs",ctxs)
