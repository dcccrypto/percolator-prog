/**
 * PERC-8130 Oracle Authority Migration
 * Sets oracle_authority = 2JaSzRYrf44fPpQBtRJfnCEgThwCmvpFd3FCXi45VXxm
 * on all 200 slabs discovered from keeper logs.
 *
 * Uses @solana/web3.js directly — no SDK needed.
 * Accounts: [admin (signer/writable), slab (writable)]
 * Instruction data: 0x10 (tag 16) + 32 bytes new authority pubkey
 */

import { readFileSync } from 'fs';
import { Connection, Keypair, PublicKey, Transaction, TransactionInstruction, sendAndConfirmTransaction } from '@solana/web3.js';

const RPC = process.env.RPC || 'https://api.devnet.solana.com';
const UPGRADE_AUTH_PATH = process.env.HOME + '/.config/solana/percolator-upgrade-authority.json';
const NEW_ORACLE_AUTHORITY = '2JaSzRYrf44fPpQBtRJfnCEgThwCmvpFd3FCXi45VXxm';

// All 200 slabs from keeper logs (foreign oracle markets)
const SLABS = [
  '24nQ41b2BLT3wzL3nnbRfp9c9LqVdWmFoFTihRMQMDu9',
  '29J8xQJRvpx5bwqKd11pb8hHBJEJUQqgnn8inJ79DgHb',
  '2M1NvXDbdSkUXTWERcrh5e3LjPKpzeEHPUYcw5rBXaDV',
  '2UaJk3w6FTzWVGUoNJEC9x2LUZoZ37CnoEbzKyXRs5jX',
  '2Zta2EPRR444Hp2WbH2L9vfM38Stwr9chDpNk66eevzU',
  '2b25rqaGNc7NVqaWced698dQCtAGee89V5mMksAoeGSx',
  '2fpq91EsXiNrQLfqy9c8TCyHTta3qHRJYi1F72BqLytC',
  '2t389M7NwJ1FbwKuv1yf8TSGk84FR1itGgxMBkjh5fDs',
  '2wZDq4DJW5n3k7urYTdpXq7KSDVq3z2Asc4nwBE92hGP',
  '36mBo1kzB13zc2hEnNksUpR65jEXMWmqaKxQLhwXcBsq',
  '3AJt5EDSaH6jLcMCWeUxD3kWe1P1f5xAyCy6J4feGoeP',
  '3CHYRTKVAifEJfysFJU7JkAKDvjpGakuJBNYJFEaJ8r8',
  '3CteDuQbeHoPRGHr8z9zapane36bq9RAB6hreTJ3jUkA',
  '3DzpSZ46yj9bmFLWxuxW8gqfHahXgurNLa4yZTyKJwiy',
  '3Eq3G6fiPFkvqQdUXNMGRrgqVCcNV74Mo7Td9qhvq3HR',
  '3GDBWNCxWMxhJcEkX72JSCx2CiFTkVQxN2cNcfKiZZD2',
  '3KFTo4VCAHaDzLVfjkTSAatDDnFPgWnunz1fzRkrWE9f',
  '3LzuDyhZzhSchxSqkBQCEaGAsXwu9vYZqSVH3MvNQB9k',
  '3M2M4y29gfoF2KZ8HSLw9m535H8fwDto6YJskweg1uWn',
  '3Tf7uaJvdQEDcPpmQwdNnTmrdVY6qGoe3osZV5BS4gi3',
  '3UJRD9YCtey3YjAD6iVznaWvHgz1bzz6dLzBhQekToqA',
  '3YDqCJGz88xGiPBiRvx4vrM51mWTiTZPZ95hxYDZqKpJ',
  '3ZKKwsKoo5UP28cYmMpvGpwoFpWLVgEWLQJCejJnECQn',
  '3bmCyPee8GWJR5aPGTyN5EyyQJLzYyD8Wkg9m1Afd1SD',
  '3jVwjHNtRCcaniG8doifbcXbKiwQgwhdd3pW56roTrWS',
  '3wiGU2vYXiz8GftjQqLeMiEt5H1ouprHFCryHydFmrZE',
  '44GTccW2NZbowKtN9g5oFxokXCrrGnVuZ99xxZLWWPTM',
  '44zmUap4gQbMjT25HPU1zQwtsoDdRVETFcxVszM3cEpd',
  '456J6cLyseXLqsDLqSczQNPmqiy9C7FUcncnexFV5rwv',
  '484DG6KQi5eVXuaXzWxaWMWeXDp9LFXyshNi33UnWfxV',
  '4DuaQvRmvcPGHb5g4JhuDFNZXyDw8DT42fvcqsKYJQTg',
  '4Jr98FJ9wNZiHJmcoFx1FECU8niLoP8KptPCg6VoTy5V',
  '4Lf3PsjVGn9aQaJdJqjyTAFRtvqGmV7E8Nf6D4osJxVU',
  '4Lni5vDTMTo3QztYAAE3PAEbWQiMyMoNumpAfeB8CgzB',
  '4U1ajBLar6yRdQWydG4M6VV2j1DcAWQjQAJRA1hMsB6J',
  '4XWMw76RpCM5KC6UYt8r2yb6ZvRwq2GxyU2joSSP73VW',
  '4YeLSFU5Btv7PeBuZ8qqSupBNyhRoDMCg1oGYtg3yZxp',
  '4asuC7CEDxG4xaxeaaoRLjuGGBPQvUnxWasuzkp7sXoM',
  '4gjLTPZ5Kp7Usno6RXW7yF26FbUcy3YffgyDC53efj54',
  '4iGAT1aPMA2cwsf6ZEmac4Yav9vTAYFpZq6YrHRnByBQ',
  '4iXMZ1ndoizZ2toeu2ePrCXXoU3Mw7eLXW79Gz3TPuA9',
  '4r4bxZ2LxNCu4EWdkXThoVaBHBsYQcWkizdkmWciprJC',
  '4r9LdjxALvCKBhKEE63aubaZfzEaG386ZNuDQ21Tpozv',
  '4ywWy434r5BLWr4tEDxVo1uDuxrc2sVwKDCM24h4L4AL',
  '5DZRZzB8JRb8MG7KnbmqRaf2A2SHTXDcXMGs7vTuZwud',
  '5FEemPKCca6ArjAWN3ppbaZ4GrcwC42qKL5LkyNcRFk1',
  '5JUTyfARLVAWTMPxPnGq5jyYq7aNuq5c1M2tvDqaFQJL',
  '5MEEy1iQXwda4zeEw2qV1k3vmbTJQMM8jnBx7fosqLGZ',
  '5Rh1L4qMEqe9gcWPpiYixqpZKgm4dYhRwuTspSjTVKHq',
  '5S4gkqX8Jz9MQPmtQ3qCU3698PnY5dFnyTdeq7fu12sW',
  '5dLkffW6yMeKcuEsYFJwYwZhz6GFno9FJJds7T9qwgss',
  '5pX7ycPtKwr7xfTxoUUgcWirq8tSz8B1Sq8PJShfFstt',
  '6F86pCA6DcJxx3eY8ZaUteLL6bTw1uAyVGQ71ahGqjtC',
  '6JSp61JAU8hjbN41oocrQ6SoYuivk7HtiTrcZZ9MtP3A',
  '6WVQp15w1uhvE9GTFkRkuah2Jw6ihfR2UDryCAbo6Pk7',
  '6ZytbpV4jeL6rV9FosZsFm2xDunpQye5VfeciLJAXa9D',
  '6aCy4rQ8z7WmpWMTKRf3fZNgRpXZErzyn4LKsZJ14wZr',
  '77WZBXU43R13Gmww5b3DG6bTxGPDzPy53TvoYDUd6Eie',
  '78soUB3NFsCv6rbTHu2MGyxWQU98bE9xfoppo8uWgn27',
  '7AXW3mzfseULtC2KzzisxNXdu7k9eRMUcQj5x1tiLNq1',
  '7G3SsnevWwUWjWAwGGmr2N11x8KAGn1abzjV3bBbZkAM',
  '7JBhXqX4yw3hcHMU5tiAB7Bxa5FSi4oiDDRhjuSHLBiP',
  '7Zs6cVnPobhF9nwh8XkSD85Dsyq3dfsiAL63fZH9r2X7',
  '7dVewVxWcVGRdLCiPgyeeKYDaSBq31J9YKjtMs9WQeem',
  '7emdGeEHsjwoayV8ACM6EJSihz8MNd9CKKShDLKBo6Dr',
  '7eubYRwJiQdJgXsw1VdaNQ7YHvHbgChe7wbPNQw74S23',
  '7f2xHgdJ6W9fdd7raXza32U7VwDSKdtReWuuscfrQ4g2',
  '7fRWb7vNyLuQHgMNnSfH7mfbonj8pSzpuhzcjScEkyC3',
  '7kHcYpFeX6LMkbwZSffxMg9nAmuavSCrCpBGj4xsu3Tn',
  '7reWhB1S8tD35tHyfb3hNi2PkUqZfhwNhGLrXT89FW6u',
  '7tLmcmyVghvmVwg7VpWC3kotkjuMg1d5XaxtodAnEKYd',
  '85eYcFxWfQ3GdM6qrAWhLE75sd6RH7p5FWrQJ2BT4uDd',
  '8Cg2Jc117eS67TftFdHARwp3c6mXv9rJiNgQr3G6mkXr',
  '8KU63GiDjJ2BqTMK49qU4TuNPgEyrebvYfjZwvTHgXEz',
  '8L47yqvQRLxZ6PzW3b9jawEM79CmokBvUzeLR7mvtyuU',
  '8MsKdp47Q2zeQeSBLf9gcYV7Gx3J7UdrydgCavZvTa4K',
  '8TG1q5QDzbntUvymBRn3HiYXQADSD64E6SGvhpjQWaTm',
  '8Wo9YVQf9akudsfZneEB3isKbZngSwodMkcGkvnTrsC2',
  '8Wxmx93jWGWFmVfQccfVsYiAL7xoUfBbd8vqJrvFhz8x',
  '8cwXLYaq1c6Crgirm61gkedcLqczxH3hFK6ePLCq1WWk',
  '8dJs5dSz9rUcP7f9NMaMEyvBgK3F7dbsPP3G9Sx7Gcwx',
  '8eFFEFBY3HHbBgzxJJP5hyxdzMNMAumnYNhkWXErBM4c',
  '8kkED3uZznGzSidr8kYJPd3VhzSh7LVngNUx2V1qnW9L',
  '8vbZkQgwdYmbwaSw7u6ZAnbKZ3GMPSbbKZgEDMSySqMJ',
  '917mzk4DhzHfbk53zMYjG7YTDgrhqPm87Aj4j4UL3XEM',
  '99pW9kkN8ddS8JwTi2RZ5BgQMdYkt6XGG54WeW78f4oU',
  '9MHHVtthn6k1rb5P2iViWf4ELRNAGw25F95QBzwiKJzU',
  '9R6iRUH6Aeo353nXDSAGZuQ7BNXdNXcVXPEEVUhSecWL',
  '9cb7EouMNZE9hYCGRpSthQiukyxvqnGyxEMpAZMdUArp',
  '9chA42j7BFRovLQyZZYFAUvHjF6F4urHqvABt5vPK4hx',
  '9qA29NmgmgYtarVU1BZm7VuFQ5a6BX9FVnXy6kYDuLUD',
  'A35wGP21WCnpQuiHS3Ec3V8g22ikfmTfM2GHuq15uyfv',
  'A3XJVaQxKsM4bbikoSTvKczQLVQQ19GbrxY9S9ShK119',
  'A4A5qw6ApZyobGUzSPdy1MvdccYUqDDmStDVJhYmzRxE',
  'AB3ZN1vxbBEh8FZRfrL55QQUUaLCwawqvCYzTDpgbuLF',
  'AWbcen87WbyqfvD3onLYxtRyJi7adtpxC4heZqZbSdLP',
  'AZ8P7axX8kaJP5x2xU7ayvvonA4R8qpJfQKhoovE7XUJ',
  'AagGNjTMxr5jy5PqGXkrNpJ4w6aRdhsF4NLBaph5ZMLJ',
  'AeDeLKxqYADNbwCHyYKMKrTzYqso7xxkV9tsLnEbHN2x',
  'Aiwhg31d3sgC3PS9ciorxzcbGFE5g4NjbtAz8EA5mcW5',
  'Av3zVrW5deLpLo1qZZ7yNJ5Lq5ja4Z9ixijVhV4MuRzE',
  'Ay7prrrEHtUvtFYAVgwpd5hD96KNzxgk9sdZ6E6H8KgD',
  'B12HLtjSnKrPT26WAG98durbLb4atxkZECvQH4Gsx8f6',
  'BDvjJsbaci29nPuMVGwqst1AEVCNWEvEBi5ZYxEv1wZX',
  'BXZjXeTekwegJAwsgCKGwN9bc8punt5HiCYPJPhP5PZk',
  'BYjFTd9EoEvHimuZpYZkm6LK1kQrPoEEzX8R3dzJbMAb',
  'BbGj3cLoU6Za1grM32xoCoEk5tC1d2yGwvraAJEwgA2Y',
  'BbPEHRVBDWQrW6Y12uMDTpHNc8FfKsucKNSTiXfemgsN',
  'Bc7A4yCa2SpaBCLCMpphwFE45YPFnJF4Hk1hPfZMKgvK',
  'BdzVD19FVKFnN9yvXfhYnyBq5pPVHupT6uW5bGcj7yw',
  'BgdMZb6ocHfvRWV8z8oh24gB4Mg94Joi4KvhMDEcxCs9',
  'Bk7XfKWs3SrZGaQCATaYnsTCs3YqyZCDnB7Yka79H1ud',
  'CBrKY6WNZhVFUmRWbVxGEd2SUm54Jza4dRssQHunhNfx',
  'CQg4hX8gE6Kj3RQ8iawARnH8Ab8XmbmzySRE7RcVVKh1',
  'CRJH9Gtk7qQDdjzDufnAZdfa7AHisfvxCmVVvzpzQN9v',
  'CinzdgsPDsCmceWZ1srfbPTC3WtaGMbMFWqU1oAK34qo',
  'CixbiFBpC79Xwuq4yd7bqhyPGBHrvSi2GdqHhUPVdrKJ',
  'CkcwQtUuPe1MjeVhyMR2zZcLsKEzP2cqGzspwmgTuZRp',
  'CrbDmfiooBUTFfGyMhJ1hpToCrBLAXXKySBwEnLHV6kj',
  'CsmCPSGzDQukzgJ8KppacGPPMvoRQS3dMgrab1Y51MaP',
  'CszMfDGuTWbQEADnpYVuNrrZoNpRBRtVDzJbaTUgmwXW',
  'CueVWxLwjoioMQhgt5RDXNbMjRaxECNiVb95UMyS1m4f',
  'CwiYZvLMAoYcWxZhJGhLNZLVjU6Wbf4A9Kkemyq8yyGp',
  'D1dHxYSMUfWkkjyFQe5YWGyUMmUrgLNVcGzi7nxysKB5',
  'D5c8tio6SnkPQSppfg2RFWj3vnYQrEi5mW99q2a7WGxb',
  'D8XDxXbPEuQpugtppgBpjJ8JRMEweQTyvoi8wVQY6oAj',
  'DBonukT6AavEuGaTS6yccVNrUkoQMekcazSNwybcaBpR',
  'DD9Ym1xSGbnCYrfZnpNvSp3JmDHVMiajzdJHz8rUbwJR',
  'DHn6Wy3AjDMgnp7xGbC1cJTANJF4sbqd8BcaXwULR81q',
  'DTN1qBtkBEEGqjTF1VU46pWCFpBgyhkX5tfz2y2dUD7C',
  'DbpPKDCxP4x18882sDNGAKUFU3FfU6JfpdRmUXEnArgF',
  'DdD13sN6DCLEpRGBAG9LenKLrCfy1aKbqaQHQdXsPHNJ',
  'DiK1ygxSBDKmgQ89CsPKKBb5xmpJzJf5mKFt1xANsj8E',
  'DiwZoi6h6MXcxsukQo6SHf39jYEffExpvGNXBqR153sr',
  'Dk4t4UFnVw6vNfPmqCRbFtXkVV7mog7E8AffXHxQ8E3C',
  'Dk5YUN7XivX9mz9EnpFxQdw1zD1MjuGNZbhhjLxCP78E',
  'Dm9fxEVpDNchoRHoCyiQ9V1Thwt7Gew16SUsYhErpXzm',
  'DwSQQiATFs9JcT1L9HSH8N2Jribgiavxsosiu1LVanGU',
  'EPtbz8me68UWNQAxSadZMdfGyC2n14Mv5XcKh1cj1uV',
  'EaRYtwNH73JgdUKtNBHBMBJYdrDFXMCVM3QRK3Dgz1gG',
  'EbUAhSm36CpQiH8sXrrjQPdAdKh6rCupnojP7nJq2RhA',
  'Eekuz2TgXRPq3rsp5brRW5hofxLdwt6KUXbLUQCKHK9G',
  'EeyNDVKYJV2FNbsrpau3oEfTXJXSxDFCDhst383JfeGq',
  'EkQty1LsYs4hx17ZCZ6md7u3sksGxzdVR1aw2RJnxFG2',
  'EysvbQ51DHK4ay2W5uXDMBbgmuLh3WXnfQPKgFgwNuve',
  'EzV6cPYcAZtk3XCkzAbQkZKBBCGfvF1todPChHfJeGrd',
  'F3YUro7KXNVfNZ6FJmMCm25uQ2nxpfypxJ91wxobxBUT',
  'F3v3pRLzwuwyzEvHvCYRuPW9uSMPTcbjQGFAoZNA9J7i',
  'F4pA14HBzNyy42W448RV6VK4yFmgqa29Z8RsAfSrdH15',
  'F6BmkxEic49Bhmkt47BqZkpUAh7qgeknUB4SwiCdpCQh',
  'FAF2cTxbNvVXstRpZtREdEtUkgXBa64Ug6FkyJ9fb5qN',
  'FCusfsg4uzcLSdRbj9Ez5okcrS1MwvKHvDbmcwrnSWvL',
  'FWcSkmQ6ME8YXAD4U2jHxPArDAVwEHMbsyqWiDLGqYPK',
  'FWjXahonkXeoGkPSXen2fGEBRfhhfMzfWwQS2J4dCg5G',
  'FeZJKzhDjYe3VpDQWzj4ziPXoFSeE682ebtRdtyFYtxp',
  'FhpPmmuh5UDAjvEjrYBPFwmj4CP4otvsYMxtTb46p1Ss',
  'FnkgNG1J3yo31QjCUBeHfeUYKzRQymkrpFyHwEsa9qJy',
  'Fo2CRdqPaEbLcF4B4wu5KENgpHMAfwe4evuP6TviTvje',
  'Fort9t4rVzMDWBtG6i7KEBn487sYi1uwxKwRbouudiLz',
  'FpUa2GwwCWctZdJ3N9HWN7fkruwEn12B59VLA5u4LuUe',
  'FpZF717S5kvoa1EQXJY25Hpx26his1jVN3MhoDFG8Xkd',
  'FrzyATwi84ecScxXseSCmiEBP1pVmQ6zsrm7kqyJTo5C',
  'Fti7o5vmQWETRJfjHm3ZeKpFXcsBpaqySkH7S5hAkK6E',
  'Fvo65knum1sGHGGrAGz5oGG3oDc6RfgKY4JqwsUkSSqW',
  'FwM91D6nN7x3uRsjDjGkMHzozyHyc5CMMbhxUzZgUbaY',
  'G2LwYndWSQ8BHgCXtMVuPZF3LBpkJKpE8C6nronLSkvB',
  'G6pwRShh2SfcJQpL7GHQGr9ww8xn4J8XrUqaUJSfNGSb',
  'GGU89iQLmceyXRDK8vgAxVvdi9RJb9JsPhXZ2NoFSENV',
  'GJYvYWnbbFAPpAkdS9KXoCq7dFbsSMQinUJ1y2JVDWbq',
  'GPWtt6dU5aGWZojFncRev9u1eCe4BoGEFh9c7RkS7TA2',
  'GTY37mGE1USe2ctdGZgC9C9RGdQe23GhS4syo1X9w7sy',
  'GYpukkn94KKDU9ufNURjDZVMGPp3LTadZrdoPtE2cdc1',
  'Ge9k8JZzv4W7EVwSt49pDSbWryu9A26PFnWkcUgd9HAV',
  'GfRak5ben9rvZiaEWW6FmmkeqjXFz9SBLhDwiPWhoapS',
  'Gi1LQ2Cc92zUbrY9JAV9eAf5SWMc1uGL9Yi56LebH4sG',
  'GuHENWHX72HxonvwLDDb1WM9mo8GG4bh5UX13o3zVme3',
  'GvgPZkQmAia7e6SyLDBwTtGCKvvf51b6XYoGnbf6yoVn',
  'H5Vunzd2yAMygnpFiGUASDSx2s8P3bfPTzjCfrRsPeph',
  'HAXvtHameEn3C5URDSs26qq9m7cYo742xf95Spn7zMGB',
  'HC4soK7sEjHNzVwek4z7vUtTg96Vr35eJAB1HbTCu9wK',
  'HKeVEQt3XfQjs7b1GJ2vB2yNisaUuV5Bsp3CJxxwg8ZV',
  'HUr9XGK9zDB1jknv7ddhroCSQatDJhFL3HZitjd8xbqS',
  'HaFUCibNFRqEXbzugb1GXR3rX5QLN27tLnyn4iLuaDns',
  'HjBePQZnoZVftg9B52gyeuHGjBvt2f8FNCVP4FeoP3YT',
  'Hp8UYQDjrAcqaQ22qUUK23thWHKTvhnHt81DcEcAVwrA',
  'HrdveBrbepjvwAn2qmCPU9eRSFG6Munpkw7gXCHvLpBN',
  'HyPMZH3LLybtwMVWC69wrwWtb39QrtxSTS9WbLTFefZA',
  'J6UU4VHbYXpCAACr5o5xjUVmquagiP2NGbbMp68VUCX9',
  'JB4K5cyYEN5EAhTpj1pZG66JneoS3nVi1ziXa5WEUgR9',
  'JBS3qeCoiAvyPRm4DsUfunA7YcL6UnRmbk6TyRBHTz2X',
  'JZHZyikqsSDEMczHvgpKxBvoSywyeNBUWReEYXBSiDQ',
  'XXs8pWLASKrMgJ6JdBcgRMbbRRA4dKRSPtXEKSf257X',
  'eSH3yfvFvDw3awbWMgjui7ygkD7MQ7VhJM2JjziFFJD',
  'iPKfQPeHvHrLMpS38ae2EWqQqpeK8Rq2b8MxSPpezwc',
  'iQpsQMZbw8Npbt73D69NUMFH7pPXJQY7tjPY5xjD4zd',
  'iSjBCYzryYW3Zj9k1TjbPZkgdcMk9PgwkVnk9T9JWDZ',
  'ibmBQXN1PCqAxtj7SiKeFSu9cHN43sVAzE2q8jiAR5k',
  's9gcjDrUYiWC799qdKfBb8xxwxJhs7TT7xmxqF4bYB9',
  'ykoRHvTmJRsCmN1guhBCWpdDhRhZb1oTutCZy5EgPEd',
  'zdBcx5NiKb8La6DjcFhaRPPCjvS65WW3668R2erRZtw',
];

const PROGRAM_IDS = [
  'FwfBKZXbYr4vTK23bMFkbgKq3npJ3MSDxEaKmq9Aj4Qn', // small
  'g9msRSV3sJmmE3r5Twn9HuBsxzuuRGTjKCVTKudm9in',  // medium
  'FxfD37s1AZTeWfFQps9Zpebi2dNQ9QSSDtfMKdbsfKrD', // large
];

function encodeSetOracleAuthority(newAuthority) {
  const pk = new PublicKey(newAuthority);
  const buf = Buffer.alloc(33);
  buf[0] = 16; // TAG_SET_ORACLE_AUTHORITY
  pk.toBuffer().copy(buf, 1);
  return buf;
}

async function getSlabOwner(connection, slabAddress) {
  try {
    const info = await connection.getAccountInfo(new PublicKey(slabAddress));
    if (!info) return null;
    return info.owner.toBase58();
  } catch {
    return null;
  }
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  const connection = new Connection(RPC, 'confirmed');
  
  // Load upgrade authority keypair
  const keypairData = JSON.parse(readFileSync(UPGRADE_AUTH_PATH, 'utf-8'));
  const admin = Keypair.fromSecretKey(Uint8Array.from(keypairData));
  console.log(`Admin: ${admin.publicKey.toBase58()}`);
  console.log(`New oracle authority: ${NEW_ORACLE_AUTHORITY}`);
  console.log(`RPC: ${RPC}`);
  console.log(`Slabs to process: ${SLABS.length}`);
  console.log('');

  const ixData = encodeSetOracleAuthority(NEW_ORACLE_AUTHORITY);
  
  let pass = 0;
  let fail = 0;
  let skip = 0;
  const failures = [];

  for (let i = 0; i < SLABS.length; i++) {
    const slabAddress = SLABS[i];
    
    // Rate limit: 5 req/s
    if (i > 0 && i % 10 === 0) {
      await sleep(2000);
    }

    // Resolve program owner
    const programId = await getSlabOwner(connection, slabAddress);
    if (!programId) {
      console.log(`[${i+1}/${SLABS.length}] SKIP ${slabAddress} — account not found`);
      skip++;
      continue;
    }

    if (!PROGRAM_IDS.includes(programId)) {
      console.log(`[${i+1}/${SLABS.length}] SKIP ${slabAddress} — unknown owner ${programId}`);
      skip++;
      continue;
    }

    const ix = new TransactionInstruction({
      programId: new PublicKey(programId),
      keys: [
        { pubkey: admin.publicKey, isSigner: true, isWritable: true },
        { pubkey: new PublicKey(slabAddress), isSigner: false, isWritable: true },
      ],
      data: ixData,
    });

    try {
      const tx = new Transaction().add(ix);
      const sig = await sendAndConfirmTransaction(connection, tx, [admin], {
        commitment: 'confirmed',
        skipPreflight: false,
      });
      console.log(`[${i+1}/${SLABS.length}] ✅ ${slabAddress} — ${sig.slice(0,16)}...`);
      pass++;
    } catch (err) {
      const msg = err?.message || String(err);
      console.log(`[${i+1}/${SLABS.length}] ❌ ${slabAddress} — ${msg.slice(0, 80)}`);
      fail++;
      failures.push({ slab: slabAddress, error: msg });
    }
    
    // Small delay between transactions
    await sleep(200);
  }

  console.log('');
  console.log(`=== Migration complete: ${pass} passed, ${fail} failed, ${skip} skipped ===`);
  if (failures.length > 0) {
    console.log('\nFailed slabs:');
    failures.forEach(f => console.log(`  ${f.slab}: ${f.error.slice(0, 100)}`));
  }

  if (fail > 0) process.exit(1);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
