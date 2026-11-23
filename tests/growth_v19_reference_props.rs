//! growth_v19 pure maths vs an INDEPENDENT reference model (J-20261116-PROG-BUG-GROWTHV19REF).
//!
//! Every reference below is written from the doc comments of `src/growth_v19.rs` using the most
//! direct arithmetic available (bit-by-bit isqrt, `u128` division, no copy of the program's
//! Newton loops, no shared helpers). Each pub fn is compared on `CASES` (20_000) inputs per fn
//! from a FIXED seed, seeded with the edge values 0, 1, 2, 2^64-1, 2^64, u128::MAX and the
//! saturating / overflow boundaries.
//!
//! SDK parity: set `GROWTHV19_DUMP=<path>` and the test also writes every (fn, inputs, program
//! output) triple as JSON lines; `scripts/growth_v19_sdk_diff.mjs` replays them through the SDK
//! port `percolator-sdk/src/abi/growth-v19.ts` and lists any disagreement.
#![cfg(not(kani))]

use percolator_prog::depth_src_v22::isqrt_u128;
use percolator_prog::growth_v19::*;
use std::fmt::Write as _;

const SEED: u64 = 0x6A0_7B19_5EED_0001;
const CASES: usize = 20_000;

// ── deterministic rng (splitmix64) ──────────────────────────────────────────────────────────
struct Rng(u64);
impl Rng {
    fn u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn u128(&mut self) -> u128 {
        ((self.u64() as u128) << 64) | self.u64() as u128
    }
    /// log-uniform bit length 0..=128, then random bits of that length.
    fn u128_log(&mut self) -> u128 {
        let bits = (self.u64() % 129) as u32;
        if bits == 0 {
            return 0;
        }
        let v = self.u128();
        if bits == 128 {
            v
        } else {
            v & ((1u128 << bits) - 1)
        }
    }
    fn u64_log(&mut self) -> u64 {
        let bits = (self.u64() % 65) as u32;
        if bits == 0 {
            0
        } else if bits == 64 {
            self.u64()
        } else {
            self.u64() & ((1u64 << bits) - 1)
        }
    }
    fn u32_log(&mut self) -> u32 {
        let s = (self.u64() % 33) as u32;
        if s >= 32 { 0 } else { (self.u64() as u32) >> s }
    }
}

fn edges_u128() -> Vec<u128> {
    let m = u64::MAX as u128;
    let mut v = vec![
        0,
        1,
        2,
        3,
        4,
        5,
        8,
        9,
        15,
        16,
        17,
        m - 1,
        m,
        m + 1,
        m + 2,
        1u128 << 64,
        (1u128 << 64) + 1,
        (1u128 << 127) - 1,
        1u128 << 127,
        (1u128 << 127) + 1,
        u128::MAX - 1,
        u128::MAX,
        m * m,
        m * m - 1,
        m * m + 1,
        m * m + 2,
        (m - 1) * (m - 1),
        (m - 1) * (m - 1) + 1,
        10_000,
        1_000_000,
    ];
    for k in [2u128, 3, 7, 1 << 20, 1 << 32, (1 << 32) + 1, 1 << 63, (1 << 63) + 1] {
        v.extend([k * k - 1, k * k, k * k + 1]);
    }
    v
}

fn edges_u64() -> Vec<u64> {
    vec![0, 1, 2, 3, 100, 9_999, 10_000, 10_001, 1_000_000, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX - 1, u64::MAX, 1 << 63]
}

// ── dump for the SDK differential ───────────────────────────────────────────────────────────
struct Dump(Option<String>);
impl Dump {
    fn rec(&mut self, f: &str, ins: &[String], out: &str) {
        if let Some(s) = self.0.as_mut() {
            let _ = writeln!(s, "{{\"f\":\"{}\",\"in\":[{}],\"out\":{}}}", f, ins.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(","), out);
        }
    }
}
fn o<T: std::fmt::Display>(x: Option<T>) -> String {
    match x {
        Some(v) => format!("\"{v}\""),
        None => "null".into(),
    }
}

// ── references ──────────────────────────────────────────────────────────────────────────────
/// floor(sqrt(n)) by the classic bit-by-bit (digit) method: no division, no Newton.
fn ref_isqrt_floor(n: u128) -> u128 {
    let mut rem = n;
    let mut res: u128 = 0;
    let mut bit: u128 = 1u128 << 126;
    while bit > n {
        bit >>= 2;
        if bit == 0 {
            return 0;
        }
    }
    while bit != 0 {
        if rem >= res + bit {
            rem -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    res
}
fn ref_isqrt_ceil(n: u128) -> u128 {
    let f = ref_isqrt_floor(n);
    if f * f == n { f } else { f + 1 }
}
/// ceil(a/b) written out.
fn cdiv(a: u128, b: u128) -> u128 {
    a / b + u128::from(a % b != 0)
}
/// 256-bit product of two u128 as (hi, lo), schoolbook on 64-bit limbs.
fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    let (a1, a0) = (a >> 64, a & u64::MAX as u128);
    let (b1, b0) = (b >> 64, b & u64::MAX as u128);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & u64::MAX as u128) + (p10 & u64::MAX as u128);
    let lo = (p00 & u64::MAX as u128) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}
fn ref_mul_fits(a: u128, b: u128) -> Option<u128> {
    let (hi, lo) = mul_wide(a, b);
    if hi == 0 { Some(lo) } else { None }
}
/// n_cap_q per the doc: floor(c_m * lambda * pos_scale / (10_000 * price)); None on price 0 or
/// when a stage (c_m*lambda, then *pos_scale) leaves u128 (fail closed).
fn ref_n_cap(c_m: u128, lambda: u32, price: u64, pos_scale: u128) -> Option<u128> {
    if price == 0 {
        return None;
    }
    let x = ref_mul_fits(c_m, lambda as u128)?;
    let p = ref_mul_fits(x, pos_scale)?;
    Some(p / (10_000u128 * price as u128))
}
fn ref_imr_for_lev(l: u16) -> Option<u64> {
    if l < 100 {
        None
    } else {
        Some(((1_000_000u32 + l as u32 - 1) / l as u32) as u64)
    }
}
fn ref_ceiling_imr(engine: u64, l: u16) -> Option<u64> {
    if engine > 10_000 {
        return None;
    }
    let c = ref_imr_for_lev(l)?;
    Some(c.max(engine))
}
fn ref_sigma(var: u32, h: u64) -> u64 {
    let v = var as u128 * h as u128;
    let s = ref_isqrt_ceil(cdiv(v, 100));
    s.min(u64::MAX as u128) as u64
}
fn ref_users_oi(oi: u128, lp: i128, long: bool) -> u128 {
    let lp_abs = lp.unsigned_abs();
    match (long, lp.signum()) {
        (true, 1) | (false, -1) => oi.saturating_sub(lp_abs),
        _ => oi,
    }
}
fn ref_whole_token(d: u8) -> u64 {
    let d = d.min(12);
    let mut r = 1u64;
    for _ in 0..d {
        r *= 10;
    }
    r
}
/// graduated ceiling: floor(log2(c_m / c_launch)) via exact 256-bit compare of c_launch << s.
fn ref_graduated(on: bool, launch: u16, tier: u16, c_m: u128, c_l: u128) -> u16 {
    let base = launch.min(tier);
    if !on || c_l == 0 || c_m < c_l {
        return base;
    }
    // largest s with c_l * 2^s <= c_m (c_m >= c_l so s >= 0)
    let mut s = 0u32;
    while s < 127 && (c_l.leading_zeros() > s) && (c_l << (s + 1)) <= c_m {
        s += 1;
    }
    let raised = launch as u64 + 100 * s as u64;
    if raised >= tier as u64 { tier } else { raised as u16 }
}
fn ref_ratchet(prev: u16, prev_slot: u64, target: u16, floor: u16, stress: u8, now: u64) -> (u16, u64) {
    let target = if stress >= 3 && floor < target { floor } else { target };
    if target == prev {
        return (prev, prev_slot);
    }
    if target < prev {
        return (target, now);
    }
    let open = (prev_slot as u128) + 9_000 <= now as u128 || (prev_slot as u128 + 9_000 > u64::MAX as u128 && now == u64::MAX);
    if open {
        let up = (prev as u32 + 100).min(u16::MAX as u32) as u16;
        return (up.min(target), now);
    }
    (prev, prev_slot)
}
/// interpolation step: exact wide floor(span*num/den).
fn ref_interp(span: u64, num: u32, den: u32) -> u64 {
    (span as u128 * num as u128 / den as u128) as u64
}
/// log2 in Q.16 from a 63-bit exact mantissa and 63-bit squaring (far more precise than the
/// program's 32-bit mantissa): the program must be within [ref-1, ref].
fn ref_log2_q16(x: u64) -> u32 {
    let k = 63 - x.leading_zeros();
    let mut m: u128 = (x as u128) << (63 - k); // [2^63, 2^64)
    let mut frac = 0u32;
    for _ in 0..16 {
        // square, renormalise to [2^63, 2^65) -> digit
        let sq = mul_wide(m, m); // up to 2^128
        let sq = sq.1; // m < 2^64 so m*m < 2^128: hi == 0
        m = sq >> 63;
        frac <<= 1;
        if m >= 1u128 << 64 {
            frac |= 1;
            m >>= 1;
        }
    }
    (k << 16) | frac
}

fn check(name: &str, bad: &mut Vec<String>, ok: bool, msg: impl FnOnce() -> String) {
    if !ok && bad.len() < 20 {
        bad.push(format!("{name}: {}", msg()));
    }
}

#[test]
fn growth_v19_matches_independent_reference() {
    let mut rng = Rng(SEED);
    let mut dump = Dump(std::env::var("GROWTHV19_DUMP").ok().map(|_| String::new()));
    let mut bad: Vec<String> = Vec::new();

    // ---- isqrt / isqrt_ceil (u128) ----
    {
        let mut xs = edges_u128();
        while xs.len() < CASES {
            xs.push(if xs.len() % 4 == 0 { rng.u128() } else { rng.u128_log() });
        }
        for &x in &xs {
            let c = isqrt_ceil_u128(x);
            let rc = ref_isqrt_ceil(x);
            check("isqrt_ceil_u128", &mut bad, c == rc, || format!("x={x} prog={c} ref={rc}"));
            let f = isqrt_u128(x);
            let rf = ref_isqrt_floor(x);
            check("isqrt_u128", &mut bad, f == rf, || format!("x={x} prog={f} ref={rf}"));
            dump.rec("isqrt_ceil", &[x.to_string()], &format!("\"{c}\""));
        }
        println!("isqrt_u128 / isqrt_ceil_u128: {} cases", xs.len());
    }

    // ---- ceiling IMR bps (+ both leverage<->IMR helpers) ----
    {
        let mut n = 0;
        let mut ls: Vec<u16> = vec![0, 1, 99, 100, 101, 150, 550, 1000, 2000, 9999, 10000, 10001, u16::MAX - 1, u16::MAX];
        let mut es: Vec<u64> = vec![0, 1, 999, 1000, 9_999, 10_000, 10_001, u64::MAX, u64::MAX - 1, 1 << 63];
        for _ in 0..CASES {
            ls.push(rng.u64() as u16);
            es.push(if rng.u64() % 3 == 0 { rng.u64_log() } else { rng.u64() % 10_100 });
        }
        for i in 0..CASES {
            let l = ls[i % ls.len()];
            let e = es[(i * 7 + i / 3) % es.len()];
            let p = ceiling_imr_bps(e, l);
            let r = ref_ceiling_imr(e, l);
            check("ceiling_imr_bps", &mut bad, p == r, || format!("e={e} l={l} prog={p:?} ref={r:?}"));
            let p2 = imr_bps_for_leverage_x100(l);
            check("imr_bps_for_leverage_x100", &mut bad, p2 == ref_imr_for_lev(l), || format!("l={l} prog={p2:?}"));
            let p3 = leverage_x100_for_imr_bps(e);
            let r3 = if e == 0 || e > 10_000 { None } else { Some((1_000_000 / e).min(u16::MAX as u64) as u16) };
            check("leverage_x100_for_imr_bps", &mut bad, p3 == r3, || format!("e={e} prog={p3:?} ref={r3:?}"));
            // doc invariant: never looser than the engine IMR.
            if let Some(b) = p {
                check("ceiling_imr_bps.ge_engine", &mut bad, b >= e && b <= 10_000, || format!("e={e} l={l} b={b}"));
            }
            dump.rec("ceilingImr", &[e.to_string(), l.to_string()], &o(p));
            dump.rec("imrForLev", &[l.to_string()], &o(p2));
            dump.rec("levForImr", &[e.to_string()], &o(p3));
            n += 1;
        }
        println!("ceiling_imr_bps (+imr_for_leverage, leverage_for_imr): {n} cases");
    }

    // ---- n_cap_q + liquidity_notional_e6 ----
    {
        let e = edges_u128();
        let ep = edges_u64();
        let lam: Vec<u32> = vec![0, 1, 10_000, 100_000, 100_001, u32::MAX];
        let mut n = 0;
        for i in 0..CASES {
            let sc = [1u128, 1_000_000, 1u128 << 64, u128::MAX];
            let cross = e.len() * lam.len() * ep.len() * sc.len();
            let (c, l, p, s) = if i < cross.min(CASES - 2_000) {
                // full cross product of the edge sets (every edge meets every other edge)
                (e[i % e.len()], lam[(i / e.len()) % lam.len()], ep[(i / (e.len() * lam.len())) % ep.len()], sc[(i / (e.len() * lam.len() * ep.len())) % sc.len()])
            } else if i % 2 == 0 {
                (rng.u128_log(), rng.u64() as u32 >> (rng.u64() % 32), rng.u64_log(), [1_000_000u128, rng.u128_log(), 1 << 20][i % 3])
            } else {
                // realistic range
                (rng.u128() >> (rng.u64() % 100 + 20), (rng.u64() % 100_001) as u32, 1 + rng.u64() % 10_000_000_000, 1_000_000)
            };
            let pr = n_cap_q(c, l, p, s);
            let rf = ref_n_cap(c, l, p, s);
            check("n_cap_q", &mut bad, pr == rf, || format!("c={c} l={l} p={p} s={s} prog={pr:?} ref={rf:?}"));
            let ln = liquidity_notional_e6(c, l);
            let lr = ref_mul_fits(c, l as u128).and_then(|x| ref_mul_fits(x, 4)).map(|x| x / 10_000);
            check("liquidity_notional_e6", &mut bad, ln == lr, || format!("c={c} l={l} prog={ln:?} ref={lr:?}"));
            dump.rec("nCap", &[c.to_string(), l.to_string(), p.to_string(), s.to_string()], &o(pr));
            if s == 1_000_000 {
                dump.rec("liqNotional", &[c.to_string(), l.to_string()], &o(ln));
            }
            n += 1;
        }
        println!("n_cap_q (+liquidity_notional_e6): {n} cases");
    }

    // ---- sigma_h_bps ----
    {
        let ev: Vec<u32> = vec![0, 1, 99, 100, 2_500, u32::MAX - 1, u32::MAX];
        let eh = edges_u64();
        let mut n = 0;
        for i in 0..CASES {
            let (v, h) = if i < 600 {
                (ev[i % ev.len()], eh[(i / 7) % eh.len()])
            } else {
                (rng.u32_log(), rng.u64_log())
            };
            let p = sigma_h_bps(v, h);
            let r = ref_sigma(v, h);
            check("sigma_h_bps", &mut bad, p == r, || format!("var={v} h={h} prog={p} ref={r}"));
            dump.rec("sigmaH", &[v.to_string(), h.to_string()], &format!("\"{p}\""));
            n += 1;
        }
        println!("sigma_h_bps: {n} cases");
    }

    // ---- users_side_oi_q ----
    {
        let e = edges_u128();
        let ei: Vec<i128> = vec![0, 1, -1, 2, -2, i64::MAX as i128, i64::MIN as i128, i128::MAX, i128::MIN, i128::MIN + 1, 1 << 64, -(1 << 64)];
        let mut n = 0;
        for i in 0..CASES {
            let oi = if i % 2 == 0 { e[i % e.len()] } else { rng.u128_log() };
            let lp: i128 = if i < 2_000 { ei[(i / 5) % ei.len()] } else { let m = rng.u128_log() >> 1; if rng.u64() & 1 == 0 { m as i128 } else { -(m as i128) } };
            for long in [true, false] {
                let p = users_side_oi_q(oi, lp, long);
                let r = ref_users_oi(oi, lp, long);
                check("users_side_oi_q", &mut bad, p == r, || format!("oi={oi} lp={lp} long={long} prog={p} ref={r}"));
                dump.rec("usersOi", &[oi.to_string(), lp.to_string(), long.to_string()], &format!("\"{p}\""));
                n += 1;
            }
        }
        println!("users_side_oi_q: {n} cases");
    }

    // ---- whole_token_atoms / tier_thresholds ----
    {
        let mut n = 0;
        for d in 0..=255u8 {
            let p = whole_token_atoms(d);
            check("whole_token_atoms", &mut bad, p == ref_whole_token(d), || format!("d={d} prog={p}"));
            dump.rec("wholeToken", &[d.to_string()], &format!("\"{p}\""));
            n += 1;
        }
        for i in 0..CASES {
            let d = (rng.u64() % 256) as u8;
            let st = [rng.u32_log(), if i % 5 == 0 { 0 } else { rng.u64() as u32 }, if i % 7 == 0 { u32::MAX } else { rng.u32_log() }];
            let p = tier_thresholds(st, d);
            let unit = ref_whole_token(d) as u128;
            let def = [25_000u128, 100_000, 500_000];
            let r: Vec<u64> = (0..3).map(|j| ((if st[j] == 0 { def[j] } else { st[j] as u128 }) * unit).min(u64::MAX as u128) as u64).collect();
            check("tier_thresholds", &mut bad, p.to_vec() == r, || format!("st={st:?} d={d} prog={p:?} ref={r:?}"));
            dump.rec("tierThr", &[st[0].to_string(), st[1].to_string(), st[2].to_string(), d.to_string()], &format!("[\"{}\",\"{}\",\"{}\"]", p[0], p[1], p[2]));
            n += 1;
        }
        println!("whole_token_atoms + tier_thresholds: {n} cases");
    }

    // ---- curve step: graduated ceiling, ratchet, interp, log2, curve_value ----
    {
        let e = edges_u128();
        let mut n = 0;
        for i in 0..CASES {
            let (c_m, c_l) = if i < 2_000 { (e[i % e.len()], e[(i / 3 + i) % e.len()]) } else {
                let c_l = rng.u128_log() >> (rng.u64() % 4);
                // c_m a few doublings of c_l half the time
                if rng.u64() & 1 == 0 { (c_l.saturating_mul(1 + (rng.u64() % 4000) as u128) >> (rng.u64() % 3), c_l) } else { (rng.u128_log(), c_l) }
            };
            let (lau, lt) = (rng.u64() as u16 >> (rng.u64() % 8), rng.u64() as u16 >> (rng.u64() % 8));
            let on = rng.u64() & 7 != 0;
            let p = graduated_ceiling_x100(on, lau, lt, c_m, c_l);
            let r = ref_graduated(on, lau, lt, c_m, c_l);
            check("graduated_ceiling_x100", &mut bad, p == r, || format!("on={on} launch={lau} tier={lt} c_m={c_m} c_l={c_l} prog={p} ref={r}"));
            dump.rec("graduated", &[on.to_string(), lau.to_string(), lt.to_string(), c_m.to_string(), c_l.to_string()], &p.to_string());

            let ue: [u16; 10] = [0, 1, 100, 65_434, 65_435, 65_436, 65_534, 65_535, 9_000, 500];
            let (mut prev, mut tgt, flo) = (rng.u64() as u16 >> (rng.u64() % 8), rng.u64() as u16 >> (rng.u64() % 8), rng.u64() as u16 >> (rng.u64() % 8));
            if i < 1_000 {
                // all edge pairs: exercises the +100 u16 saturation
                prev = ue[i % 10];
                tgt = ue[(i / 10) % 10];
            } else if i % 5 == 0 {
                tgt = prev; // "unchanged keeps its stamp" branch
            }
            let slots = [0u64, 1, 8_999, 9_000, 9_001, u64::MAX - 9_000, u64::MAX - 8_999, u64::MAX];
            let ps = if i % 2 == 0 { slots[(i / 2) % slots.len()] } else { rng.u64_log() };
            let now = if i % 3 == 0 { ps.saturating_add(rng.u64() % 20_000) } else { rng.u64_log() };
            let stress = (rng.u64() % 5) as u8;
            let p = ratchet_ceiling_x100(prev, ps, tgt, flo, stress, now);
            let r = ref_ratchet(prev, ps, tgt, flo, stress, now);
            check("ratchet_ceiling_x100", &mut bad, p == r, || format!("prev={prev} ps={ps} tgt={tgt} flo={flo} stress={stress} now={now} prog={p:?} ref={r:?}"));
            dump.rec("ratchet", &[prev.to_string(), ps.to_string(), tgt.to_string(), flo.to_string(), stress.to_string(), now.to_string()], &format!("[\"{}\",\"{}\"]", p.0, p.1));

            let span = if i % 50 == 1 { u32::MAX as u64 + (i as u64 % 3) - 1 } else if i % 4 == 0 { rng.u64_log() } else { rng.u64() >> 32 };
            let den = (rng.u32_log()).max(1);
            let num = if i % 5 == 0 { den } else { (rng.u64() % (den as u64 + 1)) as u32 };
            let p = curve_interp(span, num, den);
            check("curve_interp", &mut bad, p == ref_interp(span, num, den), || format!("span={span} num={num} den={den} prog={p}"));
            check("curve_interp.le_span", &mut bad, p <= span, || format!("span={span} num={num} den={den}"));

            let x = if i < edges_u64().len() * 3 { [edges_u64()[i % edges_u64().len()], 1u64 << (i % 64), (1u64 << (i % 64)).wrapping_sub(1)][i % 3] } else { rng.u64_log() };
            if x != 0 {
                let p = log2_q16(x).unwrap();
                let r = ref_log2_q16(x);
                check("log2_q16", &mut bad, p <= r && r - p <= 1, || format!("x={x} prog={p} ref={r}"));
                if x.is_power_of_two() {
                    check("log2_q16.pow2", &mut bad, p == (x.trailing_zeros() << 16), || format!("x={x} prog={p}"));
                }
                dump.rec("log2q16", &[x.to_string()], &format!("\"{p}\""));
            } else {
                check("log2_q16.zero", &mut bad, log2_q16(0).is_none(), || "log2(0) must be None".into());
            }
            n += 1;
        }
        // log2_q16 monotone on a dense sweep across mantissa boundaries.
        let mut prev = 0u32;
        for x in 1..=40_000u64 {
            let v = log2_q16(x).unwrap();
            check("log2_q16.monotone", &mut bad, v >= prev, || format!("x={x}"));
            prev = v;
        }
        for sh in 0..64u32 {
            let x = 1u64 << sh;
            check("log2_q16.pow2_all", &mut bad, log2_q16(x) == Some(sh << 16), || format!("x={x}"));
        }
        for base in [1u64 << 31, 1u64 << 32, (1u64 << 40) - 10_000, 1u64 << 62, u64::MAX - 40_000] {
            let mut prev = 0u32;
            for x in base..=base.saturating_add(40_000) {
                let v = log2_q16(x).unwrap();
                check("log2_q16.monotone_hi", &mut bad, v >= prev, || format!("x={x}"));
                prev = v;
                if x == u64::MAX { break; }
            }
        }
        println!("graduated_ceiling_x100 / ratchet_ceiling_x100 / curve_interp / log2_q16: {n} cases each");
    }

    if let Some(s) = dump.0 {
        std::fs::write(std::env::var("GROWTHV19_DUMP").unwrap(), s).unwrap();
    }
    assert!(bad.is_empty(), "program disagrees with the independent reference ({} shown):\n{}", bad.len(), bad.join("\n"));
}

/// Negative control: the reference model must itself reject the pre-F-8 bug (isqrt_ceil(2) == 3)
/// so a vacuous comparison cannot pass.
#[test]
fn reference_rejects_known_mutants() {
    fn mutant_ceil(x: u128) -> u128 {
        if x < 2 {
            return x;
        }
        let mut r = x;
        let mut y = x / 2 + 1; // the pre-F-8 start
        while y < r {
            r = y;
            y = (r + x / r) / 2;
        }
        if r * r == x { r } else { r + 1 }
    }
    assert_ne!(mutant_ceil(2), ref_isqrt_ceil(2));
    assert_eq!(ref_isqrt_ceil(2), 2);
    assert_eq!(ref_isqrt_floor(u128::MAX), u64::MAX as u128);
    assert_eq!(ref_isqrt_ceil(u128::MAX), 1u128 << 64);
}
