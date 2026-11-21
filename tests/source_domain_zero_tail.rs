//! `processor::source_domain_tail_is_zero` lets five wrapper source-domain scans (trade
//! snapshots, lien freshness check, backing-fee loop) stop at an all-default tail. Those scans
//! only act on occupied slots, so this is exact as long as the helper says "zero" only when every
//! slot from `from` on equals `PortfolioSourceDomainV16Account::default()`.
use percolator::{
    PortfolioSourceDomainV16Account, V16PodU128, V16PodU32, V16PodU64, PORTFOLIO_SOURCE_DOMAIN_CAP,
};
use percolator_prog::processor::source_domain_tail_is_zero as tail_is_zero;

type Table = [PortfolioSourceDomainV16Account; PORTFOLIO_SOURCE_DOMAIN_CAP];

fn reference(t: &[PortfolioSourceDomainV16Account], from: usize) -> bool {
    t.iter()
        .skip(from)
        .all(|d| *d == PortfolioSourceDomainV16Account::default() && !d.is_occupied())
}

fn empty() -> Table {
    [PortfolioSourceDomainV16Account::default(); PORTFOLIO_SOURCE_DOMAIN_CAP]
}

#[test]
fn zero_tail_on_empty_and_past_end() {
    let t = empty();
    for from in 0..=PORTFOLIO_SOURCE_DOMAIN_CAP + 2 {
        assert!(tail_is_zero(&t, from), "from={from}");
    }
    assert!(tail_is_zero(&t[..0], 0));
}

#[test]
fn any_single_nonzero_byte_in_the_tail_is_seen() {
    let slot_len = core::mem::size_of::<PortfolioSourceDomainV16Account>();
    let total = slot_len * PORTFOLIO_SOURCE_DOMAIN_CAP;
    for from in [
        0usize,
        1,
        2,
        PORTFOLIO_SOURCE_DOMAIN_CAP / 2,
        PORTFOLIO_SOURCE_DOMAIN_CAP - 1,
    ] {
        for pos in 0..total {
            for value in [1u8, 0x80, 0xff] {
                let mut t = empty();
                bytemuck::cast_slice_mut::<_, u8>(&mut t)[pos] = value;
                let expect = reference(&t, from);
                assert_eq!(
                    expect,
                    pos < from * slot_len,
                    "reference sanity pos={pos} from={from}"
                );
                assert_eq!(
                    tail_is_zero(&t, from),
                    expect,
                    "pos={pos} from={from} value={value}"
                );
            }
        }
    }
}

#[test]
fn occupied_prefix_then_zero_tail() {
    for k in 0..=PORTFOLIO_SOURCE_DOMAIN_CAP {
        let mut t = empty();
        for (i, slot) in t.iter_mut().enumerate().take(k) {
            slot.domain = V16PodU32::new(i as u32);
            slot.source_claim_market_id = V16PodU64::new(1);
            slot.source_lien_effective_reserved = V16PodU128::new(5);
        }
        for from in 0..=PORTFOLIO_SOURCE_DOMAIN_CAP {
            assert_eq!(
                tail_is_zero(&t, from),
                reference(&t, from),
                "k={k} from={from}"
            );
            assert_eq!(tail_is_zero(&t, from), from >= k, "k={k} from={from}");
        }
    }
}

#[test]
fn hole_then_occupied_slot_is_not_a_zero_tail() {
    // An empty slot followed later by an occupied one: the scan must go on and see it.
    for gap in 1..PORTFOLIO_SOURCE_DOMAIN_CAP {
        let mut t = empty();
        t[gap].domain = V16PodU32::new(5);
        t[gap].source_lien_counterparty_backing_num = V16PodU128::new(1_000_000_000_000);
        assert!(t[gap].is_occupied());
        for from in 0..=gap {
            assert!(!tail_is_zero(&t, from), "gap={gap} from={from}");
        }
        assert!(tail_is_zero(&t, gap + 1));
    }
}
